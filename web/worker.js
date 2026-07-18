/* Scan worker: runs the WASM pipeline off the main thread so a
   multi-hundred-megabyte sysdiagnose never freezes the page. Receives the
   file and indicator texts, streams chunks through the scanner, posts
   progress and the final report back. Nothing here touches the network. */

import init, { Scanner } from './pkg/trace_core.js';

const ready = init();
ready.then(
  () => self.postMessage({ type: 'ready' }),
  (err) => self.postMessage({ type: 'init-error', message: err?.message || String(err) })
);

function meetsReviewedFloor(set, stats) {
  return Number.isSafeInteger(set.min_indicators)
    && set.min_indicators >= 0
    && Number.isSafeInteger(set.min_applicable)
    && set.min_applicable >= 0
    && Number.isSafeInteger(stats?.extracted)
    && stats.extracted >= set.min_indicators
    && Number.isSafeInteger(stats?.applicable)
    && stats.applicable >= set.min_applicable;
}

self.onmessage = async (e) => {
  const msg = e.data;
  if (msg.type !== 'scan') return;
  // Every message carries the id of the scan it belongs to; the page drops
  // anything whose id doesn't match the scan it is waiting for, so results
  // can never attach to the wrong file.
  const { id } = msg;
  let scanner;
  try {
    await ready;
    scanner = new Scanner();
    for (const s of msg.sets) {
      const stats = JSON.parse(
        scanner.load_stix_with_meta(s.name, s.text, JSON.stringify(s.meta || {}))
      );
      // Re-check inside the scan worker. A long-lived page can outlive a
      // deployment and later create a worker/WASM pair from a newer cache;
      // neither side may silently scan below the reviewed snapshot floor.
      if (!meetsReviewedFloor(s, stats)) {
        throw new Error(
          `Bundled indicator set "${s.name}" is below its reviewed floor in the background scanner.`
        );
      }
    }
    const reader = msg.file.stream().getReader();
    let processed = 0;
    let lastPost = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      scanner.push(value);
      processed += value.byteLength;
      const now = Date.now();
      if (now - lastPost > 100) {
        lastPost = now;
        self.postMessage({ type: 'progress', id, processed });
      }
    }
    self.postMessage({ type: 'progress', id, processed });
    // The report envelope is assembled entirely in Rust; the producer only
    // supplies the file's declared identity. Timing comes from the engine
    // itself (its injected clock runs through parsing and assembly inside
    // finish, which a reading taken here would miss).
    scanner.set_scan_meta(JSON.stringify({
      source_name: msg.file.name,
      source_size: msg.file.size,
      scanned_via: 'worker',
    }));
    const report = JSON.parse(scanner.finish());
    scanner.free();
    scanner = null;
    self.postMessage({ type: 'report', id, report });
  } catch (err) {
    try { scanner?.free(); } catch { /* already released */ }
    self.postMessage({ type: 'error', id, message: err?.message || String(err) });
  }
};
