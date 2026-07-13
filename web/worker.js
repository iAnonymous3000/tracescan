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

self.onmessage = async (e) => {
  const msg = e.data;
  if (msg.type !== 'scan') return;
  // Every message carries the id of the scan it belongs to; the page drops
  // anything whose id doesn't match the scan it is waiting for, so results
  // can never attach to the wrong file.
  const { id } = msg;
  try {
    await ready;
    const scanner = new Scanner();
    for (const s of msg.sets) {
      scanner.load_stix_with_meta(s.name, s.text, JSON.stringify(s.meta || {}));
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
    self.postMessage({ type: 'report', id, report: JSON.parse(scanner.finish()) });
  } catch (err) {
    self.postMessage({ type: 'error', id, message: err?.message || String(err) });
  }
};
