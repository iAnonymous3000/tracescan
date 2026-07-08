/* Scan worker: runs the WASM pipeline off the main thread so a
   multi-hundred-megabyte sysdiagnose never freezes the page. Receives the
   file and indicator texts, streams chunks through the scanner, posts
   progress and the final report back. Nothing here touches the network. */

import init, { Scanner } from './pkg/trace_core.js';

const ready = init();

self.onmessage = async (e) => {
  const msg = e.data;
  if (msg.type !== 'scan') return;
  try {
    await ready;
    const scanner = new Scanner();
    for (const s of msg.sets) {
      scanner.load_stix(s.name, s.text);
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
        self.postMessage({ type: 'progress', processed });
      }
    }
    self.postMessage({ type: 'progress', processed });
    self.postMessage({ type: 'report', report: JSON.parse(scanner.finish()) });
  } catch (err) {
    self.postMessage({ type: 'error', message: err?.message || String(err) });
  }
};
