/* Trace service worker: makes the whole app work offline so the privacy
   claim is verifiable - load once, go to Airplane Mode, scan. */

// The production build replaces this exact string with a per-commit name
// ('trace-<sha>') and then verifies the substitution took (see the deploy
// command in README.md). Renaming or reformatting this line breaks that
// verification on purpose: update both together.
const CACHE = 'trace-v1';
const SHELL = [
  './',
  './index.html',
  './style.css',
  './main.js',
  './worker.js',
  './report.schema.json',
  './pkg/trace_core.js',
  './pkg/trace_core_bg.wasm',
  './iocs/manifest.json',
  './iocs/pegasus.stix2',
  './iocs/predator.stix2',
  './iocs/kingspawn.stix2',
  './iocs/triangulation.stix2',
  './iocs/rcs.stix2',
  './iocs/wintego_helios.stix2',
  './iocs/coruna.stix2',
  './iocs/darksword.stix2',
  './fixtures/sysdiagnose_demo_clean.tar.gz',
  './fixtures/sysdiagnose_demo_infected.tar.gz',
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== self.location.origin) {
    return; // cross-origin (live indicator refresh) goes straight to network
  }
  e.respondWith(
    caches.match(e.request).then(
      (hit) =>
        hit ||
        fetch(e.request).then((resp) => {
          if (resp.ok) {
            const copy = resp.clone();
            caches.open(CACHE).then((c) => c.put(e.request, copy));
          }
          return resp;
        })
    )
  );
});
