/* Trace service worker: makes the whole app work offline so the privacy
   claim is verifiable - load once, go to Airplane Mode, scan. */

// The production build replaces this exact string with a per-commit name
// ('trace-<sha>') and then verifies the substitution took (see the CI-gated
// production workflow). Renaming or reformatting this line breaks that
// verification on purpose: update both together.
const CACHE = 'trace-v1';
const TRACE_CACHE_PREFIX = 'trace-';
const SHELL = [
  './',
  './index.html',
  './style.css',
  './main.js',
  './readable-report.js',
  './report-validator.js',
  './indicator-floor.js',
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
  // Do not call skipWaiting here. A new release must remain waiting while an
  // older worker still controls an open page; activating immediately could
  // replace that page's cached worker/WASM/indicator assets mid-session and
  // produce a report assembled from two different releases.
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(SHELL))
  );
});

self.addEventListener('activate', (e) => {
  // Normal service-worker lifecycle reaches activation only after clients of
  // the previous release have gone away. Remove only Trace-owned generations:
  // caches are origin-wide, so deleting an unrelated app's cache would break a
  // shared-origin/subpath deployment. Do not claim already-open clients; the
  // new release takes control on a subsequent navigation instead.
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys
          .filter((k) => k.startsWith(TRACE_CACHE_PREFIX) && k !== CACHE)
          .map((k) => caches.delete(k))
      ))
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
