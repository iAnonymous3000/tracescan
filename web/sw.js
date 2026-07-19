/* Trace service worker: makes the whole app work offline so the privacy
   claim is verifiable - load once, go to Airplane Mode, scan. */

// The production build replaces this exact string with a per-commit name
// ('trace-<sha>') and then verifies the substitution took (see the CI-gated
// production workflow). Renaming or reformatting this line breaks that
// verification on purpose: update both together.
const CACHE = 'trace-v1';
const TRACE_CACHE_PREFIX = 'trace-';
const TRACE_CACHE_KEY = '__trace_release';
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

// CacheStorage is shared by every service-worker generation on this origin.
// Store entries under a release-qualified request URL so an older worker that
// used origin-wide caches.match(request) cannot see assets installed by this
// waiting release. The active worker maps normal requests to its own qualified
// keys below; the query is never sent during ordinary page fetches.
function cacheKey(request) {
  const url = new URL(typeof request === 'string' ? request : request.url, self.location.href);
  if (typeof request !== 'string' && request.mode === 'navigate') {
    const scopePath = new URL(self.registration.scope).pathname;
    if (url.pathname === scopePath || url.pathname === `${scopePath}index.html`) {
      // Query parameters on an app-shell navigation must not create a cache
      // miss that lets a known-old worker fetch a newer index from the network.
      // Both root and /index.html navigations use the canonical root shell.
      url.pathname = scopePath;
      url.search = '';
    }
  }
  url.searchParams.set(TRACE_CACHE_KEY, CACHE);
  return url.href;
}

self.addEventListener('install', (e) => {
  // Do not call skipWaiting here. A new release must remain waiting while an
  // older worker still controls an open page; activating immediately could
  // replace that page's cached worker/WASM/indicator assets mid-session and
  // produce a report assembled from two different releases.
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(SHELL.map(cacheKey)))
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
    caches.open(CACHE).then((cache) =>
      cache.match(cacheKey(e.request)).then(
        (hit) =>
          hit ||
          fetch(e.request).then((resp) => {
            if (resp.ok) {
              const copy = resp.clone();
              e.waitUntil(cache.put(cacheKey(e.request), copy));
            }
            return resp;
          })
      )
    )
  );
});
