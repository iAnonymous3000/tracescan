/* Kill switch for the retired GitHub Pages deployment. The old service
   worker served the cached app shell cache-first, so returning visitors
   would never reach the redirect page on their own: this replacement
   (picked up by the browser's regular sw.js update check) clears every
   cache, unregisters itself, and reloads open tabs so their next
   navigation hits the network and lands on the redirect. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    for (const key of await caches.keys()) await caches.delete(key);
    await self.registration.unregister();
    for (const client of await self.clients.matchAll({ type: 'window' })) {
      try { client.navigate(client.url); } catch { /* tab will refresh on its own eventually */ }
    }
  })());
});
