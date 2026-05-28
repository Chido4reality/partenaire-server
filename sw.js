// WRAPPER-SW-CACHE-BUST (2026-05-17)
//
// Bug fixed: the old SW served HTML documents cache-first, so once a
// browser/desktop-wrapper cached PARTENAIRE_*.html it was stuck on that
// version forever (only "Clear site data" recovered it). New strategy:
//
//   • Versioned cache name. 'activate' deletes every cache != CACHE, so
//     each deploy that bumps the version evicts all stale HTML/assets.
//   • Network-first for navigations/documents (always try fresh HTML;
//     fall back to cache only when offline). The fresh copy is written
//     back so the offline fallback stays current.
//   • Static assets (JS/CSS/img/etc.) stay cache-first for speed.
//   • skipWaiting() + clients.claim() so a new SW takes over open
//     tabs/wrappers immediately, no full restart needed.
//
// Bump CACHE on every frontend deploy that must invalidate clients.
const CACHE = 'partenaire-dozie-v16-20260528e';

const STATIC = [
  '/',
  '/login',
  '/PARTENAIRE_Login.html',
  '/PARTENAIRE_Seller.html',
  '/PARTENAIRE_Buyer.html',
  '/icon.svg',
  '/manifest.json'
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(STATIC)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

function isNavigation(req) {
  return req.mode === 'navigate' || req.destination === 'document';
}

self.addEventListener('fetch', e => {
  const req = e.request;

  // Network-first for API calls (unchanged).
  if (req.url.includes('/api/') || req.url.includes('supabase.co')) {
    e.respondWith(fetch(req).catch(() => caches.match(req)));
    return;
  }

  // Network-first for HTML/navigation requests — THE FIX. Always try the
  // network so a new deploy is picked up; cache the fresh copy; only fall
  // back to cache when offline.
  if (isNavigation(req)) {
    e.respondWith(
      fetch(req).then(res => {
        const clone = res.clone();
        caches.open(CACHE).then(c => c.put(req, clone));
        return res;
      }).catch(() =>
        caches.match(req).then(cached =>
          cached || caches.match('/PARTENAIRE_Buyer.html') ||
          caches.match('/PARTENAIRE_Seller.html')
        )
      )
    );
    return;
  }

  // Cache-first for static assets (JS/CSS/images/etc.).
  e.respondWith(
    caches.match(req).then(cached => cached || fetch(req).then(res => {
      const clone = res.clone();
      caches.open(CACHE).then(c => c.put(req, clone));
      return res;
    }))
  );
});
