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
const CACHE = 'partenaire-dozie-v32-20260621';
// BUMP (2026-06-21c): tube↔chambre cross-language search. ROOT CAUSE was NOT a
// missing synonym (the tube/chambre/"chambre a air"/inner-tube cluster was
// already present and the shared module already bridged both directions) — it
// was STALE CLIENT CACHE: installs predating the network-first-for-/data/ SW
// served an old cached dozie_synonyms.json with no "chambre", so the client-side
// expansion couldn't bridge. This bump evicts ALL old caches (activate()) and
// reloads the current dozie_search.js + dozie_synonyms.json so the bridge goes
// live on every installed/web client. Also strengthened the cluster: added
// plurals "tubes"/"chambres" + hyphen "inner-tube" (plural/hyphen queries
// previously missed the "Tube …" listings entirely).
// BUMP (2026-06-21b): buyer-search fixes — bilingual degraded-fallback (ILIKE
// name+name_en+name_fr+description) + "chambre" added to the tube synonym group
// so a single-word "chambre" finds inner-tube/"Tube …" listings. Forces phones
// onto the new buyer client + synonym map.
// BUMP (2026-06-21): Dozie bilingual Part 2 shipped — PARTENAIRE_Buyer.html now
// renders listing names in the chosen FR/EN language (dispName) + re-renders on
// the language toggle, and the client search-fallback + /dozie_search.js match
// across all four language fields (name_fr/name_en/description_fr/description_en).
// Bump forces installed phones onto the new buyer app + search module.
// BUMP (2026-06-13): FR↔EN buyer search still failed for real users ("chambre à
// air" → 0 results, "tube" → ok). Root cause: devices were stuck on the 12c
// cached buyer page, whose search calls the Dozie server endpoint /api/dozie/
// search-products; the free Render service sleeps, so it fell back to a raw
// ILIKE — EN "tube" substring-matches "Tube …" (looks fine) but FR "chambre à
// air" matches nothing. The 12d build runs the bilingual expansion CLIENT-SIDE
// (no server dependency) but those devices never received it. This bump forces
// the new SW (skipWaiting + claim + cache eviction); ADDITIONALLY the search
// engine + synonym data are now PRECACHED and served NETWORK-FIRST (below) so a
// stale /dozie_search.js or /data/dozie_synonyms.json can never silently
// disable bilingual search again.
// BUMP (2026-06-12d): bilingual search now runs CLIENT-SIDE on the buyer feed via
// the shared /dozie_search.js module (against the always-up Supabase catalogue),
// so FR<->EN translation no longer depends on the Render endpoint being awake.
// Bump evicts old cached buyer HTML + picks up the new shared module.
// BUMP (2026-06-12c): bilingual/synonym + accent-insensitive product search.
// Buyer search now calls the server endpoint /api/dozie/search-products (with a
// legacy ILIKE fallback), so "chambre à air" finds "Tube …" and "inner tube"/
// "pneu" bridge FR↔EN. Bump evicts old cached buyer HTML.
// BUMP (2026-06-12b): REAL fix for buyer create-account. The /login mode-chooser
// "Buy products" now hands a guest to /buyer?signup=1, and the buyer portal forces
// the create-account screen on ?signup=1. (Previously "Buy products" showed the
// chooser's own phone+PIN sign-in, which had no register option — the guest never
// reached the buyer portal.) Bump evicts old cached buyer HTML.
// BUMP (2026-06-12): create-account (screen-register) is now the DEFAULT guest
// landing with a prominent Sign in button; removed the restoreBuyerSession
// auto-redirect that flashed register then yanked the user to the app shell.
// Bump evicts old cached buyer HTML.
// BUMP (2026-06-11b): prominent "Créer un compte" button added to the buyer
// Sign in screen (screen-phone) so a new buyer can self-register without
// getting stuck at login. Bump evicts old cached buyer HTML.
// BUMP (2026-06-11): front-page CTA now shows BOTH "Créer un compte" and
// "Se connecter" buttons for guest buyers. Bump evicts old cached buyer HTML.
// BUMP (2026-06-10): buyer guest-entry fix — open to guest browse (no login
// wall) + stop the session auto-resume from hijacking the "Créer un compte"
// screen. Bumping evicts old precached buyer HTML on installed shells.
// BUMP (2026-06-09): the buyer self-registration + guest-browsing deploys
// changed PARTENAIRE_Buyer.html but didn't bump this version, so installed
// Capacitor wrappers running an older (cache-first) SW never swapped to this
// network-first SW and kept serving the stale buyer page. Bumping the version
// (byte change to sw.js + new cache name) forces every client to install this
// SW, evict all old caches in activate(), and skipWaiting/claim immediately —
// after which network-first navigations serve the current /buyer.

const STATIC = [
  '/',
  '/login',
  '/PARTENAIRE_Login.html',
  '/PARTENAIRE_Seller.html',
  '/PARTENAIRE_Buyer.html',
  '/dozie_search.js',
  '/data/dozie_synonyms.json',
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

  // Network-first for the bilingual-search engine + synonym data. These are
  // small and search-critical: a stale copy silently breaks FR↔EN search, so
  // always try fresh and only fall back to cache offline.
  if (req.url.includes('/dozie_search.js') || req.url.includes('/data/')) {
    e.respondWith(
      fetch(req).then(res => {
        const clone = res.clone();
        caches.open(CACHE).then(c => c.put(req, clone));
        return res;
      }).catch(() => caches.match(req))
    );
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
