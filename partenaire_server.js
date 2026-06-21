require('dotenv').config();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

// ── M-1 SECURITY: PIN hashing + Dozie JWT sessions ──────────────────
// DOZIE_JWT_SECRET is a SEPARATE secret from the MP backend's
// ADMIN_JWT_SECRET / ADMIN_IMPERSONATE_SECRET (different audience,
// independent revocation). Set it in Render env. See .env.example.
const DOZIE_JWT_SECRET = process.env.DOZIE_JWT_SECRET || '';
const DOZIE_JWT_TTL_HOURS = parseInt(process.env.DOZIE_JWT_TTL_HOURS || '24', 10);

async function hashPin(pin) { return bcrypt.hash(String(pin), 10); }
async function verifyPin(pin, hash) {
  if (!hash) return false;
  try { return await bcrypt.compare(String(pin), hash); } catch { return false; }
}

function issueDozieJwt(uid, role) {
  return jwt.sign({ uid, role }, DOZIE_JWT_SECRET,
    { expiresIn: DOZIE_JWT_TTL_HOURS * 3600 });
}
// Returns { uid, role } from a valid Bearer token, else null.
function readDozieJwt(req) {
  const h = req.headers['authorization'] || '';
  if (!h.startsWith('Bearer ') || !DOZIE_JWT_SECRET) return null;
  try {
    const p = jwt.verify(h.slice(7), DOZIE_JWT_SECRET);
    if (!p || !p.uid) return null;
    return { uid: p.uid, role: p.role };
  } catch { return null; }
}
// M-1.5.3: JWT-only. The M-1 dual-auth grace period (legacy
// x-dozie-{seller,buyer}-id header fallback) is removed — those
// headers are now ignored and grant no authentication.
function resolveDozieIdentity(req, role) {
  const j = readDozieJwt(req);
  if (!j) return { error: 'auth_required' };
  if (role && j.role !== role) return { error: 'role' };
  return { uid: j.uid, role: j.role, via: 'jwt' };
}

// ── M-2.1-A: admin JWT (separate claim role='admin' + admin_role) ───
// ptn_admin_roles is now sealed; admin auth goes admin_pin_login RPC →
// backend signs this token. admin_role carries the DB role
// (master|finance|…) used for the RPC permission checks.
function issueAdminJwt(uid, adminRole) {
  return jwt.sign({ uid, role: 'admin', admin_role: adminRole },
    DOZIE_JWT_SECRET, { expiresIn: DOZIE_JWT_TTL_HOURS * 3600 });
}
function readAdminJwt(req) {
  const h = req.headers['authorization'] || '';
  if (!h.startsWith('Bearer ') || !DOZIE_JWT_SECRET) return null;
  try {
    const p = jwt.verify(h.slice(7), DOZIE_JWT_SECRET);
    if (!p || !p.uid || p.role !== 'admin') return null;
    return { uid: p.uid, admin_role: p.admin_role || null };
  } catch { return null; }
}

// M-1.5: naive in-memory PIN-login rate limit — max 5 failed
// attempts per phone per 15 min, then 429. Sufficient at current
// scale; swap for a shared store if the server is ever multi-instance.
const PIN_FAILS = new Map(); // phone -> [tsMs, ...]
const PIN_MAX_FAILS = 5;
const PIN_WINDOW_MS = 15 * 60 * 1000;
function pinRateBlocked(phone) {
  const arr = (PIN_FAILS.get(phone) || []).filter(t => Date.now() - t < PIN_WINDOW_MS);
  PIN_FAILS.set(phone, arr);
  return arr.length >= PIN_MAX_FAILS;
}
function pinNoteFail(phone) {
  const arr = (PIN_FAILS.get(phone) || []).filter(t => Date.now() - t < PIN_WINDOW_MS);
  arr.push(Date.now());
  PIN_FAILS.set(phone, arr);
}
function pinClear(phone) { PIN_FAILS.delete(phone); }

// â”€â”€â”€ CAMPAY CONFIGURATION â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const CAMPAY_BASE_URL = process.env.CAMPAY_ENV === 'production'
  ? 'https://campay.net/api'
  : 'https://demo.campay.net/api';

// LAUNCH-PAYMENT-SECURITY — webhook shared secret (set on Render AND in
// the Campay dashboard). See the /campay/webhook handler.
const CAMPAY_WEBHOOK_SECRET = process.env.CAMPAY_WEBHOOK_SECRET || '';

// ── LAUNCH v1: IN-APP PAYMENT MASTER SWITCH ──────────────────────────
// v1 ships with NO in-app payment and NO escrow — buyers pay at the shop
// (offline). Every money-movement path (Campay collect/payout, escrow,
// /campay/* endpoints, create-and-pay's charge step) is gated behind this
// flag and is unreachable while it is false. The Campay code below is kept
// intact so a future version can revive it by setting PAYMENTS_ENABLED=true
// (env) and providing real Campay credentials.
const PAYMENTS_ENABLED = process.env.PAYMENTS_ENABLED === 'true';

// FLW-COLLECT (Slice 0/1): Flutterwave is the in-app collect provider. TEST vs
// LIVE is the key prefix (FLWSECK_TEST- vs FLWSECK-); identical code either way.
const FLW_IS_TEST = String(process.env.FLW_SECRET_KEY || '').startsWith('FLWSECK_TEST-');
// The Flutterwave collect routes (/flw/initiate, /flw/verify-return) are gated
// STRICTLY on PAYMENTS_ENABLED — so prod (flag OFF) is fully dormant and no real
// order can be touched via FLW until the deliberate flip, regardless of key
// type. Test-mode validation is done by running LOCALLY with PAYMENTS_ENABLED=
// true + TEST keys against a throwaway order. (/flw/webhook stays reachable for
// Flutterwave to call but is self-protecting: verif-hash + it only settles an
// order that has a matching DZORD transaction row, which only /flw/initiate
// creates — so with the flag off there is nothing for it to settle.)
const FLW_ROUTES_ACTIVE = PAYMENTS_ENABLED;

// Fail loud, not silent-sandbox: in production with payments ENABLED, refuse to
// boot unless the Flutterwave collect env is present. (The Campay helpers below
// stay for the legacy XAF payout path but are NO LONGER a boot requirement —
// Dozie seller payout is MANUAL this slice.)
if (PAYMENTS_ENABLED && process.env.NODE_ENV === 'production') {
  const _fail = (m) => { console.error('CRITICAL: ' + m); process.exit(1); };
  if (!process.env.FLW_SECRET_KEY)
    _fail('FLW_SECRET_KEY missing (Flutterwave secret key) — payments enabled but no collect provider');
  if (!process.env.FLW_SECRET_HASH)
    _fail('FLW_SECRET_HASH missing (Flutterwave webhook verif-hash)');
  console.log('[payments] Flutterwave collect ENABLED — mode: ' + (FLW_IS_TEST ? 'TEST' : 'LIVE'));
}

let campayToken = null;
let campayTokenExpiry = null;

async function getCampayToken() {
  // Use permanent access token if provided (preferred over username/password flow)
  if (process.env.CAMPAY_TOKEN) return process.env.CAMPAY_TOKEN;
  if (campayToken && campayTokenExpiry && Date.now() < campayTokenExpiry) return campayToken;
  const res = await fetch(`${CAMPAY_BASE_URL}/token/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: process.env.CAMPAY_USERNAME, password: process.env.CAMPAY_PASSWORD })
  });
  const data = await res.json();
  if (!data.token) throw new Error('Campay token failed: ' + JSON.stringify(data));
  campayToken = data.token;
  campayTokenExpiry = Date.now() + (55 * 60 * 1000);
  return campayToken;
}

async function campayCollect({ amount, phone, description, reference }) {
  const token = await getCampayToken();
  const cleanPhone = String(phone).replace(/\s/g,'').replace(/^\+/,'');
  const res = await fetch(`${CAMPAY_BASE_URL}/collect/`, {
    method: 'POST',
    headers: { 'Authorization': `Token ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount: String(amount), currency: 'XAF', from: cleanPhone, description, external_reference: reference })
  });
  return await res.json();
}

async function campayCheckStatus(reference) {
  const token = await getCampayToken();
  const res = await fetch(`${CAMPAY_BASE_URL}/transaction/${reference}/`, {
    headers: { 'Authorization': `Token ${token}` }
  });
  return await res.json();
}

async function campayPayout({ amount, phone, description, reference }) {
  const token = await getCampayToken();
  const cleanPhone = String(phone).replace(/\s/g,'').replace(/^\+/,'');
  const res = await fetch(`${CAMPAY_BASE_URL}/transfer/`, {
    method: 'POST',
    headers: { 'Authorization': `Token ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount: String(amount), currency: 'XAF', to: cleanPhone, description, external_reference: reference })
  });
  return await res.json();
}
const http  = require('http');
const fs    = require('fs');
const path  = require('path');
const https = require('https');
// B.4.1: OTP login retired — AfricasTalking/SMS client removed (it was
// used solely by the deleted sendOTP path; no notification path used it).

const SUPA = process.env.SUPABASE_HOST || 'ftxttdagpioieyzaijdc.supabase.co';
const KEY  = process.env.SUPABASE_KEY;
// M-2.1 Phase B.4.1: service_role key for server-context privileged reads
// that must bypass RLS (post-B.5 anon lockdown). NEVER expose its results
// to unauthenticated callers. Missing key = warn + the privileged sites
// degrade to a clean error, app keeps running.
const DOZIE_SERVICE_KEY = process.env.DOZIE_SERVICE_KEY || '';
if (!DOZIE_SERVICE_KEY) {
  console.warn('[startup] DOZIE_SERVICE_KEY not set — privileged server reads ' +
    '(order handoff, Campay payout seller lookup) will return a clean error ' +
    'until it is configured in the Render environment.');
}
const PORT = 8080;
const DIR=__dirname;

// LAUNCH-PAYMENT-SECURITY: Monetbil fully removed — Campay is the only
// payment processor. Its config, initiator, webhook handler and the
// client-controlled sandbox-bypass route were deleted.

const MIME = { '.html':'text/html', '.js':'text/javascript', '.css':'text/css', '.png':'image/png', '.jpg':'image/jpeg', '.json':'application/json', '.svg':'image/svg+xml' };

// DOZIE-UNIFIED-ENTRY: `/` no longer aliases the admin portal — it's
// served by a dynamic auto-router (see the inline /-handler below the
// API routes) that reads localStorage.dozie_jwt in the browser and
// redirects to /seller, /buyer, or /login. Admin staff continue to
// use /admin explicitly. /login is a new unified phone+PIN page with
// a buyer/seller mode chooser.
const ROUTES = {
  '/admin':  'PARTENAIRE_Admin.html',
  '/seller': 'PARTENAIRE_Seller.html',
  '/buyer':  'PARTENAIRE_Buyer.html',
  '/login':  'PARTENAIRE_Login.html',
  // Public Play-Store compliance pages — no login required (served by the
  // static handler below, same as the app shells).
  '/privacy-fr':         'privacy-fr.html',
  '/suppression-compte': 'suppression-compte.html',
};

// B.4.1: OTP login fully retired. otpStore / generateOTP / sendOTP /
// verifyOTP / DEV_OTP_BYPASS and the /otp/* routes were removed. Auth is
// PIN-only via /auth/pin-login → auth_pin_login RPC. ptn_otp_sessions
// table is left in the DB (separate future cleanup).

// â”€â”€ SUPABASE HELPER â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function supaRequest(method, table, params, body) {
  return new Promise((resolve, reject) => {
    const supaPath = '/rest/v1/' + table + (params ? '?' + params : '');
    const postBody = body ? JSON.stringify(body) : null;
    const options = {
      hostname: SUPA,
      path: supaPath, method,
      headers: {
        'apikey': KEY,
        'Authorization': 'Bearer ' + KEY,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation',
        ...(postBody ? { 'Content-Length': Buffer.byteLength(postBody) } : {})
      }
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch(e) { resolve(data); }
      });
    });
    req.on('error', reject);
    if (postBody) req.write(postBody);
    req.end();
  });
}

// M-2.1 Phase B.4.1: same as supaRequest but with the service_role key, so
// it bypasses RLS. Use ONLY for server-context reads (order handoff, payout
// seller phone) — NEVER return its results to unauthenticated callers. If
// DOZIE_SERVICE_KEY is unset it resolves to [] (no throw): callers already
// guard on an empty/missing row and emit a clean error, so the app keeps
// running rather than crashing the request.
function supaRequestPrivileged(method, table, params, body) {
  if (!DOZIE_SERVICE_KEY) {
    console.warn('[supaRequestPrivileged] DOZIE_SERVICE_KEY missing — skipping ' +
      method + ' ' + table + ' (returning [])');
    return Promise.resolve([]);
  }
  return new Promise((resolve, reject) => {
    const supaPath = '/rest/v1/' + table + (params ? '?' + params : '');
    const postBody = body ? JSON.stringify(body) : null;
    const options = {
      hostname: SUPA,
      path: supaPath, method,
      headers: {
        'apikey': DOZIE_SERVICE_KEY,
        'Authorization': 'Bearer ' + DOZIE_SERVICE_KEY,
        'Content-Type': 'application/json',
        'Prefer': 'return=representation',
        ...(postBody ? { 'Content-Length': Buffer.byteLength(postBody) } : {})
      }
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch (e) { resolve(data); }
      });
    });
    req.on('error', reject);
    if (postBody) req.write(postBody);
    req.end();
  });
}

// Call a Postgres function via PostgREST (/rest/v1/rpc/<fn>). Returns
// the parsed jsonb the SECURITY DEFINER admin_* functions produce.
function supaRpc(fn, args) {
  return supaRequest('POST', 'rpc/' + fn, '', args || {});
}

// LAUNCH-PAYMENT-SECURITY: initiateMonetbilPayment / handleMonetbilNotify
// / simulatePaymentSuccess removed. Payments go through Campay only
// (campayCollect / campayCheckStatus / campayPayout above), and payment
// state is only ever set after an authenticated, re-queried Campay
// confirmation — never a client- or webhook-asserted "SUCCESS".

// ── DOZIE-BILINGUAL-SEARCH ───────────────────────────────────────────
// Accent/case-insensitive + synonym/translation-bridged product search.
// 100% server-side, ADDITIVE: it only broadens results (raw matches are
// always preserved) and never narrows the existing search. No LLM/API calls.
//
// normalize(): lowercase, strip accents/diacritics (NFD → drop combining
// marks), collapse whitespace. Applied to BOTH the query and the product
// searchable text so "Chambre à air" and "chambre a air" compare equal.
// The normalize() + synonym-expansion LOGIC lives in ONE shared module,
// ./dozie_search.js, which the BUYER FEED also loads (PARTENAIRE_Buyer.html ->
// <script src="/dozie_search.js">). Both paths therefore run identical search
// behaviour and can't drift. The synonym groups are the single source
// data/dozie_synonyms.json (served to the client at /data/dozie_synonyms.json).
const DS = require('./dozie_search.js');
// DOZIE-BILINGUAL: Azure FR<->EN translate helper (fail-open). Lockstep with the
// MP backend's backend/src/lib/azureTranslate.js.
const DT = require('./dozie_translate.js');

// ── FLW-COLLECT (Dozie Slice 0/1) — Flutterwave hosted-checkout helpers ──────
const FLW = require('./flutterwave.js');

// Resolve an order's settlement currency from the SELLER's linked MP org
// (ptn_users.linked_mp_org_id → pa_organisations.country). CM→XAF, NG→NGN.
// FAIL CLOSED: returns { currency:null, reason } when unresolvable (e.g. a
// standalone seller with no linked MP org); callers MUST refuse to start a pay.
function _currencyForCountry(country) {
  const c = String(country || '').trim().toUpperCase();
  if (['CM', 'CMR', 'CAMEROON', 'CAMEROUN'].includes(c)) return 'XAF';
  if (['NG', 'NGA', 'NIGERIA'].includes(c)) return 'NGN';
  return null;
}
async function resolveOrderCurrency(order) {
  try {
    if (!order || !order.seller_id) return { currency: null, reason: 'no_seller' };
    const sellers = await supaRequestPrivileged('GET', 'ptn_users',
      'id=eq.' + order.seller_id + '&select=id,linked_mp_org_id');
    const seller = Array.isArray(sellers) && sellers[0];
    if (!seller || !seller.linked_mp_org_id) return { currency: null, reason: 'no_linked_org' };
    const orgs = await supaRequestPrivileged('GET', 'pa_organisations',
      'id=eq.' + seller.linked_mp_org_id + '&select=id,country');
    const org = Array.isArray(orgs) && orgs[0];
    const currency = _currencyForCountry(org && org.country);
    if (!currency) return { currency: null, reason: 'unknown_country', country: org && org.country };
    return { currency, country: org.country, source: 'mp_org' };
  } catch (e) {
    return { currency: null, reason: 'error', message: e.message };
  }
}

// XAF → mobile-money set (mirrors MP). NGN → omit so the hosted page shows all
// dashboard-enabled methods (card, bank transfer, USSD, OPay if enabled).
function flwPaymentOptions(currency) {
  return currency === 'XAF' ? 'card,mobilemoney,mobilemoneyfranco' : undefined;
}

function dozieBaseUrl(req) {
  if (process.env.DOZIE_PUBLIC_URL) return process.env.DOZIE_PUBLIC_URL.replace(/\/+$/, '');
  const proto = (req && String(req.headers['x-forwarded-proto'] || '').split(',')[0]) || 'https';
  const host = (req && req.headers['host']) || 'partenaire-server.onrender.com';
  return proto + '://' + host;
}

// The order amount to collect/hold (an accepted counter-offer overrides total).
function orderEscrowAmount(order) {
  return order && order.counter_status === 'accepted' ? order.counter_total : order && order.total;
}

// Settle a Flutterwave-collected order from a SERVER-SIDE VERIFIED transaction.
// Shared by /flw/webhook (primary) and /flw/verify-return (fallback). NEVER
// trusts a client/redirect assertion: the caller must pass the object returned
// by FLW.verifyTransaction(). Idempotent on the order + transaction row.
async function flwSettle({ verified, txRef, source }) {
  if (!verified || !txRef) return { ok: false, reason: 'missing_input' };
  // Find the transaction row written at /flw/initiate → order_id + expected currency.
  const txns = await supaRequest('GET', 'ptn_campay_transactions',
    'reference=eq.' + encodeURIComponent(txRef) + '&select=id,order_id,currency,status&limit=1');
  const txn = Array.isArray(txns) && txns[0];
  if (!txn || !txn.order_id) return { ok: false, reason: 'unknown_tx_ref' };
  if (txn.status === 'successful') return { ok: true, idempotent: true, order_id: txn.order_id };

  const orders = await supaRequest('GET', 'ptn_orders', 'id=eq.' + txn.order_id + '&select=*');
  const order = Array.isArray(orders) && orders[0];
  if (!order) return { ok: false, reason: 'order_not_found' };
  if (order.payment_status === 'paid') return { ok: true, idempotent: true, order_id: order.id };

  const amt = Number(orderEscrowAmount(order));
  const okStatus = String(verified.status || '').toLowerCase() === 'successful';
  const okAmount = Number(verified.amount) >= amt;                 // >= tolerates over-pay/rounding
  const okCurrency = String(verified.currency || '').toUpperCase() === String(txn.currency || '').toUpperCase();
  const okRef = verified.tx_ref === txRef;
  if (!(okStatus && okAmount && okCurrency && okRef)) {
    await supaRequest('POST', 'ptn_audit_log', null, {
      action: 'flw_settle_mismatch', target_type: 'ptn_orders', target_id: order.id,
      details: { source, tx_ref: txRef, okStatus, okAmount, okCurrency, okRef,
        expected_amount: amt, expected_currency: txn.currency,
        got: { amount: verified.amount, currency: verified.currency, status: verified.status, tx_ref: verified.tx_ref } }
    }).catch(() => {});
    return { ok: false, reason: 'verify_mismatch' };
  }

  await supaRequest('PATCH', 'ptn_orders', 'id=eq.' + order.id, {
    payment_status: 'paid', escrow_held: amt, status: 'confirmed',
    payment_method: 'flutterwave', campay_status: 'successful',
    campay_paid_at: new Date().toISOString(), updated_at: new Date().toISOString()
  });
  await supaRequest('PATCH', 'ptn_campay_transactions', 'id=eq.' + txn.id, {
    status: 'successful', campay_response: verified, updated_at: new Date().toISOString()
  });
  await supaRequest('POST', 'ptn_notifications', null, {
    user_id: order.seller_id, type: 'payment', order_id: order.id,
    title_en: 'Payment Received', title_fr: 'Paiement reçu',
    body_en: 'Order ' + order.order_ref + ' paid online. Funds held in escrow.',
    body_fr: 'Commande ' + order.order_ref + ' payée en ligne. Fonds en séquestre.', read: false
  }).catch(() => {});
  await supaRequest('POST', 'ptn_audit_log', null, {
    action: 'flw_settle_success', target_type: 'ptn_orders', target_id: order.id,
    details: { source, tx_ref: txRef, amount: amt, currency: txn.currency, flw_id: verified.id }
  }).catch(() => {});
  return { ok: true, order_id: order.id, amount: amt };
}

// Translate one ptn_products row's name + description to FR + EN and store both.
// Loads the row fresh by id (current DB state). FAIL-OPEN: never throws.
async function dozieTranslateProductById(id) {
  try {
    if (!id) return;
    const rows = await supaRequestPrivileged('GET', 'ptn_products',
      'id=eq.' + encodeURIComponent(id) + '&select=name,description');
    const row = Array.isArray(rows) && rows[0];
    if (!row) return;
    const tr = await DT.translateToFrEn([row.name || '', row.description || '']);
    const nm = tr[0], ds = tr[1];
    await supaRequestPrivileged('PATCH', 'ptn_products', 'id=eq.' + encodeURIComponent(id), {
      name_fr: nm.fr, name_en: nm.en, description_fr: ds.fr, description_en: ds.en,
    });
  } catch (e) {
    console.warn('[dozie-translate] product ' + id + ' refresh failed: ' + (e && e.message));
  }
}

// From a Supabase REST representation body (array of affected rows) — used by the
// proxy path when a ptn_products write DOES route through this server (dev /
// localhost). In production the Dozie apps write straight to Supabase, so the
// dedicated POST /api/dozie/translate-product endpoint (called by the seller form
// after a save) is the path that actually fires. Both are fail-open + idempotent.
async function dozieRefreshProductTranslations(responseBody) {
  try {
    let rows;
    try { rows = JSON.parse(responseBody); } catch (_) { return; }
    if (!Array.isArray(rows)) rows = (rows && rows.id) ? [rows] : [];
    for (const row of rows) { if (row && row.id) await dozieTranslateProductById(row.id); }
  } catch (e) {
    console.warn('[dozie-translate] product refresh failed: ' + (e && e.message));
  }
}

let DOZIE_SYN_INDEX = DS.buildIndex([]);
try {
  const raw = require('./data/dozie_synonyms.json');
  DOZIE_SYN_INDEX = DS.buildIndex(raw.groups || []);
  console.log('[dozie-search] synonym map loaded: ' + DOZIE_SYN_INDEX.groups.length + ' groups');
} catch (e) {
  console.warn('[dozie-search] synonym map NOT loaded (' + (e && e.message) + ') - search still works on the raw query');
}
function dozieExpandQuery(rawQ) { return DS.expand(rawQ, DOZIE_SYN_INDEX); }

// In-process cache of the published marketplace catalogue (small at this
// scale). Refreshed on a short TTL so a burst of debounced keystroke searches
// hits Supabase at most once per window.
let _dozieCatalogue = { rows: null, ts: 0 };
const DOZIE_CATALOGUE_TTL_MS = 60 * 1000;
async function dozieGetCatalogue() {
  const now = Date.now();
  if (_dozieCatalogue.rows && (now - _dozieCatalogue.ts) < DOZIE_CATALOGUE_TTL_MS) {
    return _dozieCatalogue.rows;
  }
  // MP-NO-SILENT-TRUNCATION (Part A, Dozie server): a single REST select is
  // capped at PostgREST's ~1000-row limit, so a marketplace with >1000 published
  // listings would lose the tail from search. Page through ALL rows in stable
  // listing_id order. (PostgREST .offset via limit/offset query params.)
  const PAGE = 1000;
  let list = [];
  for (let off = 0; ; off += PAGE) {
    const batch = await supaRequest('GET', 'dozie_marketplace_products',
      'published=eq.true&select=listing_id,seller_id,name,price,photo_url,stock_state,category,city,description,name_fr,name_en,description_fr,description_en'
      + '&order=listing_id.asc,seller_id.asc&limit=' + PAGE + '&offset=' + off);
    const arr = Array.isArray(batch) ? batch : [];
    list = list.concat(arr);
    if (arr.length < PAGE) break;
    if (list.length >= 50000) break; // safety
  }
  // DOZIE-BILINGUAL: pre-normalize ALL FOUR language fields once per refresh so a
  // query in either language matches. Field list lives in DS.searchableText so
  // the server (_norm) and client (_n) can't drift.
  for (const p of list) p._norm = DS.normalize(DS.searchableText(p));
  _dozieCatalogue = { rows: list, ts: now };
  return list;
}

// â”€â”€ HTTP SERVER â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,apikey,Prefer,Accept');
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  // ── MP-CAMPAY-ENV-INDICATOR-FIX: runtime config ────────────────────
  // Single source of truth for the "🧪 SANDBOX" banner. Derived from the
  // ACTUAL Campay base URL the backend uses (demo.campay.net ⇒ sandbox),
  // so the badge can never be stale vs the deployed env. No secrets.
  if (req.url.split('?')[0] === '/api/config' && req.method === 'GET') {
    const isDemo = String(CAMPAY_BASE_URL).includes('demo');
    res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify({
      campay_env: process.env.CAMPAY_ENV || 'unknown',
      campay_base_url: CAMPAY_BASE_URL,
      campay_is_demo: isDemo,
      is_sandbox: isDemo,
      // v1: clients use this to hide all in-app payment UI and show the
      // "pay at shop" notice instead.
      payments_enabled: PAYMENTS_ENABLED
    }));
    return;
  }

  // ── LAUNCH v1: BLOCK ALL MONEY-MOVEMENT ENDPOINTS ──────────────────
  // While PAYMENTS_ENABLED is false, no request may collect, hold, or
  // transfer funds. Every Campay/escrow/payout endpoint and the order
  // "retry-payment" charge path returns 410 here, before reaching the
  // (intact, revivable) handlers below. create-and-pay is handled
  // separately so an order can still be PLACED (pay at shop) without a
  // charge.
  if (!PAYMENTS_ENABLED) {
    const _pp = req.url.split('?')[0];
    const _isPay =
      _pp.startsWith('/campay/') ||
      _pp.startsWith('/monetbil/') ||
      /^\/api\/orders\/[0-9a-fA-F-]{36}\/retry-payment$/.test(_pp);
    if (_isPay) {
      res.writeHead(410, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({
        success: false, disabled: true, error_code: 'payments_disabled',
        message: 'Paiement à effectuer en boutique — le paiement en ligne est désactivé.'
      }));
      return;
    }
  }

  // ── M-2.1-A — HARDENED ADMIN API ───────────────────────────────────
  // ptn_admin_roles is sealed (no anon table access). The admin portal
  // talks to these endpoints; data flows only through the SECURITY
  // DEFINER admin_* RPCs. JWT is signed here (DOZIE_JWT_SECRET lives in
  // Node). Declared BEFORE the Phase E legacy block so the new
  // /admin/* surface isn't swallowed by its 410.
  {
    const sendJ = (code, obj) => {
      res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify(obj));
    };
    const rawPath = req.url.split('?')[0].replace(/\/+$/, '') || '/';
    const readBody = () => new Promise(r => { let b=''; req.on('data',c=>b+=c); req.on('end',()=>{ try{r(JSON.parse(b||'{}'));}catch{r({});} }); });
    const requireAdmin = () => readAdminJwt(req);

    // POST /admin/pin-login — RETIRED (Phase E). Replaced by the unified
    // admin at https://mon-partenaire-app.vercel.app/admin.html (MP frontend
    // → MP backend /api/admin/*). ptn_admin_roles is also deactivated at the
    // DB layer (active=false), so admin_pin_login would fail anyway; this 410
    // is the explicit contract signal for any old client still POSTing here.
    // Route registration kept intentionally (method/path) — only the body
    // changed — for a clean, discoverable retirement. ptn_admin_roles /
    // ptn_audit_log / Phase A RPCs are NOT dropped (sealed for audit history).
    if (rawPath === '/admin/pin-login' && req.method === 'POST') {
      return sendJ(410, {
        success: false,
        code: 'LEGACY_ADMIN_RETIRED',
        message: 'The legacy Dozie admin has been retired. Use the unified admin at https://mon-partenaire-app.vercel.app/admin.html',
        retired_at: '2026-05-17'
      });
    }

    // Everything below requires a valid admin JWT.
    if (rawPath === '/admin/users' && req.method === 'GET') {
      const j = requireAdmin();
      if (!j) return sendJ(401, { ok:false, error:'auth_required' });
      (async () => {
        try {
          const r = await supaRpc('admin_list', { p_caller: j.uid });
          if (!r || r.ok !== true) return sendJ(403, { ok:false, error:(r&&r.error)||'forbidden' });
          sendJ(200, r);
        } catch (e) { sendJ(500, { ok:false, error:'server_error', message:e.message }); }
      })();
      return;
    }
    if (rawPath === '/admin/users' && req.method === 'POST') {
      const j = requireAdmin();
      if (!j) return sendJ(401, { ok:false, error:'auth_required' });
      (async () => {
        try {
          const { email, name, role, pin } = await readBody();
          const r = await supaRpc('admin_create',
            { p_caller: j.uid, p_email: email, p_name: name, p_role: role, p_pin: pin });
          if (!r || r.ok !== true) {
            const e = (r&&r.error)||'forbidden';
            return sendJ(e==='forbidden'?403:400, { ok:false, error:e });
          }
          sendJ(200, r);
        } catch (e) { sendJ(500, { ok:false, error:'server_error', message:e.message }); }
      })();
      return;
    }
    const mToggle = rawPath.match(/^\/admin\/users\/([^/]+)\/toggle$/);
    if (mToggle && req.method === 'PATCH') {
      const j = requireAdmin();
      if (!j) return sendJ(401, { ok:false, error:'auth_required' });
      (async () => {
        try {
          const { active } = await readBody();
          const r = await supaRpc('admin_toggle',
            { p_caller: j.uid, p_target: mToggle[1], p_active: !!active });
          if (!r || r.ok !== true) {
            const e=(r&&r.error)||'forbidden';
            return sendJ(e==='forbidden'?403:400, { ok:false, error:e });
          }
          sendJ(200, r);
        } catch (e) { sendJ(500, { ok:false, error:'server_error', message:e.message }); }
      })();
      return;
    }
    const mPin = rawPath.match(/^\/admin\/users\/([^/]+)\/pin$/);
    if (mPin && req.method === 'PATCH') {
      const j = requireAdmin();
      if (!j) return sendJ(401, { ok:false, error:'auth_required' });
      (async () => {
        try {
          const { new_pin } = await readBody();
          const r = await supaRpc('admin_change_pin',
            { p_caller: j.uid, p_target: mPin[1], p_new_pin: new_pin });
          if (!r || r.ok !== true) {
            const e=(r&&r.error)||'forbidden';
            return sendJ(e==='forbidden'?403:400, { ok:false, error:e });
          }
          sendJ(200, r);
        } catch (e) { sendJ(500, { ok:false, error:'server_error', message:e.message }); }
      })();
      return;
    }
    const mDel = rawPath.match(/^\/admin\/users\/([^/]+)$/);
    if (mDel && req.method === 'DELETE') {
      const j = requireAdmin();
      if (!j) return sendJ(401, { ok:false, error:'auth_required' });
      (async () => {
        try {
          const r = await supaRpc('admin_delete', { p_caller: j.uid, p_target: mDel[1] });
          if (!r || r.ok !== true) {
            const e=(r&&r.error)||'forbidden';
            return sendJ(e==='forbidden'?403:400, { ok:false, error:e });
          }
          sendJ(200, r);
        } catch (e) { sendJ(500, { ok:false, error:'server_error', message:e.message }); }
      })();
      return;
    }
  }

  // ── PHASE E — LEGACY ADMIN RETIRED ──────────────────────────────────
  // The real admin is mon-partenaire-app.vercel.app/admin.html (served
  // by the MP frontend, talking to the MP backend /api/admin/*). This
  // Dozie server's old PIN page (PARTENAIRE_Admin.html, still in git
  // history, just no longer served) and any /admin/* | /api/admin/*
  // API surface here are gone.
  //   • GET /admin → 302 to the new MP-hosted portal. Admin staff
  //     reach this URL deliberately; the redirect keeps the legacy
  //     bookmark working.
  //   • / used to be aliased to PARTENAIRE_Admin.html via ROUTES and
  //     was caught here too. d55adaa retired that alias and added a
  //     unified-entry auto-router at the bottom of this handler; the
  //     `/` clause was removed from this redirect so the auto-router
  //     can actually fire.
  //   • /admin/* | /api/admin* → 410 Gone (discoverable for API callers)
  // NOT touched: /mp-admin/* (MP svc proxy), /api/auth/impersonate-*
  // (used by the real admin), /campay/* (financial, separate concern).
  {
    const NEW_ADMIN = 'https://mon-partenaire-app.vercel.app/admin.html';
    const p = req.url.split('?')[0].replace(/\/+$/, '') || '/';
    if (p === '/admin') {
      res.writeHead(302, { Location: NEW_ADMIN });
      res.end();
      return;
    }
    if (p.startsWith('/admin/') || p.startsWith('/api/admin')) {
      const ip = (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim()
                 || (req.socket && req.socket.remoteAddress) || 'unknown';
      console.warn('Legacy admin route hit:', req.url, 'from', ip);
      res.writeHead(410, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({
        error: 'gone',
        message: 'Legacy admin API retired. Use https://partenaire-account-api.onrender.com/api/admin/* instead.'
      }));
      return;
    }
  }

  // B.4.1: /otp/send and /otp/verify routes removed — OTP login retired.
  // Authentication is PIN-only via the /auth/pin-login route below.

  // ── M-1.5 UNIFIED PIN LOGIN ────────────────────────────────────────────────
  // POST /auth/pin-login { phone, pin, role:'seller'|'buyer' }
  // Verifies pin (bcrypt) against ptn_users.dozie_pin_hash locally and
  // issues a Dozie JWT. No SMS/OTP. Replaces the buyer OTP login and
  // the MP backend's /auth/dozie-login for sellers.
  if (req.url === '/auth/pin-login' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      const send = (code, obj) => {
        res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify(obj));
      };
      try {
        const { phone, pin, role } = JSON.parse(body || '{}');
        const cleanPhone = String(phone || '').replace(/^\+?237/, '').replace(/\D/g, '');
        if (!cleanPhone || !pin || (role !== 'seller' && role !== 'buyer')) {
          return send(400, { success: false, code: 'bad_request',
            message: 'phone, pin and role (seller|buyer) are required' });
        }
        if (pinRateBlocked(cleanPhone)) {
          return send(429, { success: false, code: 'rate_limited',
            message: 'Too many attempts. Try again in 15 minutes.' });
        }
        if (!DOZIE_JWT_SECRET) {
          return send(500, { success: false, code: 'server_misconfig',
            message: 'Auth not configured (DOZIE_JWT_SECRET missing)' });
        }

        // M-2.1 Phase B.4: bcrypt verification now happens inside the
        // auth_pin_login SECURITY DEFINER RPC — no direct ptn_users read,
        // dozie_pin_hash never leaves the DB. cleanPhone is already digits-
        // only with the +?237 country code stripped (the same canonical
        // form the old direct lookup used, so the 88 existing rows still
        // match; the RPC also strips non-digits internally for matching).
        const rpc = await supaRpc('auth_pin_login',
          { p_phone: cleanPhone, p_pin: String(pin), p_role: role });

        if (!rpc || rpc.ok !== true) {
          if (rpc && rpc.error === 'suspended') {
            return send(403, { success: false, code: 'suspended',
              message: 'This account is suspended — contact support.' });
          }
          // Uniform 401 for every other failure — never reveal whether the
          // phone or the PIN was wrong (no account enumeration).
          pinNoteFail(cleanPhone);
          return send(401, { success: false, code: 'invalid_credentials',
            message: 'Invalid phone or PIN' });
        }

        const user = rpc.user || {};
        if (user.status === 'suspended') {
          return send(403, { success: false, code: 'suspended',
            message: 'This account is suspended — contact support.' });
        }
        pinClear(cleanPhone);
        const jwtToken = issueDozieJwt(user.id, role);
        return send(200, {
          success: true,
          jwt: jwtToken,
          user: {
            id: user.id, name: user.name, phone: user.phone, role: user.role,
            company: user.company, city: user.city, category: user.category,
            status: user.status,
            // MP-DOZIE-SELLER-MIGRATION: surface the MP link so the portal can
            // route MP-linked sellers to Mon Partenaire for listing management.
            linked_mp_org_id: user.linked_mp_org_id || null
          }
        });
      } catch (e) {
        send(500, { success: false, code: 'server_error', message: e.message });
      }
    });
    return;
  }

  // POST /auth/register-buyer { name, phone, pin }
  // Self-registration for a non-MP buyer. Creates a ptn_users row
  // (role='buyer', also_buyer=true, dozie_pin_hash=bcrypt(pin)) and issues a
  // Dozie JWT so the new user is logged in immediately. Fully independent of
  // Mon Partenaire — no MP account required. Duplicate (phone, role='buyer')
  // returns 409 so the UI can route them to sign-in.
  if (req.url === '/auth/register-buyer' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      const send = (code, obj) => {
        res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify(obj));
      };
      try {
        const { name, phone, pin } = JSON.parse(body || '{}');
        const cleanName  = String(name || '').trim();
        const cleanPhone = String(phone || '').replace(/^\+?237/, '').replace(/\D/g, '');
        const cleanPin   = String(pin || '').replace(/\D/g, '');
        if (!cleanName)            return send(400, { success: false, code: 'bad_request', message: 'Le nom est requis.' });
        if (cleanPhone.length < 8) return send(400, { success: false, code: 'bad_request', message: 'Numéro de téléphone invalide.' });
        if (!/^\d{4}$/.test(cleanPin)) return send(400, { success: false, code: 'bad_pin', message: 'Le PIN doit comporter 4 chiffres.' });
        if (!DOZIE_JWT_SECRET || !DOZIE_SERVICE_KEY) {
          return send(500, { success: false, code: 'server_misconfig', message: 'Auth not configured.' });
        }
        // Duplicate (phone, role=buyer) — tell them to sign in.
        const existing = await supaRequestPrivileged('GET', 'ptn_users',
          'phone=eq.' + encodeURIComponent(cleanPhone) + '&role=eq.buyer&select=id&limit=1');
        if (Array.isArray(existing) && existing.length > 0) {
          return send(409, { success: false, code: 'duplicate_phone',
            message: 'Ce numéro a déjà un compte. Connectez-vous.' });
        }
        const dozie_pin_hash = await hashPin(cleanPin);
        const inserted = await supaRequestPrivileged('POST', 'ptn_users', '', {
          role: 'buyer', also_buyer: true, name: cleanName, phone: cleanPhone, dozie_pin_hash
        });
        const user = Array.isArray(inserted) ? inserted[0] : inserted;
        if (!user || !user.id) {
          // Unique-violation race or other PostgREST error.
          const errStr = JSON.stringify(inserted || {});
          if (/23505|duplicate/i.test(errStr)) {
            return send(409, { success: false, code: 'duplicate_phone',
              message: 'Ce numéro a déjà un compte. Connectez-vous.' });
          }
          return send(500, { success: false, code: 'insert_failed',
            message: (inserted && inserted.message) || 'Échec de la création du compte.' });
        }
        const jwtToken = issueDozieJwt(user.id, 'buyer');
        return send(200, {
          success: true,
          jwt: jwtToken,
          user: { id: user.id, name: user.name, phone: user.phone, role: 'buyer',
                  company: user.company, city: user.city, status: user.status }
        });
      } catch (e) {
        send(500, { success: false, code: 'server_error', message: e.message });
      }
    });
    return;
  }

  // ── ADMIN IMPERSONATE EXCHANGE ─────────────────────────────────────────────
  //
  // Same-origin to PARTENAIRE_Buyer.html / PARTENAIRE_Seller.html so the
  // admin-impersonation flow doesn't need CORS gymnastics. The admin portal
  // (MP backend) minted a JWT signed with ADMIN_IMPERSONATE_SECRET; we
  // verify it here, fetch the target ptn_users row, and return it. The
  // frontend stores the result in sessionStorage and renders an amber
  // banner. NO persistent token is issued — Dozie's existing auth model
  // is "currentUser in memory, anon-key Supabase calls", and we match it
  // exactly (just flagged as impersonation).
  //
  // Audit: writes one row to ptn_audit_log on success (best-effort —
  // failure is logged server-side but does not break the user flow,
  // because the MP-side audit entry on token mint is the load-bearing
  // record of the impersonation attempt).
  if (req.url.startsWith('/api/auth/impersonate-exchange') && req.method === 'GET') {
    try {
      if (!process.env.ADMIN_IMPERSONATE_SECRET) {
        res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ ok: false, error: 'ADMIN_IMPERSONATE_SECRET not configured on Dozie backend' }));
        return;
      }
      const u = new URL(req.url, 'http://x');
      const token = u.searchParams.get('token');
      if (!token) {
        res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ ok: false, error: 'token query param required' }));
        return;
      }
      let payload;
      try {
        payload = jwt.verify(token, process.env.ADMIN_IMPERSONATE_SECRET);
      } catch (e) {
        res.writeHead(401, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ ok: false, error: 'Impersonation token expired or invalid' }));
        return;
      }
      if (payload.type !== 'impersonate_dozie') {
        res.writeHead(401, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ ok: false, error: 'Wrong token type' }));
        return;
      }

      // SELECT the user row — anon-key Supabase REST, same way the frontend
      // does its reads. If the user was deleted in the 1-hour window we
      // return a clear error rather than a hollow session.
      (async () => {
        try {
          const fetchRes = await fetch('https://' + SUPA + '/rest/v1/ptn_users?id=eq.' + encodeURIComponent(payload.target_user_id) + '&select=*', {
            headers: { 'apikey': KEY, 'Authorization': 'Bearer ' + KEY }
          });
          const rows = await fetchRes.json();
          if (!rows || !rows.length) {
            res.writeHead(404, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
            res.end(JSON.stringify({ ok: false, error: 'Target user no longer exists' }));
            return;
          }
          const user = rows[0];
          if (user.status === 'suspended') {
            res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
            res.end(JSON.stringify({ ok: false, error: 'Target user is suspended' }));
            return;
          }

          // Best-effort audit insert. ptn_audit_log columns:
          // admin_email, action, target_type, target_id, details (jsonb).
          // Failure logged but doesn't block — MP-side audit entry on
          // token mint is the canonical record.
          fetch('https://' + SUPA + '/rest/v1/ptn_audit_log', {
            method: 'POST',
            headers: { 'apikey': KEY, 'Authorization': 'Bearer ' + KEY, 'Content-Type': 'application/json', 'Prefer': 'return=minimal' },
            body: JSON.stringify({
              admin_email: payload.admin_email,
              action:      'impersonate_exchange',
              target_type: 'ptn_users',
              target_id:   user.id,
              details:     {
                admin_id: payload.admin_id,
                target_user_name: user.name,
                target_user_role: user.role,
                ip: (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || null
              }
            })
          }).catch(e => console.warn('[impersonate-exchange] audit insert failed:', e.message));

          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({
            ok: true,
            user,
            admin_email: payload.admin_email,
            admin_id: payload.admin_id,
            impersonating: true
          }));
        } catch (e) {
          res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({ ok: false, error: e.message }));
        }
      })();
    } catch (outerErr) {
      res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ ok: false, error: outerErr.message }));
    }
    return;
  }

  // ── ADMIN IMPERSONATE END ──────────────────────────────────────────────────
  //
  // The frontend POSTs the same impersonation token back when the user
  // clicks "End session". We re-verify the signature (still valid for
  // 1h after issue) and write the closing audit entry. Failure is
  // non-fatal — the user's tab returns to login regardless.
  if (req.url === '/api/auth/impersonate-end' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const { token } = JSON.parse(body || '{}');
        if (!token || !process.env.ADMIN_IMPERSONATE_SECRET) {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({ ok: true, audited: false, reason: 'token or secret missing' }));
          return;
        }
        let payload;
        try { payload = jwt.verify(token, process.env.ADMIN_IMPERSONATE_SECRET); }
        catch (e) {
          // Token expired or invalid — still respond 200 so the frontend
          // can clear its state, but don't write a fake audit row.
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({ ok: true, audited: false, reason: 'token invalid' }));
          return;
        }
        if (payload.type !== 'impersonate_dozie') {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({ ok: true, audited: false, reason: 'wrong token type' }));
          return;
        }

        fetch('https://' + SUPA + '/rest/v1/ptn_audit_log', {
          method: 'POST',
          headers: { 'apikey': KEY, 'Authorization': 'Bearer ' + KEY, 'Content-Type': 'application/json', 'Prefer': 'return=minimal' },
          body: JSON.stringify({
            admin_email: payload.admin_email,
            action:      'admin_impersonate_end',
            target_type: 'ptn_users',
            target_id:   payload.target_user_id,
            details: {
              admin_id: payload.admin_id,
              ip: (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || null
            }
          })
        }).catch(e => console.warn('[impersonate-end] audit insert failed:', e.message));

        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ ok: true, audited: true }));
      } catch (e) {
        res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ ok: false, error: e.message }));
      }
    });
    return;
  }

  // LAUNCH-PAYMENT-SECURITY: /monetbil/notify, /monetbil/pay (the
  // client-supplied `sandbox:true` → fake-SUCCESS spoof) and the
  // Monetbil /payment-success return page were removed. Campay uses
  // /campay/pay → /campay/check (poll) and the authenticated
  // /campay/webhook below — no redirect/return page is involved.

  // ── ORDER SEARCH — scoped seller / buyer lookups ─────────────────────
  //
  // GET /api/seller/orders/search?ref=   (header x-dozie-seller-id)
  // GET /api/buyer/orders/search?ref=    (header x-dozie-buyer-id)
  //
  // Read-only, scoped server-side so a portal can only ever see its
  // own orders. Must run before the generic /api/ proxy.
  {
    const sm = /^\/api\/(seller|buyer)\/orders\/search$/i.exec(req.url.split('?')[0]);
    if (sm && req.method === 'GET') {
      const role = sm[1].toLowerCase();
      (async () => {
        const send = (code, obj) => {
          res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify(obj));
        };
        try {
          const u = new URL(req.url, 'http://x');
          const q = (u.searchParams.get('ref') || '').trim();
          // M-1.2 dual-auth: prefer the signed Dozie JWT; fall back
          // to the legacy x-dozie-{seller,buyer}-id header during the
          // grace period (resolveDozieIdentity console.warns on it).
          const idn = resolveDozieIdentity(req, role);
          if (idn.error === 'role')
            return send(403, { success: false, code: 'wrong_role',
              message: 'This token is not authorised for ' + role + ' data' });
          if (idn.error || !idn.uid)
            return send(401, { success: false, code: 'auth_required',
              message: 'Authentication required' });
          const scopeId = idn.uid;
          if (!q) return send(200, { success: true, data: [] });

          const col = role === 'seller' ? 'seller_id' : 'buyer_id';
          const params =
            col + '=eq.' + encodeURIComponent(scopeId) +
            '&order_ref=ilike.' + encodeURIComponent('*' + q + '*') +
            '&select=id,order_ref,status,payment_status,total,buyer_id,created_at' +
            '&order=created_at.desc&limit=20';
          const orders = await supaRequest('GET', 'ptn_orders', params);
          const list = Array.isArray(orders) ? orders : [];

          let buyerMap = {};
          const bids = [...new Set(list.map(o => o.buyer_id).filter(Boolean))];
          if (bids.length) {
            // M-2.1 Phase B.4: batch buyer-name lookup via RPC. Caller is
            // the authenticated seller/buyer running the order search
            // (scopeId = idn.uid from resolveDozieIdentity above).
            const mr = await supaRpc('get_users_minimal',
              { p_caller: scopeId, p_ids: bids });
            const us = (mr && mr.ok && Array.isArray(mr.users)) ? mr.users : [];
            us.forEach(b => { buyerMap[b.id] = b.name; });
          }
          const data = list.map(o => ({
            id: o.id, order_ref: o.order_ref, status: o.status,
            payment_status: o.payment_status, total: Number(o.total || 0),
            buyer_name: buyerMap[o.buyer_id] || null, created_at: o.created_at
          }));
          send(200, { success: true, data });
        } catch (e) {
          send(500, { success: false, message: e.message || 'Search error' });
        }
      })();
      return;
    }
  }

  // ── SPRINT D-1 — SELLER-TRIGGERED HANDOFF TO MP ──────────────────────
  //
  // POST /api/orders/<id>/complete-at-shop   body { payment_mode }
  // POST /api/orders/<id>/send-to-mp-cart    body { payment_mode, deposit_paid? }
  //
  // MP-linked seller → write a pa_online_cart row (same Supabase
  // project, so a direct supaRequest insert; no cross-service HTTP).
  // Standalone seller → complete locally: mark order delivered +
  // best-effort decrement ptn_products.stock by item NAME (items
  // carry no product_id — the QOF shape). Must run before the generic
  // /api/ proxy so these paths aren't forwarded to Supabase REST.
  {
    const handoffMatch = /^\/api\/orders\/([0-9a-f-]{36})\/(complete-at-shop|send-to-mp-cart)$/i.exec(req.url.split('?')[0]);
    if (handoffMatch && req.method === 'POST') {
      const orderId = handoffMatch[1];
      const kind    = handoffMatch[2]; // complete-at-shop | send-to-mp-cart
      let body = '';
      req.on('data', c => body += c);
      req.on('end', async () => {
        const send = (code, obj) => {
          res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify(obj));
        };
        try {
          let parsed = {};
          try { parsed = body ? JSON.parse(body) : {}; } catch (_) { parsed = {}; }
          const paymentMode  = parsed.payment_mode;
          const depositPaid  = Number(parsed.deposit_paid || 0);

          const orderRows = await supaRequest('GET', 'ptn_orders',
            'id=eq.' + encodeURIComponent(orderId) + '&select=*');
          const order = Array.isArray(orderRows) && orderRows[0];
          if (!order) return send(404, { success: false, message: 'Order not found' });
          // Accept any live post-confirmation status. Delivered is in
          // fact the most natural time to record the sale in MP
          // (buyer has the goods, escrow released). Reject only the
          // not-yet-actionable / dead states.
          if (!['confirmed', 'agreed', 'shipped', 'delivered'].includes(order.status))
            return send(409, { success: false, message: 'Order must be confirmed, shipped or delivered (is: ' + order.status + ')' });

          // Prevent double-handoff: a non-voided pa_online_cart row
          // for this order means it's already in the MP Online Cart.
          const existingHandoff = await supaRequest('GET', 'pa_online_cart',
            'dozie_order_id=eq.' + encodeURIComponent(orderId) +
            '&status=in.(pending,completed)&select=id,status');
          if (Array.isArray(existingHandoff) && existingHandoff[0])
            return send(409, { success: false, code: 'already_handed_off',
              message: 'Order already sent to MP Cart',
              mp_cart_entry_id: existingHandoff[0].id });

          const sellerRows = await supaRequestPrivileged('GET', 'ptn_users',
            'id=eq.' + encodeURIComponent(order.seller_id) + '&select=id,name,phone,linked_mp_org_id');
          const seller = Array.isArray(sellerRows) && sellerRows[0];
          if (!seller) return send(404, { success: false, message: 'Seller not found' });

          // Denormalise buyer for cashier display.
          let buyerName = null, buyerPhone = null;
          if (order.buyer_id) {
            const b = await supaRequestPrivileged('GET', 'ptn_users',
              'id=eq.' + encodeURIComponent(order.buyer_id) + '&select=name,phone');
            if (Array.isArray(b) && b[0]) { buyerName = b[0].name; buyerPhone = b[0].phone; }
          }

          const isStandalone = !seller.linked_mp_org_id;

          // send-to-mp-cart requires MP linkage (credit/partial has no
          // Dozie-side equivalent).
          if (kind === 'send-to-mp-cart' && isStandalone) {
            return send(400, { success: false, code: 'requires_mp',
              message: 'Credit / partial payments require a Mon Partenaire account. Standalone sellers can only complete fully-paid or pay-at-shop orders.' });
          }

          if (isStandalone) {
            // Local completion. ptn_orders → delivered; decrement
            // ptn_products.stock by name match (items have no product_id).
            await supaRequest('PATCH', 'ptn_orders', 'id=eq.' + encodeURIComponent(orderId),
              { status: 'delivered' });
            for (const it of (order.items || [])) {
              const nm = (it.name || '').trim();
              const qty = Number(it.qty || it.quantity || 0);
              if (!nm || qty <= 0) continue;
              const prodRows = await supaRequest('GET', 'ptn_products',
                'seller_id=eq.' + encodeURIComponent(seller.id) +
                '&name=ilike.' + encodeURIComponent(nm) + '&select=id,stock');
              const prod = Array.isArray(prodRows) && prodRows[0];
              if (prod) {
                const newStock = Math.max(0, Number(prod.stock || 0) - qty);
                await supaRequest('PATCH', 'ptn_products', 'id=eq.' + prod.id, { stock: newStock });
              }
            }
            await supaRequest('POST', 'ptn_audit_log', null, {
              admin_email: 'dozie-seller:' + (seller.phone || seller.id),
              action: 'dozie_standalone_sale_completed',
              target_type: 'ptn_orders', target_id: orderId,
              details: { order_ref: order.order_ref, payment_mode: paymentMode || 'pay_at_shop' }
            }).catch(() => {});
            return send(200, { success: true, handed_off: false, completed_locally: true });
          }

          // MP-linked → create the pa_online_cart entry. The unique
          // partial index (dozie_order_id WHERE status<>'voided')
          // prevents duplicate handoffs; surface a clean message on 409.
          const insert = {
            org_id: seller.linked_mp_org_id,
            dozie_order_id: orderId,
            dozie_order_ref: order.order_ref || orderId,
            payment_mode: paymentMode || (kind === 'complete-at-shop' ? 'pay_at_shop' : 'partial'),
            status: 'pending',
            buyer_name: buyerName,
            buyer_phone: buyerPhone,
            items: order.items || [],
            total_amount: order.total || 0,
            deposit_paid: depositPaid || order.deposit_paid || 0,
            campay_reference: order.campay_reference || null
          };
          const created = await supaRequest('POST', 'pa_online_cart', null, insert);
          if (!Array.isArray(created) || !created[0]) {
            // supaRequest returns the raw error object on failure.
            const msg = (created && (created.message || created.hint)) || 'Handoff insert failed';
            return send(500, { success: false, message: msg, detail: created });
          }
          await supaRequest('POST', 'ptn_audit_log', null, {
            admin_email: 'dozie-seller:' + (seller.phone || seller.id),
            action: kind === 'complete-at-shop' ? 'dozie_handoff_to_mp_cart' : 'dozie_handoff_to_mp_cart_credit',
            target_type: 'pa_online_cart', target_id: created[0].id,
            details: { order_ref: order.order_ref, payment_mode: insert.payment_mode, mp_org_id: seller.linked_mp_org_id }
          }).catch(() => {});
          return send(200, { success: true, handed_off: true, mp_cart_entry_id: created[0].id });
        } catch (e) {
          send(500, { success: false, message: e.message || 'Handoff error' });
        }
      });
      return;
    }
  }

  // STAGE-1-DOZIE-ORDER-RPC: re-run payment for an existing order
  // (orphans + Campay retries). Replaces the unauthenticated /campay/pay
  // for the buyer flow. RPC verifies the caller owns the order.
  //
  // ROUTE ORDERING — this block MUST sit before the generic /api/
  // Supabase proxy below; otherwise the proxy's startsWith('/api/')
  // intercepts the request and forwards to /rest/v1/orders/<uuid>/
  // retry-payment, which Supabase REST 404s as "invalid path
  // specified in request URL". Mirrors the at-shop handoff block
  // above (search for "complete-at-shop" — same ordering rationale).
  {
    const mRetry = req.url.split('?')[0].match(/^\/api\/orders\/([0-9a-fA-F-]{36})\/retry-payment$/);
    if (mRetry && req.method === 'POST') {
      let body = '';
      req.on('data', c => body += c);
      req.on('end', async () => {
        const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }); res.end(JSON.stringify(obj)); };
        try {
          const idn = resolveDozieIdentity(req, 'buyer');
          if (idn.error || !idn.uid) return send(401, { success: false, error_code: 'auth_failed', message: 'Authentication required' });
          const order_id = mRetry[1];
          const { payer_phone } = JSON.parse(body || '{}');
          if (!payer_phone) return send(400, { success: false, error_code: 'validation', message: 'payer_phone is required' });

          const rp = await supaRpc('ptn_request_payment', { p_caller: idn.uid, p_order_id: order_id, p_payer_phone: String(payer_phone) });
          if (!rp || rp.success !== true) {
            const ec = (rp && rp.error_code) || 'validation';
            const http = ec === 'forbidden' ? 403 : ec === 'not_found' ? 404 : 400;
            return send(http, { success: false, error_code: ec, message: (rp && rp.message) || 'Payment request failed', order_id });
          }
          let camp;
          try { camp = await campayCollect({ amount: rp.total, phone: String(payer_phone), description: 'PARTENAIRE ' + rp.order_ref, reference: rp.ext_reference }); }
          catch (e) { camp = { _error: e.message }; }
          if (!camp || !(camp.reference || camp.ussd_code)) {
            await supaRpc('ptn_record_campay_reference', { p_caller: idn.uid, p_order_id: order_id, p_campay_reference: null, p_campay_operator: null, p_campay_status: 'failed', p_error_message: 'Campay collect failed: ' + JSON.stringify(camp && (camp.message || camp._error || camp)) });
            return send(502, { success: false, error_code: 'campay_failed', message: 'Mobile money request failed. You can retry.', order_id, campay_error: camp });
          }
          await supaRpc('ptn_record_campay_reference', { p_caller: idn.uid, p_order_id: order_id, p_campay_reference: camp.reference || rp.ext_reference, p_campay_operator: camp.operator || null, p_campay_status: 'PENDING', p_error_message: null });
          return send(200, { success: true, order_id, order_ref: rp.order_ref, server_total: rp.total, campay_reference: camp.reference || rp.ext_reference, campay_operator: camp.operator || null, ussd_code: camp.ussd_code || null, expected_status: 'PENDING' });
        } catch (e) { send(500, { success: false, error_code: 'validation', message: e.message }); }
      });
      return;
    }
  }

  // ── SUPABASE API PROXY ────────────────────────────────────────────────
  //
  // Phase D — MP-subscription gating for sellers. Before forwarding to
  // Supabase REST, we intercept three operations:
  //   • PATCH /api/ptn_orders?id=eq.<id>     when the patch "accepts" an order
  //   • POST  /api/ptn_products              new listing
  //   • PATCH /api/ptn_products?id=eq.<id>   listing update
  // ── DOZIE-BILINGUAL-SEARCH: server-side product search ───────────────
  //   GET /api/dozie/search-products?q=&buyer_ref=
  // Accent/case-insensitive + synonym-bridged. ADDITIVE (raw query always in
  // the term set). Logs zero-result searches to dozie_search_misses (STEP 3).
  // Must run before the generic /api/ proxy. On ANY error returns 200 with
  // success:false so the buyer client can fall back to the legacy search.
  {
    const p0 = req.url.split('?')[0];
    // DOZIE-BILINGUAL: seller form pings this after a ptn_products create/edit
    // (the writes go straight to Supabase, not through this server, so this is
    // the reliable hook). Fire-and-forget; fail-open; never blocks the save.
    if (p0 === '/api/dozie/translate-product' && req.method === 'POST') {
      let body = '';
      req.on('data', c => { body += c; });
      req.on('end', () => {
        let id = null;
        try { id = (JSON.parse(body || '{}') || {}).id || null; } catch (_) {}
        if (id) dozieTranslateProductById(String(id));
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ success: true }));
      });
      return;
    }
    if (p0 === '/api/dozie/search-products' && req.method === 'GET') {
      (async () => {
        const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }); res.end(JSON.stringify(obj)); };
        try {
          const u = new URL(req.url, 'http://x');
          const rawQ = (u.searchParams.get('q') || '').trim();
          const buyerRef = (u.searchParams.get('buyer_ref') || '').trim() || null;
          if (!rawQ) return send(200, { success: true, data: [], count: 0, query_normalized: '', expanded: [] });
          const exp = dozieExpandQuery(rawQ);
          const norm = exp.norm, terms = exp.terms;
          const catalogue = await dozieGetCatalogue();
          // Prefix-aware + ranked (same shared module as the client): score each
          // listing, keep hits, sort by relevance tier desc (exact > prefix >
          // substring > synonym), stable on catalogue order for equal scores.
          const scored = [];
          for (let i = 0; i < catalogue.length; i++) {
            const s = DS.score(catalogue[i]._norm || '', exp);
            if (s > 0) scored.push({ p: catalogue[i], s: s, i: i });
          }
          scored.sort((a, b) => (b.s - a.s) || (a.i - b.i));
          const matched = scored.map(x => x.p);
          const data = matched.map(p => ({
            listing_id: p.listing_id, seller_id: p.seller_id, name: p.name,
            name_fr: p.name_fr, name_en: p.name_en,
            price: p.price, photo_url: p.photo_url, stock_state: p.stock_state,
            category: p.category, city: p.city,
          }));
          // STEP 3: best-effort zero-result logging. Never let it break search.
          if (data.length === 0) {
            try {
              await supaRequestPrivileged('POST', 'dozie_search_misses', '', {
                query_raw: rawQ, query_normalized: norm, buyer_ref: buyerRef, results_count: 0,
              });
            } catch (_) { /* swallow */ }
          }
          send(200, { success: true, data, count: data.length, query_normalized: norm, expanded: terms });
        } catch (e) {
          // Never break the buyer's search — client falls back to legacy on success:false.
          send(200, { success: false, data: [], error: (e && e.message) || 'search error' });
        }
      })();
      return;
    }

    // ── STEP 4: admin-only view of recent zero-result miss terms ────────
    //   GET /api/dozie/search-misses   (admin JWT, same as /admin/* routes)
    // Grouped by query_normalized, count desc, last 30 days. Tells Peter
    // which words to add to data/dozie_synonyms.json next.
    if (p0 === '/api/dozie/search-misses' && req.method === 'GET') {
      (async () => {
        const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }); res.end(JSON.stringify(obj)); };
        try {
          const j = readAdminJwt(req);  // module-level admin-JWT reader (same auth as the /admin/* routes)
          if (!j) return send(401, { success: false, error: 'auth_required' });
          const since = new Date(Date.now() - 30 * 24 * 3600 * 1000).toISOString();
          const rows = await supaRequestPrivileged('GET', 'dozie_search_misses',
            'select=query_normalized,query_raw,created_at&created_at=gte.' + encodeURIComponent(since) +
            '&order=created_at.desc&limit=5000');
          const list = Array.isArray(rows) ? rows : [];
          const agg = new Map();
          for (const r of list) {
            const k = r.query_normalized || '(blank)';
            const e = agg.get(k) || { query_normalized: k, count: 0, last_seen: r.created_at, example: r.query_raw };
            e.count++; if (r.created_at > e.last_seen) e.last_seen = r.created_at;
            agg.set(k, e);
          }
          const data = [...agg.values()].sort((a, b) => b.count - a.count).slice(0, 200);
          send(200, { success: true, window_days: 30, total_misses: list.length, data });
        } catch (e) {
          send(500, { success: false, error: (e && e.message) || 'server_error' });
        }
      })();
      return;
    }
  }

  // …and reject with a clear error if the seller's MP subscription is
  // anything other than active/trial. Buyers and read-only operations pass
  // through untouched. Full anon-key trust elimination is post-F.
  if (req.url.startsWith('/api/')) {
    const supaPath = '/rest/v1/' + req.url.slice(5);
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {

      // ── GATE: UNIFIED DOZIE ACCESS (Sprint B) ────────────────────────
      // Reads the dozie_seller_access view, which combines MP-linked
      // status (Sprint A) with the new standalone tier (Sprint B). The
      // view's access_state column is the authoritative answer:
      //   'full'    → no caps, allow always
      //   'limited' → free tier, enforce listing_cap/city_cap/orders_cap
      //   'blocked' → reject outright
      //
      // Order acceptance on free tier uses an atomic Postgres RPC
      // (increment_dozie_orders_accepted) so two concurrent acceptances
      // can't both squeak past a count-then-update check. The RPC returns
      // NULL when the cap was already at 2; gate treats NULL as block.
      try {
        const isOrdersPatch  = req.method === 'PATCH' && /^\/api\/ptn_orders\b/.test(req.url);
        const isProductsPost = req.method === 'POST'  && /^\/api\/ptn_products(\?|$)/.test(req.url);
        const isProductsPatch = req.method === 'PATCH' && /^\/api\/ptn_products\b/.test(req.url);

        if (isOrdersPatch || isProductsPost || isProductsPatch) {
          let parsedBody = null;
          try { parsedBody = body ? JSON.parse(body) : null; } catch (_) { parsedBody = null; }

          const extractIdFilter = (urlStr) => {
            const m = /[?&]id=eq\.([^&]+)/i.exec(urlStr);
            return m ? decodeURIComponent(m[1]) : null;
          };

          const fetchAccess = async (sellerId) => {
            try {
              const rows = await supaRequest('GET', 'dozie_seller_access',
                'seller_id=eq.' + encodeURIComponent(sellerId) +
                '&select=source,access_state,listing_cap,city_cap,orders_cap,orders_used,can_accept_orders,mp_plan,mp_id,seller_city,active_listings_count');
              if (Array.isArray(rows) && rows.length > 0) return rows[0];
              return null;
            } catch (_) { return null; }
          };

          const denyResponse = (acc, feature, extra) => {
            res.writeHead(403, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
            const planLabel = acc && (acc.mp_plan || acc.source || 'free');
            const messages = {
              dozie_access:  `Your current plan does not include Partenaire Dozie. Upgrade to a standalone Dozie subscription (3 000 FCFA/month) or to a Gold/Premium Mon Partenaire plan.`,
              listing_cap:   `You've hit the free-tier limit of 2 active listings. Upgrade to standalone Dozie (3 000 FCFA/month) for unlimited listings.`,
              city_cap:      `Free-tier sellers can only list in their own city (${(acc && acc.seller_city) || 'your city'}). Upgrade to standalone Dozie for unlimited cities.`,
              orders_cap:    `You've accepted your 2 free orders. Upgrade to standalone Dozie (3 000 FCFA/month) to keep selling.`
            };
            res.end(JSON.stringify({
              error: 'upgrade_required',
              code: feature === 'dozie_access' ? 'dozie_blocked' : 'dozie_free_cap',
              feature,
              current_plan: planLabel,
              source: acc && acc.source,
              access_state: acc && acc.access_state,
              mp_id: acc && acc.mp_id,
              message: messages[feature] || `Free-tier limit reached for ${feature}.`,
              upgrade_url: 'https://mon-partenaire-app.vercel.app',
              ...(extra || {})
            }));
          };

          // ─── DOZIE SELL RESTRICTIONS ────────────────────────────────
          // Port of the MP-side lib/dozieSellRules.js. Reads the admin BLOCK-RULES
          // table (ptn_sell_blocks) on the SAME shared Supabase and blocks a
          // disallowed CATEGORY × TOWN combination. Semantics match MP EXACTLY:
          // case-insensitive + trimmed; default-allow; only a matching block rule
          // denies (lenient). FAIL-OPEN: if the table is absent/unreadable (the
          // prod migration is held), the read returns non-array → treated as "no
          // rule" → allowed, so deploy order is irrelevant and no seller is ever
          // blocked by a missing table. Response shape mirrors the MP route:
          // 403 { success:false, code, message }.
          // KEY CHOICE: read with supaRequestPrivileged (service_role) — the MP
          // side reads the allowlist with its service client, and the new tables
          // grant nothing to anon, so the anon `supaRequest` would read empty and
          // silently fail-open in prod. Service read = decision only (never
          // returned to the client) and resolves to [] if the key is unset
          // (still fail-open). It bypasses RLS so the row is always seen.
          // MP-NIGERIA: resolve the seller's COUNTRY (for country-scoped town
          // matching) from their linked MP org. Fail-open → null on any miss,
          // which makes the town check below ALLOW (default-allow contract).
          const resolveSellerCountry = async (sellerId) => {
            if (!sellerId) return null;
            try {
              const u = await supaRequestPrivileged('GET', 'ptn_users',
                'id=eq.' + encodeURIComponent(sellerId) + '&select=linked_mp_org_id');
              const orgId = Array.isArray(u) && u[0] && u[0].linked_mp_org_id;
              if (!orgId) return null;
              const o = await supaRequestPrivileged('GET', 'pa_organisations',
                'id=eq.' + encodeURIComponent(orgId) + '&select=country');
              return (Array.isArray(o) && o[0] && o[0].country) || null;
            } catch (_) { return null; }
          };
          // Enforcement now reads ONLY the ptn_sell_blocks block-rules table (a row
          // BLOCKS a category × town combination; NULL = wildcard). BYTE-IDENTICAL
          // logic to the MP copy (backend/src/lib/dozieSellRules.js) — both must
          // return the same allow/block. Default-allow; FAIL-OPEN per dimension (a
          // NULL/empty town or country only satisfies a wildcard rule on that
          // dimension); FAIL-OPEN if the table is absent/unreadable → [] → allowed.
          const _normSR = (s) => String(s == null ? '' : s).trim().toLowerCase();
          const checkSellRules = async (category, city, country) => {
            let rules;
            try {
              rules = await supaRequestPrivileged('GET', 'ptn_sell_blocks',
                'select=category_slug,country,town');
            } catch (_) { rules = null; } // table missing/unreadable → fail open
            if (!Array.isArray(rules) || !rules.length) return { ok: true };
            const nCat = _normSR(category), nCtry = _normSR(country), nTown = _normSR(city);
            const hit = rules.find((r) =>
              (r.category_slug == null || _normSR(r.category_slug) === nCat) &&
              (r.country       == null || _normSR(r.country)       === nCtry) &&
              (r.town          == null || _normSR(r.town)          === nTown)
            );
            if (!hit) return { ok: true };
            if (hit.town != null) {
              return { ok: false, code: hit.category_slug != null ? 'COMBINATION_NOT_ALLOWED' : 'TOWN_NOT_ALLOWED',
                message: 'Selling in ' + hit.town + ' is currently not permitted on Partenaire Dozie. Contact support.' };
            }
            let label = hit.category_slug || category || '';
            if (hit.category_slug) {
              try {
                const cr = await supaRequestPrivileged('GET', 'ptn_sell_categories',
                  'category_slug=eq.' + encodeURIComponent(hit.category_slug) + '&select=label');
                if (Array.isArray(cr) && cr[0] && cr[0].label) label = cr[0].label;
              } catch (_) {}
            }
            return { ok: false, code: 'CATEGORY_NOT_ALLOWED',
              message: 'Selling in the "' + label + '" category is currently not permitted on Partenaire Dozie. Contact support.' };
          };
          const sendSellDeny = (chk) => {
            res.writeHead(403, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
            res.end(JSON.stringify({ success: false, code: chk.code, message: chk.message }));
          };
          // Check every item in the body (single object OR a bulk array).
          const enforceSellRules = async (country) => {
            const items = Array.isArray(parsedBody) ? parsedBody : (parsedBody ? [parsedBody] : []);
            for (const it of items) {
              const chk = await checkSellRules(it && it.category, it && it.city, country);
              if (!chk.ok) { sendSellDeny(chk); return false; }
            }
            return true;
          };

          // ─── ORDER ACCEPTANCE ───────────────────────────────────────
          if (isOrdersPatch) {
            const looksLikeAccept = parsedBody && (
              parsedBody.status === 'confirmed' ||
              parsedBody.status === 'shipped' ||
              (parsedBody.escrow_held !== undefined && Number(parsedBody.escrow_held) > 0)
            );
            if (looksLikeAccept) {
              const orderId = extractIdFilter(req.url);
              if (orderId) {
                const orderRows = await supaRequest('GET', 'ptn_orders',
                  'id=eq.' + encodeURIComponent(orderId) + '&select=seller_id');
                const sellerId = Array.isArray(orderRows) && orderRows[0] && orderRows[0].seller_id;
                if (sellerId) {
                  const acc = await fetchAccess(sellerId);
                  if (!acc || acc.access_state === 'blocked') return denyResponse(acc, 'dozie_access');
                  if (acc.access_state === 'limited') {
                    // Atomic increment via Postgres RPC. Returns NULL when the
                    // seller is already at the cap; otherwise the new count.
                    let newCount = null;
                    try {
                      const rpc = await supaRequest('POST', 'rpc/increment_dozie_orders_accepted',
                        null, { p_seller_id: sellerId });
                      newCount = (typeof rpc === 'number') ? rpc : (rpc && rpc.length ? rpc[0] : null);
                    } catch (_) { newCount = null; }
                    if (newCount == null) return denyResponse(acc, 'orders_cap', { orders_used: acc.orders_used, orders_cap: acc.orders_cap });
                  }
                }
              }
            }
          }

          // ─── LISTING CREATE ────────────────────────────────────────
          if (isProductsPost) {
            // DOZIE-SELL-RESTRICTIONS: block disallowed category/town first
            // (applies to ALL sellers). COUNTRY-SCOPED — resolve the seller's
            // country before the (now country-aware) sell-rule check.
            const sellerId = parsedBody && (parsedBody.seller_id || (Array.isArray(parsedBody) && parsedBody[0] && parsedBody[0].seller_id));
            if (!(await enforceSellRules(await resolveSellerCountry(sellerId)))) return;
            if (sellerId) {
              const acc = await fetchAccess(sellerId);
              if (!acc || acc.access_state === 'blocked') return denyResponse(acc, 'dozie_access');
              if (acc.access_state === 'limited') {
                // Listing-count cap (re-read the view's count for accuracy
                // since publishing/unpublishing toggles inclusion).
                if (acc.listing_cap != null && acc.active_listings_count >= acc.listing_cap) {
                  return denyResponse(acc, 'listing_cap', { listing_cap: acc.listing_cap, active_listings_count: acc.active_listings_count });
                }
                // City-cap — free tier sellers may only list in their own
                // city. ptn_products doesn't currently carry a city field,
                // but if the payload includes one and it differs from the
                // seller's home city, reject.
                if (acc.city_cap === 1 && parsedBody && parsedBody.city && parsedBody.city !== acc.seller_city) {
                  return denyResponse(acc, 'city_cap', { seller_city: acc.seller_city, requested_city: parsedBody.city });
                }
              }
            }
          }

          // ─── LISTING UPDATE ────────────────────────────────────────
          if (isProductsPatch) {
            // DOZIE-SELL-RESTRICTIONS: if the update sets category/city, block a
            // disallowed value (lenient — a patch that doesn't touch them passes).
            // COUNTRY-SCOPED — resolve the product's seller country first.
            const productId = extractIdFilter(req.url);
            let sellerId = null;
            if (productId) {
              const productRows = await supaRequest('GET', 'ptn_products',
                'id=eq.' + encodeURIComponent(productId) + '&select=seller_id');
              sellerId = Array.isArray(productRows) && productRows[0] && productRows[0].seller_id;
            }
            if (!(await enforceSellRules(await resolveSellerCountry(sellerId)))) return;
            if (sellerId) {
              const acc = await fetchAccess(sellerId);
              if (!acc || acc.access_state === 'blocked') return denyResponse(acc, 'dozie_access');
              // Updates by a 'limited' seller stay allowed — they can
              // edit existing listings without hitting the cap. Only the
              // CREATE path enforces listing_cap.
              if (acc.access_state === 'limited' && acc.city_cap === 1
                  && parsedBody && parsedBody.city && parsedBody.city !== acc.seller_city) {
                return denyResponse(acc, 'city_cap', { seller_city: acc.seller_city, requested_city: parsedBody.city });
              }
            }
          }
        }
      } catch (gateErr) {
        // Gate failure → fail open. Better to let the action through than
        // to lock the seller out on a transient internal error. The MP
        // admin still sees the audit trail downstream.
        console.warn('[mp-gate] gate evaluation failed:', gateErr && gateErr.message);
      }

      // ── Forward to Supabase REST (existing behaviour) ────────────────
      // DOZIE-BILINGUAL: recompute the ptn_products write flag in THIS scope —
      // the gate's isProductsPost/isProductsPatch are const-scoped to the try
      // block above and aren't visible here.
      const isProdWrite =
        (req.method === 'POST'  && /^\/api\/ptn_products(\?|$)/.test(req.url)) ||
        (req.method === 'PATCH' && /^\/api\/ptn_products\b/.test(req.url));
      const options = {
        hostname: SUPA, path: supaPath, method: req.method,
        headers: {
          apikey: KEY, 'Authorization': 'Bearer ' + KEY,
          'Content-Type': 'application/json',
          'Prefer': req.headers['prefer'] || 'return=representation'
        }
      };
      const pr = https.request(options, r => {
        // DOZIE-BILINGUAL: for a ptn_products create/edit, buffer the response so
        // we can read back the affected row and refresh its FR/EN (fire-and-forget,
        // fail-open) — every other proxied request still pipes straight through.
        if (isProdWrite) {
          let buf = '';
          r.on('data', d => { buf += d; });
          r.on('end', () => {
            res.writeHead(r.statusCode, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
            res.end(buf);
            if (r.statusCode >= 200 && r.statusCode < 300) dozieRefreshProductTranslations(buf);
          });
          r.on('error', () => { try { res.writeHead(502); res.end(); } catch (_) {} });
          return;
        }
        res.writeHead(r.statusCode, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        r.pipe(res);
      });
      pr.on('error', e => { res.writeHead(500); res.end(JSON.stringify({ error: e.message })); });
      if (body) pr.write(body);
      pr.end();
    });
    return;
  }

  // ── STAGE-1-DOZIE-ORDER-RPC: authenticated order creation + pay ──
  // Buyer JWT is the ONLY source of truth for buyer_id (body buyer_id
  // ignored). Server recomputes the total in ptn_create_order. One
  // (seller, items) per call — the frontend loops multi-seller carts.
  if (req.url === '/api/orders/create-and-pay' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }); res.end(JSON.stringify(obj)); };
      try {
        const idn = resolveDozieIdentity(req, 'buyer');
        if (idn.error || !idn.uid) return send(401, { success: false, error_code: 'auth_failed', message: 'Authentication required' });
        const { seller_id, items, client_total, mode, pay_option, city, notes, payer_phone } = JSON.parse(body || '{}');

        // v1: payments disabled → create the order and return a "pay at
        // shop" success. Skips ptn_request_payment + campayCollect entirely
        // (no payer_phone needed since nothing is charged).
        if (!PAYMENTS_ENABLED) {
          if (!seller_id || !Array.isArray(items) || !items.length)
            return send(400, { success: false, error_code: 'validation', message: 'seller_id and items are required' });
          const cr0 = await supaRpc('ptn_create_order', {
            p_caller: idn.uid, p_seller_id: seller_id, p_items: items,
            p_client_total: Number(client_total), p_mode: mode || 'delivery',
            p_pay_option: 'at_shop', p_city: city || null, p_notes: notes || null
          });
          if (!cr0 || cr0.success !== true) {
            const ec0 = (cr0 && cr0.error_code) || 'validation';
            return send(ec0 === 'auth_failed' ? 401 : 400, { success: false, error_code: ec0, message: (cr0 && cr0.message) || 'Order rejected', server_total: cr0 && cr0.server_total });
          }
          return send(200, { success: true, order_id: cr0.order_id, order_ref: cr0.order_ref, server_total: cr0.server_total, payment_disabled: true, pay_at_shop: true, message: 'Paiement à effectuer en boutique' });
        }

        if (!seller_id || !Array.isArray(items) || !items.length || !payer_phone)
          return send(400, { success: false, error_code: 'validation', message: 'seller_id, items and payer_phone are required' });

        // 1. Create the order (server-side total + 60s idempotency).
        const cr = await supaRpc('ptn_create_order', {
          p_caller: idn.uid, p_seller_id: seller_id, p_items: items,
          p_client_total: Number(client_total), p_mode: mode || 'delivery',
          p_pay_option: pay_option || 'full', p_city: city || null, p_notes: notes || null
        });
        if (!cr || cr.success !== true) {
          const ec = (cr && cr.error_code) || 'validation';
          const http = ec === 'auth_failed' ? 401 : 400;
          return send(http, { success: false, error_code: ec, message: (cr && cr.message) || 'Order rejected', server_total: cr && cr.server_total });
        }
        const { order_id, order_ref, server_total } = cr;

        // 2. Mark payment requested (ownership re-checked in the RPC).
        const rp = await supaRpc('ptn_request_payment', { p_caller: idn.uid, p_order_id: order_id, p_payer_phone: String(payer_phone) });
        if (!rp || rp.success !== true)
          return send(400, { success: false, error_code: (rp && rp.error_code) || 'validation', message: (rp && rp.message) || 'Payment request failed', order_id });

        // 3. Campay collect. On failure: keep the order, mark failed,
        //    let the buyer retry via /api/orders/:id/retry-payment.
        let camp;
        try { camp = await campayCollect({ amount: server_total, phone: String(payer_phone), description: 'PARTENAIRE ' + order_ref, reference: rp.ext_reference }); }
        catch (e) { camp = { _error: e.message }; }
        if (!camp || !(camp.reference || camp.ussd_code)) {
          await supaRpc('ptn_record_campay_reference', { p_caller: idn.uid, p_order_id: order_id, p_campay_reference: null, p_campay_operator: null, p_campay_status: 'failed', p_error_message: 'Campay collect failed: ' + JSON.stringify(camp && (camp.message || camp._error || camp)) });
          return send(502, { success: false, error_code: 'campay_failed', message: 'Mobile money request failed. You can retry.', order_id, campay_error: camp });
        }

        // 4. Persist the Campay reference.
        await supaRpc('ptn_record_campay_reference', { p_caller: idn.uid, p_order_id: order_id, p_campay_reference: camp.reference || rp.ext_reference, p_campay_operator: camp.operator || null, p_campay_status: 'PENDING', p_error_message: null });
        return send(200, { success: true, order_id, order_ref, server_total, campay_reference: camp.reference || rp.ext_reference, campay_operator: camp.operator || null, ussd_code: camp.ussd_code || null, expected_status: 'PENDING' });
      } catch (e) { send(500, { success: false, error_code: 'validation', message: e.message }); }
    });
    return;
  }

  // â”€â”€
  // ── CAMPAY PAY ─────────────────────────────────────────────
  // TODO STAGE-2: legacy unauthenticated path kept functional until the
  // buyer flow fully cuts over; secured replacement is
  // /api/orders/:id/retry-payment above.
  // ── FLUTTERWAVE: INITIATE (Slice 1 collect) ──────────────────
  // Buyer starts a hosted-checkout payment for a confirmed, payment-requested
  // order. Returns { link } to redirect to. payment_status is NOT set here —
  // only a verified webhook/return settles it.
  if (req.url === '/flw/initiate' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }); res.end(JSON.stringify(obj)); };
      try {
        if (!FLW_ROUTES_ACTIVE) return send(503, { success: false, error_code: 'payments_disabled', message: 'Online payment is not enabled' });
        const idn = resolveDozieIdentity(req, 'buyer');
        if (idn.error || !idn.uid) return send(401, { success: false, error_code: 'auth_failed', message: 'Authentication required' });
        const { order_id } = JSON.parse(body || '{}');
        if (!order_id) return send(400, { success: false, error_code: 'validation', message: 'order_id required' });

        const orders = await supaRequest('GET', 'ptn_orders', 'id=eq.' + order_id + '&select=*');
        const order = Array.isArray(orders) && orders[0];
        if (!order) return send(404, { success: false, error_code: 'not_found', message: 'Order not found' });
        if (order.buyer_id !== idn.uid) return send(403, { success: false, error_code: 'forbidden', message: 'Not your order' });
        if (order.payment_status === 'paid') return send(409, { success: false, error_code: 'already_paid', message: 'Order already paid' });
        if (!(order.status === 'confirmed' && order.payment_requested)) return send(409, { success: false, error_code: 'not_payable', message: 'Order is not awaiting payment (status: ' + order.status + ')' });

        const cur = await resolveOrderCurrency(order);
        if (!cur.currency) return send(422, { success: false, error_code: 'currency_unresolved', message: 'Could not resolve the order currency (seller has no linked country). Online payment unavailable for this seller.', reason: cur.reason });

        const amt = Number(orderEscrowAmount(order));
        if (!(amt > 0)) return send(422, { success: false, error_code: 'bad_amount', message: 'Order amount is not payable' });

        // Buyer contact (email synthesized from phone, like MP).
        const buyers = await supaRequestPrivileged('GET', 'ptn_users', 'id=eq.' + idn.uid + '&select=id,phone,name');
        const buyer = (Array.isArray(buyers) && buyers[0]) || {};
        const phone = buyer.phone || order.payer_phone || '';
        const email = (phone ? String(phone).replace(/[^0-9]/g, '') : order.order_ref) + '@nomail.partenaire.app';

        const txRef = 'DZORD-' + order.order_ref + '-' + Date.now() + '-' + Math.random().toString(36).slice(2, 7);
        const redirect_url = dozieBaseUrl(req) + '/buyer?flw_tx=' + encodeURIComponent(txRef);

        let link;
        try {
          ({ link } = await FLW.createPayment({
            tx_ref: txRef, amount: amt, currency: cur.currency, redirect_url,
            customer: { email, name: buyer.name || 'Buyer', phonenumber: phone || '' },
            meta: { order_id: order.id, order_ref: order.order_ref, seller_id: order.seller_id, buyer_id: order.buyer_id },
            title: 'Partenaire Dozie — ' + order.order_ref,
            payment_options: flwPaymentOptions(cur.currency),
          }));
        } catch (e) {
          await supaRequest('POST', 'ptn_campay_transactions', null, { reference: txRef, order_id: order.id, transaction_type: 'flutterwave_collect', amount: amt, currency: cur.currency, payer_phone: phone, status: 'failed' }).catch(() => {});
          console.error('[flw initiate]', e.message, e.flw || '');
          return send(502, { success: false, error_code: 'flw_init_failed', message: 'Could not start the online payment. Please try again.' });
        }

        // Record the attempt so the webhook/return can find the order by tx_ref.
        await supaRequest('POST', 'ptn_campay_transactions', null, { reference: txRef, order_id: order.id, transaction_type: 'flutterwave_collect', amount: amt, currency: cur.currency, payer_phone: phone, status: 'initiated' });
        await supaRequest('PATCH', 'ptn_orders', 'id=eq.' + order.id, { campay_reference: txRef, campay_status: 'initiated', payment_method: 'flutterwave', updated_at: new Date().toISOString() }).catch(() => {});
        return send(200, { success: true, link, tx_ref: txRef, amount: amt, currency: cur.currency });
      } catch (e) { send(500, { success: false, error_code: 'error', message: e.message }); }
    });
    return;
  }

  // ── FLUTTERWAVE: WEBHOOK (primary settle) ────────────────────
  // Cloned from MP: header verif-hash === FLW_SECRET_HASH → else 401 (503 if
  // unset); then a server-side verify decides — never the webhook's own claim.
  if (req.url === '/flw/webhook' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }); res.end(JSON.stringify(obj)); };
      try {
        const secret = process.env.FLW_SECRET_HASH;
        if (!secret) { console.error('[flw webhook] FLW_SECRET_HASH not set — rejecting'); return send(503, { ok: false, error: 'webhook_not_configured' }); }
        const sent = req.headers['verif-hash'];
        if (!sent || sent !== secret) return send(401, { ok: false, error: 'invalid_hash' });

        const payload = JSON.parse(body || '{}');
        const data = payload.data || {};
        const txRef = data.tx_ref, txId = data.id;
        const chargeStatus = String(data.status || '').toLowerCase();
        if (!txRef) return send(200, { ok: true, skipped: 'no_tx_ref' });
        if (!String(txRef).startsWith('DZORD-')) return send(200, { ok: true, skipped: 'not_dozie_order' });

        if (chargeStatus !== 'successful') {
          if (chargeStatus === 'failed' || chargeStatus === 'cancelled')
            await supaRequest('PATCH', 'ptn_campay_transactions', 'reference=eq.' + encodeURIComponent(txRef), { status: chargeStatus, updated_at: new Date().toISOString() }).catch(() => {});
          return send(200, { ok: true, status: chargeStatus });
        }

        let verified;
        try { verified = await FLW.verifyTransaction(txId); }
        catch (e) { console.error('[flw webhook] verify failed:', e.message); return send(200, { ok: true, verified: false, reason: 'verify_error' }); }

        const r = await flwSettle({ verified, txRef, source: 'webhook' });
        return send(200, { ok: true, settled: r.ok, idempotent: !!r.idempotent, reason: r.reason || null });
      } catch (e) { send(200, { ok: false, error: e.message }); }
    });
    return;
  }

  // ── FLUTTERWAVE: VERIFY-RETURN (redirect fallback) ───────────
  // FLW redirects the buyer to /buyer?flw_tx=<ref>&transaction_id=<id>. The
  // buyer page posts here so a missed webhook still settles. Same verify +
  // idempotency as the webhook — the redirect itself never settles anything.
  if (req.url === '/flw/verify-return' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }); res.end(JSON.stringify(obj)); };
      try {
        if (!FLW_ROUTES_ACTIVE) return send(503, { success: false, message: 'Online payment is not enabled' });
        const idn = resolveDozieIdentity(req, 'buyer');
        if (idn.error || !idn.uid) return send(401, { success: false, message: 'Authentication required' });
        const { tx_ref, transaction_id } = JSON.parse(body || '{}');
        if (!tx_ref || !transaction_id) return send(400, { success: false, message: 'tx_ref and transaction_id required' });
        if (!String(tx_ref).startsWith('DZORD-')) return send(400, { success: false, message: 'bad tx_ref' });

        let verified;
        try { verified = await FLW.verifyTransaction(transaction_id); }
        catch (e) { return send(200, { success: false, verified: false, reason: 'verify_error' }); }

        const r = await flwSettle({ verified, txRef: tx_ref, source: 'return' });
        return send(200, { success: r.ok, paid: r.ok, idempotent: !!r.idempotent, order_id: r.order_id || null, reason: r.reason || null });
      } catch (e) { send(500, { success: false, message: e.message }); }
    });
    return;
  }

  // ── FLUTTERWAVE: MARK PAID OUT (admin, MANUAL payout this slice) ──
  // No automated FLW Transfers yet. Peter records an out-of-band seller payment
  // here: sets escrow_released=true + a manual payout ref + status delivered.
  if (req.url === '/flw/mark-paid-out' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }); res.end(JSON.stringify(obj)); };
      try {
        const { order_id, admin_pin, payout_ref } = JSON.parse(body || '{}');
        if (!process.env.ADMIN_PIN || admin_pin !== process.env.ADMIN_PIN) return send(200, { success: false, message: 'Non autorisé' });
        if (!order_id) return send(400, { success: false, message: 'order_id required' });
        const orders = await supaRequest('GET', 'ptn_orders', 'id=eq.' + order_id + '&select=*');
        const order = Array.isArray(orders) && orders[0];
        if (!order) return send(404, { success: false, message: 'Order not found' });
        if (order.escrow_released) return send(200, { success: false, message: 'Already released' });
        if (order.payment_status !== 'paid' || !order.escrow_held) return send(200, { success: false, message: 'No escrow to release' });
        const ref = payout_ref || ('MANUAL-' + order.order_ref + '-' + Date.now());
        await supaRequest('PATCH', 'ptn_orders', 'id=eq.' + order_id, { escrow_released: true, campay_payout_ref: ref, campay_payout_at: new Date().toISOString(), status: 'delivered', updated_at: new Date().toISOString() });
        await supaRequest('POST', 'ptn_audit_log', null, { action: 'flw_manual_payout_recorded', target_type: 'ptn_orders', target_id: order_id, details: { order_ref: order.order_ref, amount: order.escrow_held, payout_ref: ref } }).catch(() => {});
        await supaRequest('POST', 'ptn_notifications', null, { user_id: order.seller_id, type: 'payment', order_id, title_en: 'Payout Sent', title_fr: 'Paiement envoyé', body_en: 'Payout for order ' + order.order_ref + ' has been sent (ref ' + ref + ').', body_fr: 'Le paiement de la commande ' + order.order_ref + ' a été envoyé (réf ' + ref + ').', read: false }).catch(() => {});
        return send(200, { success: true, order_id, payout_ref: ref, amount: order.escrow_held });
      } catch (e) { send(500, { success: false, message: e.message }); }
    });
    return;
  }

  if (req.url === '/campay/pay' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const { order_id, phone, amount, type } = JSON.parse(body);
        if (!phone || !amount) {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          return res.end(JSON.stringify({ success: false, message: 'Phone and amount required' }));
        }
        const ref = 'PAY-' + Date.now() + '-' + Math.random().toString(36).substr(2,6).toUpperCase();
        const token = await getCampayToken();
        const cleanPhone = String(phone).replace(/\s/g,'').replace(/^\+/,'');
        const cr = await fetch(CAMPAY_BASE_URL + '/collect/', {
          method: 'POST',
          headers: { 'Authorization': 'Token ' + token, 'Content-Type': 'application/json' },
          body: JSON.stringify({ amount: String(amount), currency: 'XAF', from: cleanPhone, description: 'Paiement PARTENAIRE', external_reference: ref })
        });
        const result = await cr.json();
        await supaRequest('POST', 'ptn_campay_transactions', null, { reference: ref, order_id: order_id || null, transaction_type: type || 'payment', amount, payer_phone: phone, status: 'pending' });
        if (result.reference || result.ussd_code) {
          if (order_id) await supaRequest('PATCH', 'ptn_orders', 'id=eq.' + order_id, { campay_reference: ref, campay_status: 'pending', payer_phone: phone });
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({ success: true, reference: ref, ussd_code: result.ussd_code, operator: result.operator }));
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({ success: false, message: result.message || 'Paiement echoue', details: result }));
        }
      } catch(e) {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ success: false, message: e.message }));
      }
    });
    return;
  }

  // ── CAMPAY CHECK ────────────────────────────────────────────
  if (req.url === '/campay/check' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const { reference, order_id } = JSON.parse(body);
        const token = await getCampayToken();
        const cr = await fetch(CAMPAY_BASE_URL + '/transaction/' + reference + '/', { headers: { 'Authorization': 'Token ' + token } });
        const result = await cr.json();
        const isPaid = result.status === 'SUCCESSFUL';
        await supaRequest('PATCH', 'ptn_campay_transactions', 'reference=eq.' + reference, { status: isPaid ? 'successful' : (result.status || 'pending').toLowerCase(), updated_at: new Date().toISOString() });
        if (isPaid && order_id) {
          const orders = await supaRequest('GET', 'ptn_orders', 'id=eq.' + order_id + '&select=total,counter_total,counter_status,seller_id,order_ref');
          const order = orders && orders[0];
          const amt = order && order.counter_status === 'accepted' ? order.counter_total : order && order.total;
          await supaRequest('PATCH', 'ptn_orders', 'id=eq.' + order_id, { payment_status: 'paid', campay_status: 'successful', campay_paid_at: new Date().toISOString(), escrow_held: amt, status: 'confirmed' });
          if (order) await supaRequest('POST', 'ptn_notifications', null, { user_id: order.seller_id, type: 'payment', title_en: 'Payment Received', title_fr: 'Paiement recu', body_en: 'Order ' + order.order_ref + ' paid.', body_fr: 'Commande ' + order.order_ref + ' payee.', order_id });
        }
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ success: true, paid: isPaid, status: result.status }));
      } catch(e) {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ success: false, message: e.message }));
      }
    });
    return;
  }

  // ── CAMPAY RELEASE (admin) ──────────────────────────────────
  if (req.url === '/campay/release' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const { order_id, admin_pin } = JSON.parse(body);
        if (!process.env.ADMIN_PIN || admin_pin !== process.env.ADMIN_PIN) {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          return res.end(JSON.stringify({ success: false, message: 'Non autorise' }));
        }
        const orders = await supaRequest('GET', 'ptn_orders', 'id=eq.' + order_id + '&select=*');
        const order = orders && orders[0];
        if (!order || order.escrow_released) {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          return res.end(JSON.stringify({ success: false, message: 'Invalid order' }));
        }
        const sellers = await supaRequestPrivileged('GET', 'ptn_users', 'id=eq.' + order.seller_id + '&select=id,phone,momo_phone,name');
        const sRow = (sellers && sellers[0]) || {};
        // MOMO-PHONE-CAPTURE: pay out to the seller's dedicated Mobile
        // Money number when set, else fall back to their login phone.
        const sellerPhone = (sRow.momo_phone || sRow.phone) || '';
        const payoutVia = sRow.momo_phone ? 'momo_phone' : 'phone';
        await supaRequest('POST', 'ptn_audit_log', null, {
          action: 'campay_payout_target', target_type: 'ptn_users', target_id: order.seller_id,
          details: { endpoint: '/campay/release', order_ref: order.order_ref, payout_phone: sellerPhone, source: payoutVia }
        }).catch(e => console.warn('[payout audit] ' + e.message));
        const ref = 'PAYOUT-' + order.order_ref + '-' + Date.now();
        const token = await getCampayToken();
        const cleanPhone = String(sellerPhone).replace(/\s/g,'').replace(/^\+/,'');
        const cr = await fetch(CAMPAY_BASE_URL + '/transfer/', {
          method: 'POST',
          headers: { 'Authorization': 'Token ' + token, 'Content-Type': 'application/json' },
          body: JSON.stringify({ amount: String(order.escrow_held), currency: 'XAF', to: cleanPhone, description: 'Paiement PARTENAIRE ' + order.order_ref, external_reference: ref })
        });
        const result = await cr.json();
        if (result.reference || result.status === 'SUCCESSFUL') {
          await supaRequest('PATCH', 'ptn_orders', 'id=eq.' + order_id, { escrow_released: true, campay_payout_ref: ref, campay_payout_at: new Date().toISOString(), status: 'delivered' });
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({ success: true, amount: order.escrow_held, reference: ref }));
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({ success: false, message: 'Virement echoue', details: result }));
        }
      } catch(e) {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ success: false, message: e.message }));
      }
    });
    return;
  }

  // ── CAMPAY WEBHOOK (LAUNCH-PAYMENT-SECURITY) ────────────────
  // Defence in depth — a webhook NEVER directly marks money received:
  //   1. Signature: Campay signs the payload. Per Campay's API docs the
  //      webhook body carries a `signature` field that is a JWT signed
  //      with the app's Webhook Key (HS256). We verify it with
  //      CAMPAY_WEBHOOK_SECRET. ⚠️ SCHEME-TO-CONFIRM: the codebase had no
  //      prior signature handling and Campay's exact field/algorithm must
  //      be confirmed from Peter's Campay dashboard before launch — see
  //      the report. This check is therefore best-effort; security does
  //      NOT depend on it because of (3).
  //   2. Idempotency: already-successful txn / already-paid order → 200,
  //      no re-credit, no duplicate notifications.
  //   3. Authoritative re-query (THE hard gate): regardless of what the
  //      webhook claims, we call Campay's /transaction/{ref}/ with our
  //      authenticated token and only proceed if Campay itself says
  //      SUCCESSFUL and the amount matches what we recorded. A forged or
  //      unsigned webhook cannot get past this — Campay's own API is the
  //      source of truth.
  //   4. Every outcome is written to ptn_audit_log.
  if (req.url === '/campay/webhook' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      const sendJson = (code, obj) => {
        res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify(obj));
      };
      const audit = (action, details) =>
        supaRequest('POST', 'ptn_audit_log', null, {
          admin_email: 'system:campay-webhook', action,
          target_type: 'ptn_campay_transactions',
          target_id: (details && details.reference) || null, details: details || {}
        }).catch(e => console.warn('[campay-webhook] audit insert failed:', e.message));

      let payload;
      try { payload = JSON.parse(body || '{}'); }
      catch { return sendJson(400, { error: 'bad_json' }); }
      const { reference, status, operator, signature } = payload;

      // (1) Signature — JWT in the body signed with the Webhook Key.
      // Enforced whenever the secret is configured (Task 3 makes it
      // mandatory in production).
      if (CAMPAY_WEBHOOK_SECRET) {
        let ok = false;
        try { if (signature) { jwt.verify(String(signature), CAMPAY_WEBHOOK_SECRET); ok = true; } }
        catch (_) { ok = false; }
        if (!ok) {
          await audit('campay_webhook_signature_invalid', {
            reference: reference || null,
            ip: (req.headers['x-forwarded-for'] || '').toString().split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || null
          });
          return sendJson(401, { error: 'invalid_signature' });
        }
      }

      if (!reference) return sendJson(400, { error: 'reference_required' });

      try {
        const txns = await supaRequest('GET', 'ptn_campay_transactions', 'reference=eq.' + encodeURIComponent(reference) + '&select=*');
        const txn = txns && txns[0];
        if (!txn) { await audit('campay_webhook_mismatch', { reference, reason: 'unknown_reference' }); return sendJson(200, { received: true, ignored: 'unknown_reference' }); }

        // (2) Idempotency.
        if (txn.status === 'successful') return sendJson(200, { received: true, idempotent: true });
        if (txn.order_id) {
          const paidChk = await supaRequest('GET', 'ptn_orders', 'id=eq.' + txn.order_id + '&select=payment_status');
          if (paidChk && paidChk[0] && paidChk[0].payment_status === 'paid')
            return sendJson(200, { received: true, idempotent: true });
        }

        // (3) Authoritative re-query — Campay is the source of truth.
        const token = await getCampayToken();
        const cr = await fetch(CAMPAY_BASE_URL + '/transaction/' + encodeURIComponent(reference) + '/', { headers: { 'Authorization': 'Token ' + token } });
        const verified = await cr.json();
        const expectedAmt = Number(txn.amount);
        const gotAmt = Number(verified && verified.amount);
        const statusOk = verified && verified.status === 'SUCCESSFUL';
        const amountOk = !Number.isNaN(expectedAmt) && !Number.isNaN(gotAmt) && gotAmt === expectedAmt;
        if (!statusOk || !amountOk) {
          await audit('campay_webhook_mismatch', {
            reference, order_id: txn.order_id || null,
            webhook_status: status, campay_status: verified && verified.status,
            expected_amount: expectedAmt, campay_amount: gotAmt
          });
          return sendJson(200, { received: true, verified: false });
        }

        // Verified — safe to mark paid (mirrors /campay/check).
        if (txn.order_id) {
          const orders = await supaRequest('GET', 'ptn_orders', 'id=eq.' + txn.order_id + '&select=total,counter_total,counter_status');
          const order = orders && orders[0];
          const amt = order && order.counter_status === 'accepted' ? order.counter_total : order && order.total;
          await supaRequest('PATCH', 'ptn_orders', 'id=eq.' + txn.order_id, { payment_status: 'paid', campay_status: 'successful', campay_operator: operator || null, campay_paid_at: new Date().toISOString(), escrow_held: amt, status: 'confirmed' });
        }
        await supaRequest('PATCH', 'ptn_campay_transactions', 'reference=eq.' + encodeURIComponent(reference), { status: 'successful', operator: operator || null, updated_at: new Date().toISOString() });
        await audit('campay_webhook_success', { reference, order_id: txn.order_id || null, amount: expectedAmt });
        return sendJson(200, { received: true, verified: true });
      } catch (e) {
        console.error('[campay-webhook] error:', e.message);
        await audit('campay_webhook_mismatch', { reference, reason: 'exception', message: e.message });
        return sendJson(200, { received: true, error: 'processing_error' });
      }
    });
    return;
  }


  // ── CAMPAY AUTO-RELEASE (triggered by buyer confirming delivery) ──
  if (req.url === '/campay/auto-release' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { order_id } = JSON.parse(body);
        if (!order_id) {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          return res.end(JSON.stringify({ success: false, message: 'order_id required' }));
        }

        // Get order details
        const orders = await supaRequest('GET', 'ptn_orders',
          'id=eq.' + order_id + '&select=*');
        const order = orders && orders[0];

        if (!order) {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          return res.end(JSON.stringify({ success: false, message: 'Order not found' }));
        }

        if (order.escrow_released) {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          return res.end(JSON.stringify({ success: false, message: 'Already released' }));
        }

        if (!order.escrow_held || order.payment_status !== 'paid') {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          return res.end(JSON.stringify({ success: false, message: 'No escrow to release' }));
        }

        // FLW-COLLECT: a Flutterwave-collected order is NOT paid out via the
        // Campay XAF rail (wrong provider/currency). Mark it delivered, keep
        // escrow_released=false, and QUEUE it for MANUAL payout (Peter records
        // the out-of-band payment via /flw/mark-paid-out). Automated FLW
        // Transfers payout is the next slice.
        if (order.payment_method === 'flutterwave') {
          await supaRequest('PATCH', 'ptn_orders', 'id=eq.' + order_id, { status: 'delivered', delivery_confirmed_at: new Date().toISOString(), updated_at: new Date().toISOString() });
          await supaRequest('POST', 'ptn_audit_log', null, { action: 'flw_payout_queued_manual', target_type: 'ptn_orders', target_id: order_id, details: { order_ref: order.order_ref, amount: order.escrow_held } }).catch(() => {});
          await supaRequest('POST', 'ptn_notifications', null, { user_id: order.seller_id, type: 'order', order_id: order_id, title_en: 'Delivery Confirmed', title_fr: 'Livraison confirmée', body_en: 'Buyer confirmed delivery of ' + order.order_ref + '. Your payout is being processed.', body_fr: "L'acheteur a confirmé la livraison de " + order.order_ref + '. Votre paiement est en cours.', read: false }).catch(() => {});
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          return res.end(JSON.stringify({ success: true, manual: true, message: 'Delivery confirmed; payout queued for manual processing' }));
        }

        // Get seller phone — MOMO-PHONE-CAPTURE: prefer the seller's
        // dedicated Mobile Money number, fall back to their login phone.
        const sellers = await supaRequestPrivileged('GET', 'ptn_users',
          'id=eq.' + order.seller_id + '&select=id,phone,momo_phone,name');
        const seller = sellers && sellers[0];
        const payoutPhone = seller && (seller.momo_phone || seller.phone);

        if (!seller || !payoutPhone) {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          return res.end(JSON.stringify({ success: false, message: 'Seller phone not found' }));
        }
        await supaRequest('POST', 'ptn_audit_log', null, {
          action: 'campay_payout_target', target_type: 'ptn_users', target_id: order.seller_id,
          details: { endpoint: '/campay/auto-release', order_ref: order.order_ref, payout_phone: payoutPhone, source: seller.momo_phone ? 'momo_phone' : 'phone' }
        }).catch(e => console.warn('[payout audit] ' + e.message));

        const ref = 'AUTOPAY-' + order.order_ref + '-' + Date.now();
        const cleanPhone = String(payoutPhone).replace(/\s/g, '').replace(/^\+/, '');

        // Payout via Campay
        const token = await getCampayToken();
        const pr = await fetch(CAMPAY_BASE_URL + '/transfer/', {
          method: 'POST',
          headers: { 'Authorization': 'Token ' + token, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            amount: String(order.escrow_held),
            currency: 'XAF',
            to: cleanPhone,
            description: 'Paiement PARTENAIRE ' + order.order_ref,
            external_reference: ref
          })
        });
        const result = await pr.json();

        if (result.reference || result.status === 'SUCCESSFUL') {
          // Update order
          await supaRequest('PATCH', 'ptn_orders', 'id=eq.' + order_id, {
            escrow_released: true,
            campay_payout_ref: ref,
            campay_payout_at: new Date().toISOString(),
            status: 'delivered',
            updated_at: new Date().toISOString()
          });

          // Notify seller
          await supaRequest('POST', 'ptn_notifications', null, {
            user_id: order.seller_id,
            type: 'payment',
            order_id: order_id,
            title_en: 'Payment Received!',
            title_fr: 'Paiement recu!',
            body_en: order.escrow_held + ' FCFA sent to your account for order ' + order.order_ref,
            body_fr: order.escrow_held + ' FCFA envoye sur votre compte pour ' + order.order_ref,
            read: false
          });

          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({ success: true, amount: order.escrow_held, reference: ref }));
        } else {
          console.error('Auto-release payout failed:', result);
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({ success: false, message: 'Payout failed', details: result }));
        }
      } catch(e) {
        console.error('Auto-release error:', e.message);
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ success: false, message: e.message }));
      }
    });
    return;
  }


  // ── CAMPAY DIRECT PAYOUT (admin only) ────────────────────────
  if (req.url === '/campay/payout' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { phone, amount, description, admin_pin } = JSON.parse(body);
        if (!process.env.ADMIN_PIN || admin_pin !== process.env.ADMIN_PIN) {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          return res.end(JSON.stringify({ success: false, message: 'Non autorise' }));
        }
        const token = await getCampayToken();
        const cleanPhone = String(phone).replace(/\s/g, '').replace(/^\+/, '');
        const ref = 'PAYOUT-DIRECT-' + Date.now();
        const r = await fetch(CAMPAY_BASE_URL + '/transfer/', {
          method: 'POST',
          headers: { 'Authorization': 'Token ' + token, 'Content-Type': 'application/json' },
          body: JSON.stringify({ amount: String(amount), currency: 'XAF', to: cleanPhone, description: description || 'PARTENAIRE payout', external_reference: ref })
        });
        const result = await r.json();
        console.log('Direct payout result:', result);
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ success: !!(result.reference || result.status === 'SUCCESSFUL'), result, reference: ref }));
      } catch(e) {
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ success: false, message: e.message }));
      }
    });
    return;
  }


  // ── MP ADMIN BRIDGE (proxy to Mon Partenaire API) ─────────────
  if (req.url.startsWith('/mp-admin/')) {
    const mpPath = req.url.replace('/mp-admin/', '/api/subscriptions/svc/');
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      const mpUrl = new URL(process.env.MP_API_URL || 'https://partenaire-account-api.onrender.com');
      const options = {
        hostname: mpUrl.hostname,
        path: mpPath,
        method: req.method,
        headers: {
          'Content-Type': 'application/json',
          'x-service-key': process.env.DOZIE_SERVICE_KEY || ''
        }
      };
      if (body) options.headers['Content-Length'] = Buffer.byteLength(body);
      const pr = https.request(options, r => {
        res.writeHead(r.statusCode, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        r.pipe(res);
      });
      pr.on('error', e => { res.writeHead(502); res.end(JSON.stringify({ success: false, error: e.message })); });
      if (body) pr.write(body);
      pr.end();
    });
    return;
  }

  // ── CAMPAY SIMULATE (sandbox testing only) ───────────────────
  if (req.url === '/campay/simulate' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', async () => {
      try {
        const { reference, order_id } = JSON.parse(body);
        if (!reference) {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          return res.end(JSON.stringify({ success: false, message: 'Reference required' }));
        }

        // Mark transaction as successful
        await supaRequest('PATCH', 'ptn_campay_transactions', 
          'reference=eq.' + reference,
          { status: 'successful', updated_at: new Date().toISOString() });

        // Update order if order_id provided
        if (order_id) {
          const orders = await supaRequest('GET', 'ptn_orders',
            'id=eq.' + order_id + '&select=total,counter_total,counter_status,seller_id,order_ref');
          const order = orders && orders[0];
          const amt = order && order.counter_status === 'accepted' 
            ? order.counter_total : order && order.total;

          await supaRequest('PATCH', 'ptn_orders', 'id=eq.' + order_id, {
            payment_status: 'paid',
            campay_status: 'successful',
            campay_reference: reference,
            campay_paid_at: new Date().toISOString(),
            escrow_held: amt,
            status: 'confirmed',
            updated_at: new Date().toISOString()
          });

          // Notify seller
          if (order) {
            await supaRequest('POST', 'ptn_notifications', null, {
              user_id: order.seller_id,
              type: 'payment',
              order_id: order_id,
              title_en: 'Payment Received!',
              title_fr: 'Paiement recu!',
              body_en: 'Order ' + order.order_ref + ' paid. Funds in escrow.',
              body_fr: 'Commande ' + order.order_ref + ' payee. Fonds en escrow.',
              read: false
            });
          }
        }

        console.log('[SANDBOX] Simulated payment success for', reference, 'order:', order_id);
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ success: true, message: 'Payment simulated successfully' }));
      } catch(e) {
        console.error('Simulate error:', e.message);
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ success: false, message: e.message }));
      }
    });
    return;
  }

  // DOZIE-UNIFIED-ENTRY: `/` auto-router. Tiny shell that decodes the
  // JWT in localStorage and replaces itself with /seller, /buyer, or
  // /login. Network-first SW caches this page so cold launch in the
  // Capacitor wrap is one round trip + an in-browser redirect.
  // No DB calls; the JWT's `role` claim is the source of truth — same
  // claim the buyer/seller portals already trust on hard refresh.
  if ((req.url === '/' || req.url.split('?')[0] === '/') && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache',
      'Access-Control-Allow-Origin': '*',
    });
    res.end(
      '<!DOCTYPE html><html lang="fr"><head>' +
      '<meta charset="utf-8">' +
      '<meta name="viewport" content="width=device-width,initial-scale=1">' +
      '<title>PARTENAIRE Dozie</title>' +
      '<meta name="theme-color" content="#1A2B4A">' +
      '<link rel="icon" href="/icon.svg" type="image/svg+xml">' +
      '<style>html,body{margin:0;height:100%;background:#1A2B4A;color:#fff;' +
      'font-family:system-ui,sans-serif;display:flex;align-items:center;' +
      'justify-content:center}.l{text-align:center;opacity:.75;font-size:14px}</style>' +
      '</head><body>' +
      '<div class="l">PARTENAIRE Dozie…</div>' +
      '<script>(function(){try{var t=localStorage.getItem("dozie_jwt");' +
      'if(t){var p=JSON.parse(atob(t.split(".")[1].replace(/-/g,"+").replace(/_/g,"/")));' +
      'if(p&&p.uid&&(!p.exp||Date.now()/1000<p.exp)){' +
      'if(p.role==="seller"){location.replace("/seller");return;}' +
      'if(p.role==="buyer"){location.replace("/buyer");return;}}}' +
      '}catch(_){}location.replace("/login");})();<\/script>' +
      '</body></html>'
    );
    return;
  }

  // SERVE LOCAL FILES â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  let url = req.url.split('?')[0];
  if (ROUTES[url]) url = '/' + ROUTES[url];
  const f = path.join(DIR, url.slice(1));
  fs.readFile(f, (e, d) => {
    if (e) { res.writeHead(404); res.end('Not found: ' + url); return; }
    const ext = path.extname(f);
    const headers = { 'Content-Type': MIME[ext] || 'text/plain', 'Access-Control-Allow-Origin': '*' };
    // ALWAYS-FRESH for app shells + the service worker so a deploy reaches
    // installed Capacitor wrappers immediately — no stale WebView HTTP cache.
    // The SW itself is network-first for navigations, so revalidated HTML is
    // served fresh when online; assets stay cacheable (SW caches them).
    if (ext === '.html' || url === '/sw.js' || url === '/manifest.json') {
      headers['Cache-Control'] = 'no-cache, must-revalidate';
    }
    res.writeHead(200, headers);
    res.end(d);
  });

}).listen(PORT, () => {
  console.log('');
  console.log('â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”');
  console.log('â”‚   PARTENAIRE âœ¦ Server + Campay Ready          â”‚');
  console.log('â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤');
  console.log('â”‚  Admin:   RETIRED → mon-partenaire-app/admin â”‚');
  console.log('â”‚  Seller:  http://localhost:8080/seller        â”‚');
  console.log('â”‚  Buyer:   http://localhost:8080/buyer         â”‚');
  console.log('â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤');
  console.log('â”‚  PIN login:   POST /auth/pin-login            â”‚');
  console.log('â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜');
  console.log('');
});
