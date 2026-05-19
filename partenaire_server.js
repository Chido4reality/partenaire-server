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

// Fail loud, not silent-sandbox: in production, refuse to boot unless the
// Campay config is real. A crashed deploy is recoverable; silently
// running against demo.campay or with an unauthenticated webhook is not.
if (process.env.NODE_ENV === 'production') {
  const _fail = (m) => { console.error('CRITICAL: ' + m); process.exit(1); };
  if (process.env.CAMPAY_ENV !== 'production')
    _fail('CAMPAY_ENV must be "production" in a production deployment');
  if (!process.env.CAMPAY_TOKEN && !(process.env.CAMPAY_USERNAME && process.env.CAMPAY_PASSWORD))
    _fail('Campay credentials missing (set CAMPAY_TOKEN, or CAMPAY_USERNAME + CAMPAY_PASSWORD)');
  if (!CAMPAY_WEBHOOK_SECRET)
    _fail('CAMPAY_WEBHOOK_SECRET missing');
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

const SUPA = 'ftxttdagpioieyzaijdc.supabase.co';
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

const MIME = { '.html':'text/html', '.js':'text/javascript', '.css':'text/css', '.png':'image/png', '.jpg':'image/jpeg' };

const ROUTES = {
  '/':       'PARTENAIRE_Admin.html',
  '/admin':  'PARTENAIRE_Admin.html',
  '/seller': 'PARTENAIRE_Seller.html',
  '/buyer':  'PARTENAIRE_Buyer.html',
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
      is_sandbox: isDemo
    }));
    return;
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
  //   • GET / and GET /admin  → 302 to the new portal (302 not 301: keeps
  //     flexibility to revisit; root was still mapped to the legacy
  //     PARTENAIRE_Admin.html via ROUTES, so it must be covered too)
  //   • /admin/* | /api/admin* → 410 Gone (discoverable for API callers)
  // NOT touched: /mp-admin/* (MP svc proxy), /api/auth/impersonate-*
  // (used by the real admin), /campay/* (financial, separate concern).
  {
    const NEW_ADMIN = 'https://mon-partenaire-app.vercel.app/admin.html';
    const p = req.url.split('?')[0].replace(/\/+$/, '') || '/';
    if (p === '/' || p === '/admin') {
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
            status: user.status
          }
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

  // ── SUPABASE API PROXY ────────────────────────────────────────────────
  //
  // Phase D — MP-subscription gating for sellers. Before forwarding to
  // Supabase REST, we intercept three operations:
  //   • PATCH /api/ptn_orders?id=eq.<id>     when the patch "accepts" an order
  //   • POST  /api/ptn_products              new listing
  //   • PATCH /api/ptn_products?id=eq.<id>   listing update
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
            const sellerId = parsedBody && (parsedBody.seller_id || (Array.isArray(parsedBody) && parsedBody[0] && parsedBody[0].seller_id));
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
            const productId = extractIdFilter(req.url);
            if (productId) {
              const productRows = await supaRequest('GET', 'ptn_products',
                'id=eq.' + encodeURIComponent(productId) + '&select=seller_id');
              const sellerId = Array.isArray(productRows) && productRows[0] && productRows[0].seller_id;
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
        }
      } catch (gateErr) {
        // Gate failure → fail open. Better to let the action through than
        // to lock the seller out on a transient internal error. The MP
        // admin still sees the audit trail downstream.
        console.warn('[mp-gate] gate evaluation failed:', gateErr && gateErr.message);
      }

      // ── Forward to Supabase REST (existing behaviour) ────────────────
      const options = {
        hostname: SUPA, path: supaPath, method: req.method,
        headers: {
          apikey: KEY, 'Authorization': 'Bearer ' + KEY,
          'Content-Type': 'application/json',
          'Prefer': req.headers['prefer'] || 'return=representation'
        }
      };
      const pr = https.request(options, r => {
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

  // STAGE-1-DOZIE-ORDER-RPC: re-run payment for an existing order
  // (orphans + Campay retries). Replaces the unauthenticated /campay/pay
  // for the buyer flow. RPC verifies the caller owns the order.
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

  // â”€â”€
  // ── CAMPAY PAY ─────────────────────────────────────────────
  // TODO STAGE-2: legacy unauthenticated path kept functional until the
  // buyer flow fully cuts over; secured replacement is
  // /api/orders/:id/retry-payment above.
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

  // SERVE LOCAL FILES â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  let url = req.url.split('?')[0];
  if (ROUTES[url]) url = '/' + ROUTES[url];
  const f = path.join(DIR, url.slice(1));
  fs.readFile(f, (e, d) => {
    if (e) { res.writeHead(404); res.end('Not found: ' + url); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'text/plain' });
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
