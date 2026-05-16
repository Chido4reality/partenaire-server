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
// Dual-auth during the grace period: prefer a valid JWT; fall back to
// the legacy x-dozie-{seller,buyer}-id header (with a console.warn so
// stale frontends are visible). The header fallback MUST be removed
// in a follow-up commit once Peter confirms the JWT flow.
function resolveDozieIdentity(req, role) {
  const j = readDozieJwt(req);
  if (j) {
    if (role && j.role !== role) return { error: 'role' };
    return { uid: j.uid, role: j.role, via: 'jwt' };
  }
  const legacy = role === 'buyer'
    ? req.headers['x-dozie-buyer-id']
    : req.headers['x-dozie-seller-id'];
  if (legacy) {
    console.warn('legacy header auth used for', req.url, '— frontend likely stale');
    return { uid: legacy, role, via: 'legacy-header' };
  }
  return { error: 'auth_required' };
}

// â”€â”€â”€ CAMPAY CONFIGURATION â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const CAMPAY_BASE_URL = process.env.CAMPAY_ENV === 'production'
  ? 'https://campay.net/api'
  : 'https://demo.campay.net/api';

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
const AfricasTalking = require('africastalking');

const AT  = AfricasTalking({ apiKey: process.env.AT_API_KEY, username: process.env.AT_USERNAME });
const SMS = AT.SMS;

const SUPA = 'ftxttdagpioieyzaijdc.supabase.co';
const KEY  = process.env.SUPABASE_KEY;
const PORT = 8080;
const DIR=__dirname;

// â”€â”€ MONETBIL CONFIG â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Replace with real keys when going live
const MONETBIL_SERVICE_KEY    = 'test_service_key_partenaire';
const MONETBIL_SERVICE_SECRET = 'test_service_secret_partenaire';
const MONETBIL_API = 'https://api.monetbil.com';

const MIME = { '.html':'text/html', '.js':'text/javascript', '.css':'text/css', '.png':'image/png', '.jpg':'image/jpeg' };

const ROUTES = {
  '/':       'PARTENAIRE_Admin.html',
  '/admin':  'PARTENAIRE_Admin.html',
  '/seller': 'PARTENAIRE_Seller.html',
  '/buyer':  'PARTENAIRE_Buyer.html',
};

// M-1.3: the old hardcoded OTP test backdoor has been removed.
// A dev-only bypass is available ONLY when both NODE_ENV=development
// AND ALLOW_DEV_OTP_BYPASS=1 are set (never in production); it
// accepts the literal code "000000" for any number.
const DEV_OTP_BYPASS =
  process.env.NODE_ENV === 'development' && process.env.ALLOW_DEV_OTP_BYPASS === '1';

// â”€â”€ OTP STORE (in-memory) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const otpStore = {}; // { phone: { code, expiresAt } }

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTP(phone) {
  const code = generateOTP();
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes
  otpStore[phone] = { code, expiresAt };
  await SMS.send({
    to: [phone.startsWith('+') ? phone : '+' + phone],
    message: `Your PARTENAIRE verification code is: ${code}. Valid for 5 minutes.`,
    from: 'PARTENAIRE'
  });
  console.log(`[OTP] Sent to ${phone}: ${code}`);
  return true;
}

function verifyOTP(phone, code, email) {
  // Dev-only bypass — gated behind NODE_ENV=development AND
  // ALLOW_DEV_OTP_BYPASS=1. Never active in production. No hardcoded
  // phone/code constants.
  if (DEV_OTP_BYPASS && code === '000000') {
    console.warn('[OTP] DEV bypass used (NODE_ENV=development, ALLOW_DEV_OTP_BYPASS=1)');
    return { ok: true, dev_bypass: true };
  }

  // â”€â”€ Normal OTP verification â”€â”€
  const entry = otpStore[phone];
  if (!entry) return { ok: false, reason: 'No OTP requested for this number' };
  if (Date.now() > entry.expiresAt) {
    delete otpStore[phone];
    return { ok: false, reason: 'OTP expired' };
  }
  if (entry.code !== code) return { ok: false, reason: 'Invalid OTP' };
  delete otpStore[phone];
  return { ok: true };
}

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

// â”€â”€ MONETBIL PAYMENT INITIATOR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
function initiateMonetbilPayment(amount, phone, paymentRef, returnUrl) {
  return new Promise((resolve, reject) => {
    const params = new URLSearchParams({
      service_key: MONETBIL_SERVICE_KEY,
      amount: amount.toString(),
      phone: '+237' + phone.replace(/^\+237/, ''),
      item_ref: paymentRef,
      payment_ref: paymentRef,
      return_url: returnUrl || 'http://localhost:8080/payment-success',
      notify_url: 'http://localhost:8080/monetbil/notify',
      locale: 'fr',
      country: 'CM',
      currency: 'XAF'
    });
    const reqBody = params.toString();
    const options = {
      hostname: 'api.monetbil.com',
      path: '/payment/v1/placePayment',
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(reqBody)
      }
    };
    const req = https.request(options, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch(e) { resolve({ error: data }); }
      });
    });
    req.on('error', reject);
    req.write(reqBody);
    req.end();
  });
}

// â”€â”€ WEBHOOK HANDLER: Monetbil notifies us of payment result â”€â”€
async function handleMonetbilNotify(body) {
  try {
    const params = new URLSearchParams(body);
    const status     = params.get('status');
    const paymentRef = params.get('payment_ref');
    const amount     = parseFloat(params.get('amount') || '0');
    const phone      = params.get('phone') || '';
    const operator   = params.get('operator') || '';

    console.log(`[Monetbil] Payment ${paymentRef}: ${status} â€” ${amount} XAF from ${phone} via ${operator}`);

    if (status !== 'SUCCESS') {
      console.log('[Monetbil] Payment failed or pending:', status);
      return;
    }

    if (paymentRef.startsWith('ORD-') || paymentRef.startsWith('QOF-')) {
      const orders = await supaRequest('GET', 'ptn_orders', 'order_ref=eq.' + paymentRef + '&select=*');
      if (orders && orders[0]) {
        const order = orders[0];
        await supaRequest('PATCH', 'ptn_orders', 'order_ref=eq.' + paymentRef, {
          escrow_held: amount,
          status: 'confirmed',
          updated_at: new Date().toISOString()
        });
        await supaRequest('POST', 'ptn_notifications', null, {
          user_id: order.seller_id,
          type: 'payment',
          title_en: 'ðŸ’° Payment Received!',
          title_fr: 'ðŸ’° Paiement reÃ§u!',
          body_en: `Payment of ${amount.toLocaleString()} XAF confirmed for order ${paymentRef} via ${operator}`,
          body_fr: `Paiement de ${amount.toLocaleString()} XAF confirmÃ© pour la commande ${paymentRef} via ${operator}`,
          read: false
        });
        await supaRequest('POST', 'ptn_notifications', null, {
          user_id: order.buyer_id,
          type: 'payment',
          title_en: 'âœ… Payment Confirmed',
          title_fr: 'âœ… Paiement confirmÃ©',
          body_en: `Your payment of ${amount.toLocaleString()} XAF for order ${paymentRef} was received.`,
          body_fr: `Votre paiement de ${amount.toLocaleString()} XAF pour la commande ${paymentRef} a Ã©tÃ© reÃ§u.`,
          read: false
        });
        console.log('[Monetbil] Order', paymentRef, 'confirmed');
      }

    } else if (paymentRef.startsWith('SUB-')) {
      // Sprint B-bis: legacy badge-subscription renewal via Monetbil.
      // The badge model (ptn_subscriptions table) was archived to
      // ptn_subscriptions_legacy_archive_2026_05 and replaced by the
      // CamPay-driven standalone flow (DZSUB- prefix → /api/dozie-sub
      // on the MP backend). Webhook ignores SUB-* refs now; any
      // straggler payment would be visible in Monetbil's dashboard
      // for manual reconciliation.
      console.log('[Monetbil] Ignoring legacy SUB- ref (badge model retired in Sprint B-bis):', paymentRef);
    }
  } catch(e) {
    console.error('[Monetbil] Webhook error:', e.message);
  }
}

// â”€â”€ SIMULATE PAYMENT SUCCESS (sandbox/demo mode) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function simulatePaymentSuccess(paymentRef, amount, phone) {
  console.log('[SANDBOX] Simulating payment success for', paymentRef);
  const fakeBody = new URLSearchParams({
    status: 'SUCCESS',
    payment_ref: paymentRef,
    amount: amount.toString(),
    phone: phone,
    operator: 'MTN_MOMO_CM'
  }).toString();
  await handleMonetbilNotify(fakeBody);
}

// â”€â”€ HTTP SERVER â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,apikey,Prefer,Accept');
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  // ── PHASE E — LEGACY ADMIN RETIRED ──────────────────────────────────
  // The real admin is mon-partenaire-app.vercel.app/admin.html (served
  // by the MP frontend, talking to the MP backend /api/admin/*). This
  // Dozie server's old PIN page (PARTENAIRE_Admin.html, still in git
  // history, just no longer served) and any /admin/* | /api/admin/*
  // API surface here are gone.
  //   • GET /admin            → 301 to the new portal
  //   • /admin/* | /api/admin* → 410 Gone (discoverable for API callers)
  // NOT touched: /mp-admin/* (MP svc proxy), /api/auth/impersonate-*
  // (used by the real admin), /campay/* (financial, separate concern).
  {
    const NEW_ADMIN = 'https://mon-partenaire-app.vercel.app/admin.html';
    const p = req.url.split('?')[0].replace(/\/+$/, '') || '/';
    if (p === '/admin') {
      res.writeHead(301, { Location: NEW_ADMIN });
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

  // â”€â”€ SEND OTP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (req.url === '/otp/send' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const { phone } = JSON.parse(body);
        if (!phone) throw new Error('Phone required');
        await sendOTP(phone);
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ success: true, message: 'OTP sent' }));
      } catch(e) {
        res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ success: false, error: e.message }));
      }
    });
    return;
  }

  // â”€â”€ VERIFY OTP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (req.url === '/otp/verify' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const { phone, code, email, role } = JSON.parse(body);
        const result = verifyOTP(phone, code, email);
        if (!result.ok) {
          res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({ ok: false, code: 'invalid_otp', reason: result.reason || 'Invalid OTP' }));
          return;
        }
        // M-1.2: issue a Dozie JWT bound to the verified user so the
        // frontend can drop header-trust. Look the user up by phone
        // (role disambiguates buyer vs seller when both exist).
        let jwtToken = null, uid = null, urole = role || null;
        try {
          const clean = String(phone || '').replace(/^\+?237/, '').replace(/\D/g, '');
          let q = 'phone=eq.' + encodeURIComponent(clean) + '&select=id,role&limit=1';
          if (role === 'buyer' || role === 'seller') q += '&role=eq.' + role;
          const rows = await supaRequest('GET', 'ptn_users', q);
          const u = Array.isArray(rows) && rows[0];
          if (u) {
            uid = u.id; urole = u.role || urole;
            if (DOZIE_JWT_SECRET) jwtToken = issueDozieJwt(u.id, urole);
          }
        } catch (_) { /* JWT is best-effort; legacy header still works during grace */ }
        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ ...result, jwt: jwtToken, uid, role: urole }));
      } catch(e) {
        res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ success: false, error: e.message }));
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

  // â”€â”€ MONETBIL WEBHOOK â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (req.url === '/monetbil/notify' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      await handleMonetbilNotify(body);
      res.writeHead(200);
      res.end('OK');
    });
    return;
  }

  // â”€â”€ INITIATE PAYMENT â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (req.url === '/monetbil/pay' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const data = JSON.parse(body);
        const { amount, phone, paymentRef, type, sandbox } = data;
        if (sandbox) {
          setTimeout(() => simulatePaymentSuccess(paymentRef, amount, phone), 3000);
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({
            success: true, sandbox: true, payment_url: null,
            message: 'SANDBOX: Payment will be confirmed in 3 seconds',
            payment_ref: paymentRef
          }));
        } else {
          const result = await initiateMonetbilPayment(amount, phone, paymentRef);
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify(result));
        }
      } catch(e) {
        res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // â”€â”€ PAYMENT SUCCESS PAGE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (req.url.startsWith('/payment-success')) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html><html><head><meta charset="UTF-8">
      <style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#1A2B4A;color:#fff;text-align:center}
      .box{background:rgba(255,255,255,0.1);border-radius:20px;padding:40px;max-width:400px}
      .icon{font-size:64px;margin-bottom:16px}h1{font-size:24px;margin-bottom:8px}
      p{opacity:0.7;margin-bottom:24px}a{background:#C9A84C;color:#1A2B4A;padding:12px 24px;border-radius:10px;text-decoration:none;font-weight:700}</style>
    </head><body><div class="box">
      <div class="icon">âœ…</div><h1>Payment Successful!</h1>
      <p>Your payment has been confirmed. You can close this window.</p>
      <a href="http://localhost:8080/buyer">Back to PARTENAIRE</a>
    </div></body></html>`);
    return;
  }

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
            const bs = await supaRequest('GET', 'ptn_users',
              'id=in.(' + bids.join(',') + ')&select=id,name');
            (Array.isArray(bs) ? bs : []).forEach(b => { buyerMap[b.id] = b.name; });
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

          const sellerRows = await supaRequest('GET', 'ptn_users',
            'id=eq.' + encodeURIComponent(order.seller_id) + '&select=id,name,phone,linked_mp_org_id');
          const seller = Array.isArray(sellerRows) && sellerRows[0];
          if (!seller) return send(404, { success: false, message: 'Seller not found' });

          // Denormalise buyer for cashier display.
          let buyerName = null, buyerPhone = null;
          if (order.buyer_id) {
            const b = await supaRequest('GET', 'ptn_users',
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

  // â”€â”€ 
  // ── CAMPAY PAY ─────────────────────────────────────────────
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
        const sellers = await supaRequest('GET', 'ptn_users', 'id=eq.' + order.seller_id + '&select=phone,name');
        const sellerPhone = sellers && sellers[0] && sellers[0].phone || '';
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

  // ── CAMPAY WEBHOOK ──────────────────────────────────────────
  if (req.url === '/campay/webhook' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const { reference, status, operator } = JSON.parse(body);
        if (status === 'SUCCESSFUL' && reference) {
          const txns = await supaRequest('GET', 'ptn_campay_transactions', 'reference=eq.' + reference + '&select=*');
          const txn = txns && txns[0];
          if (txn && txn.order_id) {
            const orders = await supaRequest('GET', 'ptn_orders', 'id=eq.' + txn.order_id + '&select=total,counter_total,counter_status');
            const order = orders && orders[0];
            const amt = order && order.counter_status === 'accepted' ? order.counter_total : order && order.total;
            await supaRequest('PATCH', 'ptn_orders', 'id=eq.' + txn.order_id, { payment_status: 'paid', campay_status: 'successful', campay_operator: operator, campay_paid_at: new Date().toISOString(), escrow_held: amt, status: 'confirmed' });
          }
          await supaRequest('PATCH', 'ptn_campay_transactions', 'reference=eq.' + reference, { status: 'successful', operator, updated_at: new Date().toISOString() });
        }
      } catch(e) { console.error('Webhook error:', e.message); }
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      res.end(JSON.stringify({ received: true }));
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

        // Get seller phone
        const sellers = await supaRequest('GET', 'ptn_users',
          'id=eq.' + order.seller_id + '&select=phone,name');
        const seller = sellers && sellers[0];

        if (!seller || !seller.phone) {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          return res.end(JSON.stringify({ success: false, message: 'Seller phone not found' }));
        }

        const ref = 'AUTOPAY-' + order.order_ref + '-' + Date.now();
        const cleanPhone = String(seller.phone).replace(/\s/g, '').replace(/^\+/, '');

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
  console.log('â”‚   PARTENAIRE âœ¦ Server + OTP + Monetbil Ready â”‚');
  console.log('â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤');
  console.log('â”‚  Admin:   RETIRED → mon-partenaire-app/admin â”‚');
  console.log('â”‚  Seller:  http://localhost:8080/seller        â”‚');
  console.log('â”‚  Buyer:   http://localhost:8080/buyer         â”‚');
  console.log('â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤');
  console.log('â”‚  OTP send:    POST /otp/send                  â”‚');
  console.log('â”‚  OTP verify:  POST /otp/verify                â”‚');
  console.log('â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜');
  console.log('');
});
