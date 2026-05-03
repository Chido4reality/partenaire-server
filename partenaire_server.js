require('dotenv').config();

// â”€â”€â”€ CAMPAY CONFIGURATION â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const CAMPAY_BASE_URL = process.env.CAMPAY_ENV === 'production'
  ? 'https://campay.net/api'
  : 'https://demo.campay.net/api';

let campayToken = null;
let campayTokenExpiry = null;

async function getCampayToken() {
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

// â”€â”€ BACKDOOR CONFIG (for testing) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const BACKDOOR_PHONE = '675995524';
const BACKDOOR_EMAIL = 'chido4reality@yahoo.com';
const BACKDOOR_CODE  = '2468';

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
  // â”€â”€ BACKDOOR: always let the test account through â”€â”€
  const cleanPhone = phone ? phone.replace(/^\+237/, '') : '';
  const isBackdoorPhone = cleanPhone === BACKDOOR_PHONE || phone === '+237' + BACKDOOR_PHONE;
  const isBackdoorEmail = email && email.toLowerCase() === BACKDOOR_EMAIL.toLowerCase();
  if ((isBackdoorPhone || isBackdoorEmail) && code === BACKDOOR_CODE) {
    console.log('[OTP] Backdoor access granted for', phone || email);
    return { ok: true, backdoor: true };
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
      const sellerId = paymentRef.replace('SUB-', '').split('-')[0];
      const subs = await supaRequest('GET', 'ptn_subscriptions', 'seller_id=eq.' + sellerId + '&select=*');
      if (subs && subs[0]) {
        const sub = subs[0];
        const nextDue = new Date();
        nextDue.setDate(nextDue.getDate() + 30);
        await supaRequest('PATCH', 'ptn_subscriptions', 'seller_id=eq.' + sellerId, {
          status: 'active',
          last_paid_date: new Date().toISOString().split('T')[0],
          next_due_date: nextDue.toISOString().split('T')[0],
          payment_alert: false,
          updated_at: new Date().toISOString()
        });
        await supaRequest('POST', 'ptn_sub_payments', null, {
          subscription_id: sub.id,
          seller_id: sellerId,
          amount,
          method: operator,
          payment_ref: paymentRef,
          paid_at: new Date().toISOString(),
          notes: 'Paid via Monetbil MoMo'
        });
        await supaRequest('PATCH', 'ptn_users', 'id=eq.' + sellerId, { status: 'active' });
        await supaRequest('POST', 'ptn_notifications', null, {
          user_id: sellerId,
          type: 'payment',
          title_en: 'âœ… Subscription Renewed!',
          title_fr: 'âœ… Abonnement renouvelÃ©!',
          body_en: `Payment of ${amount.toLocaleString()} XAF confirmed. Your shop is active until ${nextDue.toDateString()}.`,
          body_fr: `Paiement de ${amount.toLocaleString()} XAF confirmÃ©. Votre boutique est active jusqu'au ${nextDue.toLocaleDateString('fr-FR')}.`,
          read: false
        });
        console.log('[Monetbil] Subscription renewed for seller', sellerId);
      }
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

  // â”€â”€ SEND OTP â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (req.url === '/otp/send' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', async () => {
      try {
        const { phone } = JSON.parse(body);
        if (!phone) throw new Error('Phone required');
        // Skip sending SMS for backdoor number
        const cleanPhone = phone.replace(/^\+237/, '');
        if (cleanPhone === BACKDOOR_PHONE) {
          res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
          res.end(JSON.stringify({ success: true, message: 'OTP sent' }));
          return;
        }
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
        const { phone, code, email } = JSON.parse(body);
        const result = verifyOTP(phone, code, email);
        res.writeHead(result.ok ? 200 : 400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify(result));
      } catch(e) {
        res.writeHead(500, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        res.end(JSON.stringify({ success: false, error: e.message }));
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

  // â”€â”€ SUPABASE API PROXY â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  if (req.url.startsWith('/api/')) {
    const supaPath = '/rest/v1/' + req.url.slice(5);
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
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

  // â”€â”€ SERVE LOCAL FILES â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  let url = req.url.split('?')[0];
  if (ROUTES[url]) url = '/' + ROUTES[url];
  const f = path.join(DIR, url.slice(1));
  fs.readFile(f, (e, d) => {
    if (e) { res.writeHead(404); res.end('Not found: ' + url); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'text/plain' });
    res.end(d);
  });




// ── CAMPAY PAYMENT INTEGRATION ───────────────────────────────
const CAMPAY_BASE = process.env.CAMPAY_ENV === 'production'
  ? 'https://campay.net/api'
  : 'https://demo.campay.net/api';

let _cToken = null, _cExp = null;

async function getCT() {
  if (_cToken && _cExp && Date.now() < _cExp) return _cToken;
  const r = await fetch(CAMPAY_BASE + '/token/', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: process.env.CAMPAY_USERNAME, password: process.env.CAMPAY_PASSWORD })
  });
  const d = await r.json();
  if (!d.token) throw new Error('Campay auth failed');
  _cToken = d.token; _cExp = Date.now() + 55 * 60 * 1000;
  return _cToken;
}

server.post('/campay/pay', async (req, res) => {
  const { order_id, phone, amount, type } = req.body;
  if (!phone || !amount) return res.end(JSON.stringify({ success: false, message: 'Phone and amount required' }));
  try {
    const ref = 'PAY-' + Date.now() + '-' + Math.random().toString(36).substr(2,6).toUpperCase();
    const token = await getCT();
    const cleanPhone = String(phone).replace(/\s/g,'').replace(/^\+/,'');
    const r = await fetch(CAMPAY_BASE + '/collect/', {
      method: 'POST', headers: { 'Authorization': 'Token ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount: String(amount), currency: 'XAF', from: cleanPhone, description: 'Paiement PARTENAIRE', external_reference: ref })
    });
    const result = await r.json();
    await supabase.from('ptn_campay_transactions').insert({ reference: ref, order_id: order_id || null, transaction_type: type || 'payment', amount, payer_phone: phone, status: 'pending' });
    if (result.reference || result.ussd_code) {
      if (order_id) await supabase.from('ptn_orders').update({ campay_reference: ref, campay_status: 'pending', payer_phone: phone }).eq('id', order_id);
      res.end(JSON.stringify({ success: true, reference: ref, ussd_code: result.ussd_code, operator: result.operator }));
    } else {
      res.end(JSON.stringify({ success: false, message: result.message || 'Paiement echoue', details: result }));
    }
  } catch (err) { res.end(JSON.stringify({ success: false, message: err.message })); }
});

server.post('/campay/check', async (req, res) => {
  const { reference, order_id } = req.body;
  if (!reference) return res.end(JSON.stringify({ success: false, message: 'Reference required' }));
  try {
    const token = await getCT();
    const r = await fetch(CAMPAY_BASE + '/transaction/' + reference + '/', { headers: { 'Authorization': 'Token ' + token } });
    const result = await r.json();
    const isPaid = result.status === 'SUCCESSFUL';
    await supabase.from('ptn_campay_transactions').update({ status: isPaid ? 'successful' : (result.status || 'pending').toLowerCase(), updated_at: new Date().toISOString() }).eq('reference', reference);
    if (isPaid && order_id) {
      const { data: order } = await supabase.from('ptn_orders').select('total,counter_total,counter_status,seller_id,order_ref').eq('id', order_id).single();
      const amt = order && order.counter_status === 'accepted' ? order.counter_total : order && order.total;
      await supabase.from('ptn_orders').update({ payment_status: 'paid', campay_status: 'successful', campay_paid_at: new Date().toISOString(), escrow_held: amt, status: 'confirmed' }).eq('id', order_id);
      if (order) await supabase.from('ptn_notifications').insert({ user_id: order.seller_id, type: 'payment', title_en: 'Payment Received', title_fr: 'Paiement recu', body_en: 'Order ' + order.order_ref + ' paid. Funds in escrow.', body_fr: 'Commande ' + order.order_ref + ' payee.', order_id });
    }
    res.end(JSON.stringify({ success: true, paid: isPaid, status: result.status }));
  } catch (err) { res.end(JSON.stringify({ success: false, message: err.message })); }
});

server.post('/campay/release', async (req, res) => {
  const { order_id, admin_pin } = req.body;
  if (admin_pin !== (process.env.ADMIN_PIN || '2468')) return res.end(JSON.stringify({ success: false, message: 'Non autorise' }));
  try {
    const { data: order } = await supabase.from('ptn_orders').select('*,seller:seller_id(phone,name)').eq('id', order_id).single();
    if (!order || order.escrow_released) return res.end(JSON.stringify({ success: false, message: 'Invalid order' }));
    const ref = 'PAYOUT-' + order.order_ref + '-' + Date.now();
    const token = await getCT();
    const cleanPhone = String(order.seller && order.seller.phone || '').replace(/\s/g,'').replace(/^\+/,'');
    const r = await fetch(CAMPAY_BASE + '/transfer/', {
      method: 'POST', headers: { 'Authorization': 'Token ' + token, 'Content-Type': 'application/json' },
      body: JSON.stringify({ amount: String(order.escrow_held), currency: 'XAF', to: cleanPhone, description: 'Paiement PARTENAIRE ' + order.order_ref, external_reference: ref })
    });
    const result = await r.json();
    if (result.reference || result.status === 'SUCCESSFUL') {
      await supabase.from('ptn_orders').update({ escrow_released: true, campay_payout_ref: ref, campay_payout_at: new Date().toISOString(), status: 'delivered' }).eq('id', order_id);
      res.end(JSON.stringify({ success: true, amount: order.escrow_held, reference: ref }));
    } else {
      res.end(JSON.stringify({ success: false, message: 'Virement echoue', details: result }));
    }
  } catch (err) { res.end(JSON.stringify({ success: false, message: err.message })); }
});

server.post('/campay/webhook', async (req, res) => {
  const { reference, status, operator } = req.body;
  if (status === 'SUCCESSFUL' && reference) {
    const { data: txn } = await supabase.from('ptn_campay_transactions').select('*').eq('reference', reference).single();
    if (txn && txn.order_id) {
      const { data: order } = await supabase.from('ptn_orders').select('total,counter_total,counter_status').eq('id', txn.order_id).single();
      const amt = order && order.counter_status === 'accepted' ? order.counter_total : order && order.total;
      await supabase.from('ptn_orders').update({ payment_status: 'paid', campay_status: 'successful', campay_operator: operator, campay_paid_at: new Date().toISOString(), escrow_held: amt, status: 'confirmed' }).eq('id', txn.order_id);
    }
    await supabase.from('ptn_campay_transactions').update({ status: 'successful', operator, updated_at: new Date().toISOString() }).eq('reference', reference);
  }
  res.end(JSON.stringify({ received: true }));
});

}).listen(PORT, () => {
  console.log('');
  console.log('â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”');
  console.log('â”‚   PARTENAIRE âœ¦ Server + OTP + Monetbil Ready â”‚');
  console.log('â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤');
  console.log('â”‚  Admin:   http://localhost:8080/admin         â”‚');
  console.log('â”‚  Seller:  http://localhost:8080/seller        â”‚');
  console.log('â”‚  Buyer:   http://localhost:8080/buyer         â”‚');
  console.log('â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤');
  console.log('â”‚  OTP send:    POST /otp/send                  â”‚');
  console.log('â”‚  OTP verify:  POST /otp/verify                â”‚');
  console.log('â”‚  Backdoor:    675995524 / code 2468           â”‚');
  console.log('â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜');
  console.log('');
});
