require('dotenv').config();
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

// ── MONETBIL CONFIG ───────────────────────────────────────────
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

// ── BACKDOOR CONFIG (for testing) ────────────────────────────
const BACKDOOR_PHONE = '675995524';
const BACKDOOR_EMAIL = 'chido4reality@yahoo.com';
const BACKDOOR_CODE  = '2468';

// ── OTP STORE (in-memory) ────────────────────────────────────
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
  // ── BACKDOOR: always let the test account through ──
  const cleanPhone = phone ? phone.replace(/^\+237/, '') : '';
  const isBackdoorPhone = cleanPhone === BACKDOOR_PHONE || phone === '+237' + BACKDOOR_PHONE;
  const isBackdoorEmail = email && email.toLowerCase() === BACKDOOR_EMAIL.toLowerCase();
  if ((isBackdoorPhone || isBackdoorEmail) && code === BACKDOOR_CODE) {
    console.log('[OTP] Backdoor access granted for', phone || email);
    return { ok: true, backdoor: true };
  }

  // ── Normal OTP verification ──
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

// ── SUPABASE HELPER ───────────────────────────────────────────
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

// ── MONETBIL PAYMENT INITIATOR ────────────────────────────────
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

// ── WEBHOOK HANDLER: Monetbil notifies us of payment result ──
async function handleMonetbilNotify(body) {
  try {
    const params = new URLSearchParams(body);
    const status     = params.get('status');
    const paymentRef = params.get('payment_ref');
    const amount     = parseFloat(params.get('amount') || '0');
    const phone      = params.get('phone') || '';
    const operator   = params.get('operator') || '';

    console.log(`[Monetbil] Payment ${paymentRef}: ${status} — ${amount} XAF from ${phone} via ${operator}`);

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
          title_en: '💰 Payment Received!',
          title_fr: '💰 Paiement reçu!',
          body_en: `Payment of ${amount.toLocaleString()} XAF confirmed for order ${paymentRef} via ${operator}`,
          body_fr: `Paiement de ${amount.toLocaleString()} XAF confirmé pour la commande ${paymentRef} via ${operator}`,
          read: false
        });
        await supaRequest('POST', 'ptn_notifications', null, {
          user_id: order.buyer_id,
          type: 'payment',
          title_en: '✅ Payment Confirmed',
          title_fr: '✅ Paiement confirmé',
          body_en: `Your payment of ${amount.toLocaleString()} XAF for order ${paymentRef} was received.`,
          body_fr: `Votre paiement de ${amount.toLocaleString()} XAF pour la commande ${paymentRef} a été reçu.`,
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
          title_en: '✅ Subscription Renewed!',
          title_fr: '✅ Abonnement renouvelé!',
          body_en: `Payment of ${amount.toLocaleString()} XAF confirmed. Your shop is active until ${nextDue.toDateString()}.`,
          body_fr: `Paiement de ${amount.toLocaleString()} XAF confirmé. Votre boutique est active jusqu'au ${nextDue.toLocaleDateString('fr-FR')}.`,
          read: false
        });
        console.log('[Monetbil] Subscription renewed for seller', sellerId);
      }
    }
  } catch(e) {
    console.error('[Monetbil] Webhook error:', e.message);
  }
}

// ── SIMULATE PAYMENT SUCCESS (sandbox/demo mode) ──────────────
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

// ── HTTP SERVER ───────────────────────────────────────────────
http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,apikey,Prefer,Accept');
  if (req.method === 'OPTIONS') { res.writeHead(200); res.end(); return; }

  // ── SEND OTP ────────────────────────────────────────────────
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

  // ── VERIFY OTP ──────────────────────────────────────────────
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

  // ── MONETBIL WEBHOOK ────────────────────────────────────────
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

  // ── INITIATE PAYMENT ────────────────────────────────────────
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

  // ── PAYMENT SUCCESS PAGE ────────────────────────────────────
  if (req.url.startsWith('/payment-success')) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<!DOCTYPE html><html><head><meta charset="UTF-8">
      <style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#1A2B4A;color:#fff;text-align:center}
      .box{background:rgba(255,255,255,0.1);border-radius:20px;padding:40px;max-width:400px}
      .icon{font-size:64px;margin-bottom:16px}h1{font-size:24px;margin-bottom:8px}
      p{opacity:0.7;margin-bottom:24px}a{background:#C9A84C;color:#1A2B4A;padding:12px 24px;border-radius:10px;text-decoration:none;font-weight:700}</style>
    </head><body><div class="box">
      <div class="icon">✅</div><h1>Payment Successful!</h1>
      <p>Your payment has been confirmed. You can close this window.</p>
      <a href="http://localhost:8080/buyer">Back to PARTENAIRE</a>
    </div></body></html>`);
    return;
  }

  // ── SUPABASE API PROXY ──────────────────────────────────────
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

  // ── SERVE LOCAL FILES ───────────────────────────────────────
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
  console.log('┌──────────────────────────────────────────────┐');
  console.log('│   PARTENAIRE ✦ Server + OTP + Monetbil Ready │');
  console.log('├──────────────────────────────────────────────┤');
  console.log('│  Admin:   http://localhost:8080/admin         │');
  console.log('│  Seller:  http://localhost:8080/seller        │');
  console.log('│  Buyer:   http://localhost:8080/buyer         │');
  console.log('├──────────────────────────────────────────────┤');
  console.log('│  OTP send:    POST /otp/send                  │');
  console.log('│  OTP verify:  POST /otp/verify                │');
  console.log('│  Backdoor:    675995524 / code 2468           │');
  console.log('└──────────────────────────────────────────────┘');
  console.log('');
});