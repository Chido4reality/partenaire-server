// Flutterwave v3 integration for Dozie — Standard Checkout (hosted page).
// CLONED from the MP backend's services/flutterwave.js (the proven, working
// collect integration) so the two can't drift. Dozie SLICE 0/1 = COLLECT leg
// only (createPayment + verifyTransaction). NO payout/Transfers here — Dozie
// seller payout is MANUAL this slice.
//
// TEST vs LIVE is decided purely by the key in FLW_SECRET_KEY (FLWSECK_TEST-…
// vs FLWSECK-…) — the base URL is identical, so swapping to live keys needs no
// code change. Reads the key from env at call time.

const FLW_BASE = 'https://api.flutterwave.com/v3';

function secretKey() {
  const k = process.env.FLW_SECRET_KEY;
  if (!k) throw new Error('FLW_SECRET_KEY not configured');
  return k;
}

function isTestKey() {
  return String(process.env.FLW_SECRET_KEY || '').startsWith('FLWSECK_TEST-');
}

// Create a Standard Checkout payment. Returns { link, raw }.
// payment_options: for NGN we OMIT the field so the hosted page shows every
// method enabled on the Flutterwave dashboard (card, bank transfer, USSD, and
// OPay if enabled). For XAF we pass the mobile-money set MP uses.
async function createPayment({ tx_ref, amount, currency, redirect_url, customer, meta, title, payment_options }) {
  const body = {
    tx_ref,
    amount,                 // numeric major units (XAF/NGN, no minor-unit handling)
    currency,               // 'XAF' | 'NGN'
    redirect_url,
    customer,               // { email, name, phonenumber }
    meta,                   // { order_id, order_ref, seller_id, buyer_id }
    customizations: { title: title || 'Partenaire Dozie order' },
  };
  // Only set payment_options when explicitly provided (XAF). Omitting it for
  // NGN lets the dashboard-enabled method list (incl. OPay) drive the page.
  if (payment_options) body.payment_options = payment_options;

  const res = await fetch(`${FLW_BASE}/payments`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${secretKey()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.status !== 'success' || !json.data || !json.data.link) {
    const msg = (json && json.message) || `Flutterwave create failed (HTTP ${res.status})`;
    const err = new Error(msg);
    err.flw = json;
    throw err;
  }
  return { link: json.data.link, raw: json };
}

// Server-side verify a transaction by Flutterwave transaction id.
// Returns the verified data object (or throws).
async function verifyTransaction(transactionId) {
  const res = await fetch(`${FLW_BASE}/transactions/${encodeURIComponent(transactionId)}/verify`, {
    headers: { Authorization: `Bearer ${secretKey()}` },
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.status !== 'success' || !json.data) {
    const err = new Error((json && json.message) || `Flutterwave verify failed (HTTP ${res.status})`);
    err.flw = json;
    throw err;
  }
  return json.data; // { status, amount, currency, tx_ref, id, ... }
}

module.exports = { createPayment, verifyTransaction, isTestKey, FLW_BASE };
