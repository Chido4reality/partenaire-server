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

// Refund a previously-successful charge. Our flow is full-order only, so the
// caller passes amount = order.total. FLW v3: POST /v3/transactions/:id/refund
// with { amount }. Some collection corridors (mobile money, OPay) are NOT
// API-refundable — FLW returns an error; we surface { ok:false, reason } and the
// caller falls back to a manual refund (refund_status='pending_manual'). On
// success FLW returns data.{ id, status } (status 'completed' | 'pending').
// NEVER throws — refunds must degrade to manual, not crash resolveRefund.
async function refundTransaction(flwTxId, amount) {
  if (!flwTxId) return { ok: false, reason: 'no_flw_tx_id' };
  try {
    const res = await fetch(`${FLW_BASE}/transactions/${encodeURIComponent(flwTxId)}/refund`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${secretKey()}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(amount != null ? { amount } : {}),
    });
    const json = await res.json().catch(() => ({}));
    if (!res.ok || json.status !== 'success' || !json.data) {
      return { ok: false, reason: (json && json.message) || `Flutterwave refund failed (HTTP ${res.status})`, raw: json };
    }
    return { ok: true, refundId: String(json.data.id != null ? json.data.id : ''), status: json.data.status || null, raw: json };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

// ── SELLER PAYOUT — Phase 1 (CAPTURE + VERIFY only; NO Transfers) ──────────
// These reuse the same FLW v3 base + FLW_SECRET_KEY as the collect leg. They
// are read/verify lookups only — they never move money.

// List banks for a country (NG). FLW v3: GET /v3/banks/:country.
// Returns [{ code, name }] (throws on failure).
async function getBanks(country) {
  const res = await fetch(`${FLW_BASE}/banks/${encodeURIComponent(country)}`, {
    headers: { Authorization: `Bearer ${secretKey()}` },
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.status !== 'success' || !Array.isArray(json.data)) {
    const err = new Error((json && json.message) || `Flutterwave banks failed (HTTP ${res.status})`);
    err.flw = json;
    throw err;
  }
  // Normalize + sort by name; some FLW entries share a code (branches) — keep all.
  return json.data
    .map(b => ({ code: String(b.code), name: b.name }))
    .filter(b => b.code && b.name)
    .sort((a, b) => a.name.localeCompare(b.name));
}

// Resolve (verify) a bank account name. FLW v3: POST /v3/accounts/resolve with
// { account_number, account_bank }. Returns { account_name } (throws if FLW
// can't resolve — caller surfaces a clean error).
async function resolveAccount(account_number, account_bank) {
  const res = await fetch(`${FLW_BASE}/accounts/resolve`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${secretKey()}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ account_number, account_bank }),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.status !== 'success' || !json.data || !json.data.account_name) {
    const err = new Error((json && json.message) || `Could not resolve account (HTTP ${res.status})`);
    err.flw = json;
    throw err;
  }
  return { account_name: json.data.account_name };
}

// ── SELLER PAYOUT — Phase 2 (REAL MONEY: Flutterwave Transfers) ────────────
// Reuse the same FLW v3 base + FLW_SECRET_KEY. These MOVE money — the caller
// (payoutSellerForOrder) owns idempotency (PO-<order_ref> reference + a
// claim-before-call status write).

// Transfer fee FLW charges the sender for a payout. v3: GET /v3/transfers/fee.
// Returns a number (0 on any ambiguity — caller treats fee as seller-borne).
async function getTransferFee(amount, currency) {
  const url = `${FLW_BASE}/transfers/fee?amount=${encodeURIComponent(amount)}&currency=${encodeURIComponent(currency)}`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${secretKey()}` } });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.status !== 'success' || !Array.isArray(json.data)) {
    const err = new Error((json && json.message) || `Flutterwave fee failed (HTTP ${res.status})`);
    err.flw = json;
    throw err;
  }
  const entry = json.data.find(d => d && d.fee != null) || json.data[0] || {};
  const fee = Number(entry.fee || 0);
  return isFinite(fee) ? fee : 0;
}

// Create a payout transfer. v3: POST /v3/transfers. Returns { id, status,
// reference, raw }. Throws on failure; err.retryable flags insufficient-balance
// / settlement-not-ready (caller keeps funds + retries) vs a hard error.
//   NG bank: { account_bank, account_number, amount, currency:'NGN', narration,
//             reference, debit_currency:'NGN' }.
//   CM MoMo (XAF): FLW mobile-money transfer shape — IMPLEMENTED BEST-EFFORT,
//   the exact params are UNCERTAIN (see report). XAF is gated OFF upstream
//   (payoutSellerForOrder never calls this for XAF), so this branch does not
//   execute until XAF is enabled on the account and the params are confirmed.
async function createTransfer(p) {
  let body;
  if (p.currency === 'NGN' || p.country === 'NG') {
    body = {
      account_bank: p.bank_code,
      account_number: p.account_number,
      amount: p.amount,
      currency: 'NGN',
      narration: p.narration || 'Partenaire Dozie payout',
      reference: p.reference,
      debit_currency: 'NGN',
    };
  } else {
    // XAF / Cameroon Mobile Money — TO CONFIRM before XAF go-live:
    //  - account_bank: FLW expects the mobile-money network code here. For CM
    //    the codes are not the same strings as our 'MTN'/'ORANGE'; FLW's CM MoMo
    //    transfer corridor + exact network code must be confirmed from the FLW
    //    dashboard/support. We pass the operator through and let the gate keep
    //    this dormant until verified.
    //  - account_number: beneficiary MoMo phone (digits).
    body = {
      account_bank: p.momo_operator,
      account_number: p.momo_number,
      amount: p.amount,
      currency: 'XAF',
      narration: p.narration || 'Partenaire Dozie payout',
      reference: p.reference,
      debit_currency: 'XAF',
      meta: [{ mobile_number: p.momo_number }],
    };
  }
  const res = await fetch(`${FLW_BASE}/transfers`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${secretKey()}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.status !== 'success' || !json.data) {
    const msg = (json && json.message) || `Flutterwave transfer failed (HTTP ${res.status})`;
    const err = new Error(msg);
    err.flw = json;
    err.retryable = /insufficient|balance|not enough|settlement|try again|temporar|unsettled/i.test(msg);
    throw err;
  }
  return {
    id: json.data.id,
    status: json.data.status || null,
    reference: json.data.reference || p.reference,
    fee: json.data.fee,
    raw: json,
  };
}

// Fetch a transfer by id (authoritative status for the async webhook). Throws.
async function verifyTransfer(transferId) {
  const res = await fetch(`${FLW_BASE}/transfers/${encodeURIComponent(transferId)}`, {
    headers: { Authorization: `Bearer ${secretKey()}` },
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok || json.status !== 'success' || !json.data) {
    const err = new Error((json && json.message) || `Flutterwave transfer fetch failed (HTTP ${res.status})`);
    err.flw = json;
    throw err;
  }
  return json.data; // { id, status: 'SUCCESSFUL'|'FAILED'|'NEW'|'PENDING', complete_message, ... }
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

module.exports = { createPayment, verifyTransaction, refundTransaction, getBanks, resolveAccount, getTransferFee, createTransfer, verifyTransfer, isTestKey, FLW_BASE };
