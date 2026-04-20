// PARTENAIRE ✦ Seller OTP Auto-Patcher
// Run this ONCE from your project folder:
//   node patch_seller_otp.js
//
// It will patch PARTENAIRE_Seller.html automatically — no manual editing needed.

const fs = require('fs');
const path = require('path');

const FILE = path.join(__dirname, 'PARTENAIRE_Seller.html');

if (!fs.existsSync(FILE)) {
  console.error('❌ PARTENAIRE_Seller.html not found in this folder.');
  console.error('   Make sure you run this script from: C:\\Users\\Admin\\Desktop\\PARTENAIRE-Dozie.  Files');
  process.exit(1);
}

let html = fs.readFileSync(FILE, 'utf8');
let patchCount = 0;

// ── PATCH 1: Replace the OTP session creation block in sendOTP() ──
const OLD_SEND = `    // Store OTP session
    // Clean up old sessions for this phone first
    try {
      const oldSessions = await GET('ptn_otp_sessions', \`phone=eq.\${phone}&select=id\`);
      for (const s of oldSessions) {
        await xhr('DELETE', apiUrl('ptn_otp_sessions') + '?id=eq.' + s.id);
      }
    } catch(e) {}
    // Create fresh OTP session (demo: always 1234)
    await POST('ptn_otp_sessions', { phone, otp: '1234', expires_at: new Date(Date.now() + 60*60*1000).toISOString() });
    document.getElementById('otp-sub').textContent = \`Code sent to +237 \${phone}\`;
    showScreen('screen-otp');
    setTimeout(() => document.getElementById('otp0').focus(), 300);`;

const NEW_SEND = `    // ── PATCHED: Use server OTP (handles backdoor 2468 + Africa's Talking SMS) ──
    const res = await fetch('/otp/send', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phone: '+237' + phone })
    });
    const data = await res.json();
    if (!data.success) throw new Error(data.error || 'Failed to send OTP');
    document.getElementById('otp-sub').textContent = \`Code sent to +237 \${phone}\`;
    showScreen('screen-otp');
    setTimeout(() => document.getElementById('otp0').focus(), 300);`;

if (html.includes(OLD_SEND)) {
  html = html.replace(OLD_SEND, NEW_SEND);
  patchCount++;
  console.log('✅ Patch 1 applied: sendOTP() now uses /otp/send server endpoint');
} else if (html.includes('/otp/send')) {
  console.log('ℹ️  Patch 1 already applied (skipping)');
  patchCount++;
} else {
  console.warn('⚠️  Patch 1: Could not find the OTP send block. Your file may differ.');
}

// ── PATCH 2: Replace the verifyOTP try block ──
const OLD_VERIFY = `  try {
    // First try unused session
    let sessions = await GET('ptn_otp_sessions',
      \`phone=eq.\${loginPhone}&otp=eq.\${otp}&used=eq.false&select=id,expires_at\`);
    
    // If no unused session found, check if OTP is correct but already used (re-verify)
    if (!sessions.length) {
      const usedSessions = await GET('ptn_otp_sessions',
        \`phone=eq.\${loginPhone}&otp=eq.\${otp}&select=id,expires_at,used\`);
      if (!usedSessions.length) {
        showAuthError('otp-error','❌ Wrong code. Demo OTP is always 1234'); return;
      }
      // OTP matches but was used — allow if within 5 min of creation
      sessions = usedSessions;
    }

    const session = sessions[0];
    // Mark as used (ignore if already used)
    try { await PATCH('ptn_otp_sessions','id',session.id,{used:true}); } catch(e) {}

    // Load seller profile
    const sellers = await GET('ptn_users', \`phone=eq.\${loginPhone}&role=eq.seller&select=*\`);
    currentSeller = sellers[0];

    // Check if they also have a buyer account
    const buyers = await GET('ptn_users', \`phone=eq.\${loginPhone}&role=eq.buyer&select=id\`);
    currentSeller._hasBuyerAccount = buyers.length > 0;

    // Check if suspended for non-payment
    if (currentSeller.status === 'suspended') {
      showSuspendedScreen();
      return;
    }
    enterApp();
  } catch(e) {
    showAuthError('otp-error', e.message);
  }`;

const NEW_VERIFY = `  try {
    // ── PATCHED: Verify via server (backdoor 2468 + real OTP) ──
    const res = await fetch('/otp/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phone: '+237' + loginPhone, code: otp })
    });
    const result = await res.json();
    if (!result.ok) { showAuthError('otp-error', result.reason || 'Wrong code'); return; }

    const sellers = await GET('ptn_users', \`phone=eq.\${loginPhone}&role=eq.seller&select=*\`);
    currentSeller = sellers[0];
    const buyers = await GET('ptn_users', \`phone=eq.\${loginPhone}&role=eq.buyer&select=id\`);
    currentSeller._hasBuyerAccount = buyers.length > 0;

    if (currentSeller.status === 'suspended') {
      showSuspendedScreen();
      return;
    }
    enterApp();
  } catch(e) {
    showAuthError('otp-error', e.message);
  }`;

if (html.includes(OLD_VERIFY)) {
  html = html.replace(OLD_VERIFY, NEW_VERIFY);
  patchCount++;
  console.log('✅ Patch 2 applied: verifyOTP() now uses /otp/verify server endpoint');
} else if (html.includes('/otp/verify')) {
  console.log('ℹ️  Patch 2 already applied (skipping)');
  patchCount++;
} else {
  console.warn('⚠️  Patch 2: Could not find the OTP verify block. Your file may differ.');
}

// ── Save the file ──
if (patchCount > 0) {
  // Backup original
  fs.writeFileSync(FILE + '.backup', fs.readFileSync(FILE));
  // Write patched version
  fs.writeFileSync(FILE, html, 'utf8');
  console.log('');
  console.log('🎉 PARTENAIRE_Seller.html has been patched successfully!');
  console.log('   Original backed up as: PARTENAIRE_Seller.html.backup');
  console.log('');
  console.log('🔑 Your backdoor login:');
  console.log('   Phone: 675995524  →  Code: 2468  (works anywhere, no SMS needed)');
  console.log('');
  console.log('▶  Now run: node partenaire_server.js');
} else {
  console.log('❌ No patches applied. Check the warnings above.');
}
