# PARTENAIRE ✦ OTP Patch Instructions
## Apply these changes to PARTENAIRE_Buyer.html and PARTENAIRE_Seller.html

---

## BUYER PORTAL — 3 changes in PARTENAIRE_Buyer.html

### Change 1: Replace `sendOTP()` function
Find this entire function and replace it:

```javascript
// FIND THIS:
async function sendOTP() {
  const phone = document.getElementById('phone-input').value.trim().replace(/\s/g,'');
  if (phone.length < 8) { authErr('phone-error','Enter a valid phone number'); return; }
  loginPhone = phone;
  try {
    // Check if buyer exists
    const buyers = await GET('ptn_users', `phone=eq.${phone}&role=eq.buyer&select=id,name`);
    if (!buyers || !buyers.length) {
      authErr('phone-error','No buyer account found. Please register first.');
      return;
    }
    // Clean old OTPs and create new one
    try {
      const old = await GET('ptn_otp_sessions', `phone=eq.${phone}&select=id`);
      if (old && old.length) {
        for (const s of old) {
          await xhr('DELETE', apiUrl('ptn_otp_sessions') + '?id=eq.' + s.id);
        }
      }
    } catch(e) {}
    await POST('ptn_otp_sessions', { phone, otp:'1234', expires_at: new Date(Date.now()+3600000).toISOString() });
    document.getElementById('otp-sub').textContent = `Code sent to +237 ${phone} (Demo: 1234)`;
    showScreen('screen-otp');
    setTimeout(() => document.getElementById('o0').focus(), 300);
  } catch(e) { authErr('phone-error', e.message); }
}

// REPLACE WITH:
async function sendOTP() {
  const phone = document.getElementById('phone-input').value.trim().replace(/\s/g,'');
  if (phone.length < 8) { authErr('phone-error','Enter a valid phone number'); return; }
  loginPhone = phone;
  try {
    const buyers = await GET('ptn_users', `phone=eq.${phone}&role=eq.buyer&select=id,name`);
    if (!buyers || !buyers.length) {
      authErr('phone-error','No buyer account found. Please register first.');
      return;
    }
    const res = await fetch('/otp/send', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phone: '+237' + phone })
    });
    const data = await res.json();
    if (!data.success) throw new Error(data.error || 'Failed to send OTP');
    document.getElementById('otp-sub').textContent = `Code sent to +237 ${phone}`;
    showScreen('screen-otp');
    setTimeout(() => document.getElementById('o0').focus(), 300);
  } catch(e) { authErr('phone-error', e.message); }
}
```

---

### Change 2: Replace `verifyOTP()` function
Find this entire function and replace it:

```javascript
// FIND THIS:
async function verifyOTP() {
  const otp = [0,1,2,3].map(i=>document.getElementById('o'+i).value).join('');
  if (otp.length!==4) { authErr('otp-error','Enter all 4 digits'); return; }
  try {
    // Check OTP
    const sessions = await GET('ptn_otp_sessions', `phone=eq.${loginPhone}&otp=eq.${otp}&select=id,expires_at`);
    if (!sessions || !sessions.length) { authErr('otp-error','Wrong code. Demo code is 1234'); return; }
    try { await PATCH('ptn_otp_sessions','id',sessions[0].id,{used:true}); } catch(e) {}

    // Load buyer
    const buyers = await GET('ptn_users', `phone=eq.${loginPhone}&role=eq.buyer&select=*`);
    currentBuyer = buyers[0];

    // Check if also a seller
    const sellers = await GET('ptn_users', `phone=eq.${loginPhone}&role=eq.seller&select=id`);
    currentBuyer._hasSeller = sellers && sellers.length > 0;

    enterApp();
  } catch(e) { authErr('otp-error', e.message); }
}

// REPLACE WITH:
async function verifyOTP() {
  const otp = [0,1,2,3].map(i=>document.getElementById('o'+i).value).join('');
  if (otp.length!==4) { authErr('otp-error','Enter all 4 digits'); return; }
  try {
    const res = await fetch('/otp/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phone: '+237' + loginPhone, code: otp })
    });
    const result = await res.json();
    if (!result.ok) { authErr('otp-error', result.reason || 'Wrong code'); return; }
    const buyers = await GET('ptn_users', `phone=eq.${loginPhone}&role=eq.buyer&select=*`);
    currentBuyer = buyers[0];
    const sellers = await GET('ptn_users', `phone=eq.${loginPhone}&role=eq.seller&select=id`);
    currentBuyer._hasSeller = sellers && sellers.length > 0;
    enterApp();
  } catch(e) { authErr('otp-error', e.message); }
}
```

---

### Change 3: Update the OTP hint text
Find and replace:
```
<div class="auth-hint">Code OTP démo / Demo OTP: <strong>1234</strong></div>
```
Replace with:
```
<div class="auth-hint">Code OTP: SMS sent to your phone 📱</div>
```

---

## SELLER PORTAL — 2 changes in PARTENAIRE_Seller.html

### Change 1: Replace `sendOTP()` function
Find this block inside `sendOTP()` and replace the try block:

```javascript
// FIND THIS (inside sendOTP, after the sellers.length check):
    // Store OTP session
    // Clean up old sessions for this phone first
    try {
      const oldSessions = await GET('ptn_otp_sessions', `phone=eq.${phone}&select=id`);
      for (const s of oldSessions) {
        await xhr('DELETE', apiUrl('ptn_otp_sessions') + '?id=eq.' + s.id);
      }
    } catch(e) {}
    // Create fresh OTP session (demo: always 1234)
    await POST('ptn_otp_sessions', { phone, otp: '1234', expires_at: new Date(Date.now() + 60*60*1000).toISOString() });
    document.getElementById('otp-sub').textContent = `Code sent to +237 ${phone}`;
    showScreen('screen-otp');
    setTimeout(() => document.getElementById('otp0').focus(), 300);

// REPLACE WITH:
    const res = await fetch('/otp/send', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phone: '+237' + phone })
    });
    const data = await res.json();
    if (!data.success) throw new Error(data.error || 'Failed to send OTP');
    document.getElementById('otp-sub').textContent = `Code sent to +237 ${phone}`;
    showScreen('screen-otp');
    setTimeout(() => document.getElementById('otp0').focus(), 300);
```

---

### Change 2: Replace `verifyOTP()` function
Find the try block inside `verifyOTP()` and replace:

```javascript
// FIND THIS (the try block inside verifyOTP):
  try {
    // First try unused session
    let sessions = await GET('ptn_otp_sessions',
      `phone=eq.${loginPhone}&otp=eq.${otp}&used=eq.false&select=id,expires_at`);
    
    // If no unused session found, check if OTP is correct but already used (re-verify)
    if (!sessions.length) {
      const usedSessions = await GET('ptn_otp_sessions',
        `phone=eq.${loginPhone}&otp=eq.${otp}&select=id,expires_at,used`);
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
    const sellers = await GET('ptn_users', `phone=eq.${loginPhone}&role=eq.seller&select=*`);
    currentSeller = sellers[0];

    // Check if they also have a buyer account
    const buyers = await GET('ptn_users', `phone=eq.${loginPhone}&role=eq.buyer&select=id`);
    currentSeller._hasBuyerAccount = buyers.length > 0;

    // Check if suspended for non-payment
    if (currentSeller.status === 'suspended') {
      showSuspendedScreen();
      return;
    }
    enterApp();
  } catch(e) {
    showAuthError('otp-error', e.message);
  }

// REPLACE WITH:
  try {
    const res = await fetch('/otp/verify', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ phone: '+237' + loginPhone, code: otp })
    });
    const result = await res.json();
    if (!result.ok) { showAuthError('otp-error', result.reason || 'Wrong code'); return; }

    const sellers = await GET('ptn_users', `phone=eq.${loginPhone}&role=eq.seller&select=*`);
    currentSeller = sellers[0];
    const buyers = await GET('ptn_users', `phone=eq.${loginPhone}&role=eq.buyer&select=id`);
    currentSeller._hasBuyerAccount = buyers.length > 0;

    if (currentSeller.status === 'suspended') {
      showSuspendedScreen();
      return;
    }
    enterApp();
  } catch(e) {
    showAuthError('otp-error', e.message);
  }
```

---

## YOUR BACKDOOR (works anywhere in the world)
- Phone: `675995524` + code `2468` → instant login, no SMS needed
- Email: `chido4reality@yahoo.com` + code `2468` → instant login (Admin portal)

## AFTER MAKING CHANGES
1. Save both HTML files
2. Restart server: `node partenaire_server.js`
3. Test at `http://localhost:8080/buyer` with phone `675995524` and code `2468`
