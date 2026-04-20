// PARTENAIRE ✦ Seller Login Hint Remover
// Run: node patch_seller_hints.js
// Removes the visible demo phone numbers from the seller login screen

const fs = require('fs');
const path = require('path');

const FILE = path.join(__dirname, 'PARTENAIRE_Seller.html');
if (!fs.existsSync(FILE)) { console.error('❌ PARTENAIRE_Seller.html not found'); process.exit(1); }

let html = fs.readFileSync(FILE, 'utf8');
let count = 0;

// Remove demo seller hints from phone login screen
const OLD_HINT = `      <div class="auth-hint">
        <strong>Demo sellers:</strong><br>
        699000010 — MotoKing Douala (Gold)<br>
        699000011 — Parts Express CM (Silver)<br>
        699000014 — Guangzhou Motors (Premium)
      </div>`;

const NEW_HINT = `      <div class="auth-hint">
        Enter your registered phone number to receive a verification code.
      </div>`;

if (html.includes(OLD_HINT)) {
  html = html.replace(OLD_HINT, NEW_HINT);
  count++;
  console.log('✅ Removed demo phone numbers from login screen');
} else if (!html.includes('Demo sellers')) {
  console.log('ℹ️  Hint already removed (skipping)');
  count++;
} else {
  console.warn('⚠️  Could not find exact hint block — check manually');
}

// Also remove demo OTP hint from OTP screen
const OLD_OTP_HINT = `      <div class="auth-hint">Code OTP demo / Demo OTP code: <strong>1234</strong></div>`;
const NEW_OTP_HINT = `      <div class="auth-hint">Enter the 4-digit code sent to your phone.</div>`;

if (html.includes(OLD_OTP_HINT)) {
  html = html.replace(OLD_OTP_HINT, NEW_OTP_HINT);
  count++;
  console.log('✅ Removed demo OTP code from OTP screen');
}

if (count > 0) {
  fs.writeFileSync(FILE + '.hints.backup', fs.readFileSync(FILE));
  fs.writeFileSync(FILE, html, 'utf8');
  console.log('');
  console.log('🎉 PARTENAIRE_Seller.html hints removed successfully!');
  console.log('   Restart server: node partenaire_server.js');
} else {
  console.log('Nothing patched.');
}
