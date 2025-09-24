/* ---------- helpers ---------- */

// convert ArrayBuffer to hex (uppercase)
function buf2hex(buffer) {
  const bytes = new Uint8Array(buffer);
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return hex.toUpperCase();
}

// SHA-1 using Web Crypto API -> returns uppercase hex string
async function sha1Hex(input) {
  const enc = new TextEncoder();
  const data = enc.encode(input);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  return buf2hex(hashBuffer);
}

/* ---------- HIBP range query (k-anonymity) ---------- */
/* returns count (0 if not found), or -1 on network/error */
async function checkPwnedCountBySha1(sha1hex) {
  const prefix = sha1hex.slice(0, 5);
  const suffix = sha1hex.slice(5);
  const url = `https://api.pwnedpasswords.com/range/${prefix}`;

  try {
    const res = await fetch(url);
    if (!res.ok) return -1;

    const text = await res.text();
    const lines = text.split(/\r?\n/);

    for (const line of lines) {
      if (!line) continue;
      const [suf, countStr] = line.split(':');
      if (suf === suffix) {
        return parseInt(countStr.replace(/\D/g, ''), 10) || 0;
      }
    }
    return 0;
  } catch (err) {
    console.error('HIBP fetch error', err);
    return -1;
  }
}

/* ---------- Strength calculation ---------- */
function scorePassword(password) {
  let score = 0;
  const suggestions = [];

  if (password.length >= 12) score += 30;
  else if (password.length >= 8) score += 15;
  else if (password.length > 0) suggestions.push('Make it longer (≥12 chars)');

  if (/[A-Z]/.test(password)) score += 15;
  else suggestions.push('Add uppercase letters');

  if (/[a-z]/.test(password)) score += 15;
  else suggestions.push('Add lowercase letters');

  if (/\d/.test(password)) score += 15;
  else suggestions.push('Include numbers');

  if (/[^A-Za-z0-9]/.test(password)) score += 25;
  else suggestions.push('Add special characters');

  return { score: Math.min(score, 100), suggestions };
}

/* ---------- UI wiring + debounce ---------- */
const input = document.getElementById('pwd');
const fill = document.getElementById('strength-fill');
const feedback = document.getElementById('feedback');
const pwnedStatus = document.getElementById('pwned-status');
const pwnedCount = document.getElementById('pwned-count');

let debounceTimer = null;

function updateStrengthUI(score, suggestions) {
  fill.style.width = score + '%';
  if (score < 40) fill.style.background = '#e74c3c';
  else if (score < 80) fill.style.background = '#f39c12';
  else fill.style.background = '#27ae60';

  if (suggestions.length === 0) {
    feedback.innerHTML = '<strong style="color:#27ae60">Strength: Strong</strong>';
  } else {
    feedback.innerHTML = 'Suggestions:<br>• ' + suggestions.slice(0, 5).join('<br>• ');
  }
}

async function doFullCheck(password) {
  const { score, suggestions } = scorePassword(password);
  updateStrengthUI(score, suggestions);

  if (!password) {
    pwnedStatus.textContent = 'Breach status: unknown';
    pwnedStatus.className = 'pill muted';
    pwnedCount.textContent = '';
    return;
  }

  pwnedStatus.textContent = 'Checking breaches…';
  pwnedStatus.className = 'pill checking';

  try {
    const sha1 = await sha1Hex(password);
    const count = await checkPwnedCountBySha1(sha1);

    if (count === -1) {
      pwnedStatus.textContent = 'Breach status: unavailable';
      pwnedStatus.className = 'pill muted';
      pwnedCount.textContent = '';
      return;
    }

    if (count > 0) {
      pwnedStatus.textContent = 'Compromised';
      pwnedStatus.className = 'pill pwned';
      pwnedCount.textContent = `This password has appeared ${count.toLocaleString()} times in breaches — choose a different password.`;
    } else {
      pwnedStatus.textContent = 'Not found in breaches';
      pwnedStatus.className = 'pill safe';
      pwnedCount.textContent = 'Good — this password was not found in the HIBP database.';
    }
  } catch (err) {
    console.error(err);
    pwnedStatus.textContent = 'Breach check error';
    pwnedStatus.className = 'pill muted';
    pwnedCount.textContent = '';
  }
}

function debounceFullCheck(password) {
  if (debounceTimer) clearTimeout(debounceTimer);
  debounceTimer = setTimeout(() => doFullCheck(password), 700);
}

/* ---------- attach listener ---------- */
input.addEventListener('input', (e) => {
  const pwd = e.target.value;
  const { score, suggestions } = scorePassword(pwd);
  updateStrengthUI(score, suggestions);
  debounceFullCheck(pwd);
});
