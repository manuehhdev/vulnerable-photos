async function init() {
  const who = await fetch('/api/whoami').then((r) => r.json());
  if (!who.user) {
    window.location.href = 'login.html';
    return;
  }
  document.getElementById('whoami').textContent = `Signed in as ${who.user.username}${who.user.is_admin ? ' (admin)' : ''}`;
}

document.getElementById('logout-btn').addEventListener('click', async () => {
  await fetch('/api/logout', { method: 'POST' });
  window.location.href = 'login.html';
});

document.getElementById('email-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const email = document.getElementById('email-input').value;
  // VULN: CSRF — plain POST, no anti-CSRF token.
  const res = await fetch('/api/account/email', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  alert(res.ok ? 'Email updated' : 'Failed');
});

document.getElementById('avatar-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const url = document.getElementById('avatar-url').value;
  // VULN: SSRF — the server fetches whatever URL is given, no validation.
  const res = await fetch('/api/account/avatar-from-url', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  const data = await res.json();
  document.getElementById('avatar-output').textContent = JSON.stringify(data, null, 2);
});

document.getElementById('settings-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  let body;
  try {
    body = JSON.parse(document.getElementById('settings-json').value);
  } catch (err) {
    alert('Invalid JSON');
    return;
  }
  // VULN: prototype pollution — raw JSON forwarded straight into
  // _.defaultsDeep on the server (lodash 4.17.11, CVE-2019-10744).
  const res = await fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  alert('Saved: ' + JSON.stringify(data.prefs));
});

document.getElementById('admin-btn').addEventListener('click', async () => {
  const res = await fetch('/api/admin/users');
  const data = await res.json();
  document.getElementById('admin-output').textContent = JSON.stringify(data, null, 2);
});

init();
