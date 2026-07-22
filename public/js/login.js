const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const noticeEl = document.getElementById('notice');

document.getElementById('show-register').addEventListener('click', (e) => {
  e.preventDefault();
  loginForm.style.display = loginForm.style.display === 'none' ? 'block' : 'none';
  registerForm.style.display = registerForm.style.display === 'none' ? 'block' : 'none';
});

function showNotice(msg, type) {
  // VULN: reflected XSS — server error messages (which can include raw SQL /
  // user input) are rendered with innerHTML, unescaped.
  noticeEl.innerHTML = `<div class="notice ${type}">${msg}</div>`;
}

loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  const res = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  const data = await res.json();
  if (!res.ok) {
    showNotice(data.error || 'Login failed', 'error');
    return;
  }
  window.location.href = 'index.html';
});

registerForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('reg-username').value;
  const email = document.getElementById('reg-email').value;
  const password = document.getElementById('reg-password').value;

  const res = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password }),
  });
  const data = await res.json();
  if (!res.ok) {
    showNotice(data.error || 'Registration failed', 'error');
    return;
  }
  window.location.href = 'index.html';
});
