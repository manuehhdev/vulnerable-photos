/**
 * VulnerablePhotos — INTENTIONALLY INSECURE. Educational use only. Do not deploy.
 * See LAB_GUIDE.md and KNOWN_VULNERABILITIES.md for the full vulnerability catalogue.
 */
require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const jwt = require('jsonwebtoken');
const _ = require('lodash');
const axios = require('axios');
const db = require('./lib/db');

const app = express();
const PORT = 4567;

// VULN: hardcoded, short, guessable JWT secret (CWE-798) — also lives in this
// public source file, so anyone who forks the repo can forge share tokens.
const JWT_SECRET = process.env.JWT_SECRET;

const upload = multer({ dest: path.join(__dirname, 'uploads') });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// -----------------------------------------------------------------------
// VULN: Misconfigured CORS — reflects any Origin and allows credentials.
// This lets ANY third-party site read authenticated API responses cross-site.
// -----------------------------------------------------------------------
const ALLOWED_ORIGINS = [
  'http://127.0.0.1:4567',
  'http://localhost:4567',
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  // Si el origin no está permitido, no se envían cabeceras CORS
  // y el browser bloquea la respuesta cross-origin.
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// -----------------------------------------------------------------------
// VULN: weak session config — no SameSite (cookie auto-sent cross-site,
// which is what makes the CSRF demos below work), weak static secret.
// -----------------------------------------------------------------------
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'strict' },
  })
);

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/attacker', express.static(path.join(__dirname, 'attacker')));

function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'not logged in' });
  next();
}

// =========================================================================
// VULN 1: SQL Injection — raw string concatenation, no parameterization.
// =========================================================================
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
  // Try: username = admin' -- , password = anything  ->  auth bypass
  db.get(query, [username, password], (err, row) => {
    if (err) return res.status(500).json({ error: err.message, query });
    if (!row) return res.status(401).json({ error: 'invalid credentials' });
    req.session.user = { id: row.id, username: row.username, is_admin: !!row.is_admin };
    res.json({ ok: true, user: req.session.user });
  });
});

app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email) return res.status(400).json({ error: 'missing fields' });
  const query = `INSERT INTO users (username, password, email) VALUES (?, ?, ?)`;
  db.run(query, [username, password, email], function (err) {
    if (err) return res.status(400).json({ error: err.message });
    req.session.user = { id: this.lastID, username, is_admin: false };
    res.json({ ok: true, user: req.session.user });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/whoami', (req, res) => {
  res.json({ user: req.session.user || null });
});

// SQLi #2: search, string-concatenated LIKE + UNION-friendly surface.
app.get('/api/search', requireLogin, (req, res) => {
  const q = req.query.q || '';
  const query = `SELECT id, owner_id, title, description, filename FROM photos WHERE title LIKE ? OR description LIKE ?`;
  db.all(query, [`%${q}%`, `%${q}%`], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message, query });
    // VULN: reflected XSS — the raw query term is echoed back verbatim for the
    // frontend to render with innerHTML (see public/js/app.js).
    res.json({ term: q, results: rows });
  });
});

// =========================================================================
// VULN 2: Stored XSS — titles/descriptions are stored and returned as-is;
// the frontend renders them with innerHTML (no escaping). See public/js/app.js.
// =========================================================================
app.post('/api/photos', requireLogin, upload.single('photo'), (req, res) => {
  const { title, description } = req.body;
  if (!req.file) return res.status(400).json({ error: 'no file uploaded' });
 
  const query = `INSERT INTO photos (owner_id, title, description, filename) VALUES (?, ?, ?, ?)`;
  db.run(query, [req.session.user.id, title, description, req.file.filename], function (err) {
    if (err) return res.status(400).json({ error: err.message, query });
    res.json({ ok: true, id: this.lastID });
  });
});

app.get('/api/photos', requireLogin, (req, res) => {
  db.all('SELECT id, owner_id, title, description, filename FROM photos', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// =========================================================================
// VULN 3: Broken Access Control / IDOR — only checks that *a* session exists,
// never that the session's user matches the requested :id / resource owner.
// Sequential integer IDs make enumeration trivial.
// =========================================================================
app.get('/api/users/:id/photos', requireLogin, (req, res) => {
  const userId = req.params.id; // no check that req.session.user.id === userId
  
  if (req.session.user.id !== parseInt(userId)) {
  return res.status(401).json({ error: 'Unauthorized' });
}

  db.all('SELECT id, owner_id, title, description, filename FROM photos WHERE owner_id = ?', [userId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get('/api/photos/:id', requireLogin, (req, res) => {
  db.get('SELECT id, owner_id, title, description, filename FROM photos WHERE id = ?', [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: 'not found' });
    if (row.owner_id !== req.session.user.id)
      return res.status(403).json({ error: 'forbidden' });
    res.json(row); // no ownership check
  });
});

// =========================================================================
// VULN 4: CSRF — state-changing actions, no anti-CSRF token, cookie sent
// automatically cross-site (session cookie has no SameSite attribute above).
// GET-based delete included deliberately to show the worst-case variant.
// =========================================================================
app.post('/api/photos/:id/delete', requireLogin, (req, res) => {
  db.run('DELETE FROM photos WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ ok: true });
  });
});

// app.get('/api/photos/:id/delete', requireLogin, (req, res) => {

//    const origin = req.headers.origin;
//   const expectedOrigin = 'http://127.0.0.1:4567';

//   if (origin !== expectedOrigin) {
//     return res.status(403).json({ error: 'Forbidden' });
//   }


//   db.run('DELETE FROM photos WHERE id = ?', [req.params.id], (err) => {
//     if (err) return res.status(500).json({ error: err.message });
//     res.json({ ok: true });
//   });
// });

app.post('/api/account/email', requireLogin, (req, res) => {

  const origin = req.headers.origin;
  const expectedOrigin = 'http://127.0.0.1:4567';

  if (origin !== expectedOrigin) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const { email } = req.body;
  db.run('UPDATE users SET email = ? WHERE id = ?', [email, req.session.user.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ ok: true, email });
  });
});

// =========================================================================
// EXTRA: Prototype Pollution via lodash 4.17.11 `_.defaultsDeep`
// (CVE-2019-10744). Polluting Object.prototype flips the `isAdmin` default
// used by requireAdmin() below for every plain object app-wide.
// =========================================================================
app.post('/api/settings', requireLogin, (req, res) => {
  const defaults = { theme: 'light', tileSize: 'medium' };
  const prefs = {};
  for (const key of ['theme', 'tileSize']) {
    prefs[key] = req.body[key] !== undefined ? req.body[key] : defaults[key];
  }
  req.session.prefs = prefs;
  res.json({ ok: true, prefs });
});

function requireAdmin(req, res, next) {
  const flags = {}; // if Object.prototype was polluted with isAdmin:true, flags.isAdmin is now true
  if (flags.isAdmin || (req.session.user && req.session.user.is_admin)) return next();
  return res.status(403).json({ error: 'forbidden' });
}

app.get('/api/admin/users', requireLogin, requireAdmin, (req, res) => {
  db.all('SELECT id, username, password, email, is_admin FROM users', (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// =========================================================================
// EXTRA: SSRF — server fetches an attacker-supplied URL with no allowlist,
// no scheme restriction, no protection against internal/loopback targets.
// =========================================================================
app.post('/api/account/avatar-from-url', requireLogin, async (req, res) => {
  const { url } = req.body;
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol))
      return res.status(400).json({ error: 'http/https only' });

    const blocked = ['127.0.0.1', 'localhost', '169.254.169.254', '0.0.0.0', '::1', '[::1]'];
    if (blocked.includes(parsed.hostname))
      return res.status(400).json({ error: 'URL points to a blocked host' });

    const response = await axios.get(url, { responseType: 'arraybuffer' });
    const destName = `${Date.now()}-avatar-fetch`;
    fs.writeFileSync(path.join(__dirname, 'uploads', destName), response.data);
    db.run('UPDATE users SET avatar = ? WHERE id = ?', [destName, req.session.user.id]);
    res.json({ ok: true, avatar: destName, contentType: response.headers['content-type'] });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Stand-in for an "internal-only" service — reachable directly here because
// this is a single local demo app, but in real deployments a route like this
// would live on an internal network the browser can't reach, only the server
// can (which is exactly what makes SSRF dangerous).
app.get('/internal/debug-config', (req, res) => {
  res.json({
    note: 'INTERNAL ONLY — not meant to be browser-reachable in a real deployment',
    AWS_SECRET_ACCESS_KEY: 'FAKE-EXAMPLE-KEY-DO-NOT-USE',
    admin_panel_token: 'fake-internal-token-abc123',
  });
});

// =========================================================================
// EXTRA: Weak/hardcoded JWT secret (jsonwebtoken 8.5.1, CVE-2022-23529 class
// of issues) — share links are signed with a short hardcoded secret that's
// checked into source, so anyone with the repo can forge tokens (e.g. to
// remove the expiry or share a photo they don't own).
// =========================================================================
app.post('/api/photos/:id/share', requireLogin, (req, res) => {
  const token = jwt.sign({ photoId: req.params.id }, JWT_SECRET, { expiresIn: '5m' });
  res.json({ ok: true, token, url: `/shared/${token}` });
});

app.get('/shared/:token', (req, res) => {
  jwt.verify(req.params.token, JWT_SECRET, { algorithms: ['HS256'] }, (err, payload) => {
    if (err) return res.status(401).json({ error: 'invalid or expired token' });
    db.get('SELECT id, title, description, filename FROM photos WHERE id = ?', [payload.photoId], (err2, row) => {
      if (err2 || !row) return res.status(404).json({ error: 'not found' });
      res.json(row);
    });
  });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`VulnerablePhotos (INSECURE — lab use only) listening on http://127.0.0.1:${PORT}`);
});
