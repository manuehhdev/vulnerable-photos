# LAB_GUIDE.md — VulnerablePhotos Workshop

> Run everything against `http://127.0.0.1:3000` only. Do not expose this app
> to any network. Use only the seed accounts and fake data provided.

## 1. Setup

```bash
nvm install 16        # if you don't already have it
nvm use                # reads .nvmrc -> Node 16
npm install
npm run seed            # (re)creates db/gallery.db with seed users + photos
npm start
```

Open `http://127.0.0.1:3000` — you'll land on `login.html`. Seed accounts:

| username | password | role  |
|----------|----------|-------|
| alice    | alice123 | user  |
| bob      | bob123   | user  |
| admin    | admin123 | admin |

Every vulnerable line in `server.js` is tagged with a `// VULN:` comment
explaining the flaw and the CWE/CVE class it belongs to.

---

## 2. Exploit Walkthroughs

### 2.1 SQL Injection — authentication bypass

`POST /api/login` builds its query with raw string concatenation
(`server.js`, `/api/login`).

1. Go to the login page.
2. Username: `admin' --`
3. Password: `anything`
4. You are logged in as `admin` without knowing the password.

The query becomes:
```sql
SELECT * FROM users WHERE username = 'admin' --' AND password = 'anything'
```
`--` comments out the password check entirely.

**Also try (data exfiltration via search):**
```
GET /api/search?q=%' UNION SELECT id, id, username, password, 'x' FROM users --
```
This dumps every username/password pair into the photo search results because
`/api/search` is built the same way (`WHERE title LIKE '%<q>%'`).

### 2.2 Stored & Reflected XSS

**Stored:** Log in, upload a photo with title:
```html
 <img src=x onerror="alert(/stored-xss/.source+document.cookie)">
```
Every user who views the gallery (or the same user reloading it) now executes
your script — the title is inserted via `innerHTML` in `public/js/app.js`
(`renderGrid`) with no escaping. Because the session cookie is *not*
`httpOnly` in this app (see `server.js`), the payload can read
`document.cookie` directly.

**Reflected:** Search for:
```html
<img src=x onerror="alert(/reflected-xss/.source)">
```
The raw query term is echoed back into `#search-notice` unescaped
(`public/js/app.js`, `runSearch`).

### 2.3 Broken Access Control (IDOR)

Log in as `bob`. In the sidebar, click **"View user's photos by ID"** and
enter `1` (alice's user id). You'll see alice's private photos even though
your session belongs to bob — `GET /api/users/:id/photos` only checks that
*a* session exists, never that it matches `:id`.

```bash
curl -b cookies.txt http://127.0.0.1:3000/api/users/1/photos
```

Sequential integer IDs make this trivial to script: loop `id = 1..N` and dump
every user's photo library.

### 2.4 CSRF

With the app running and you logged in as any user, open
`attacker/csrf-delete.html` from a **different origin** (so the browser
treats it as cross-site):

```bash
cd attacker
python3 -m http.server 4000
# visit http://127.0.0.1:4000/csrf-delete.html while logged into
# http://127.0.0.1:3000 in the same browser
```

Loading that page silently:
- POSTs to `/api/account/email`, changing your email to `attacker@evil.example`.
- Loads an `<img>` pointed at `GET /api/photos/1/delete`, deleting photo id 1.

No confirmation, no click, no token — the session cookie has no `SameSite`
attribute, so the browser attaches it to the cross-site request automatically.

### 2.5 Misconfigured CORS

Serve the attacker page the same way:

```bash
cd attacker
python3 -m http.server 4000
# visit http://127.0.0.1:4000/cors-steal.html while logged into
# http://127.0.0.1:3000
```

Click **"Steal victim's data"**. Because the server reflects the `Origin`
header into `Access-Control-Allow-Origin` and sets
`Access-Control-Allow-Credentials: true`, `fetch(..., { credentials: 'include' })`
from `127.0.0.1:4000` can read authenticated JSON from `127.0.0.1:3000` —
including, chained with the IDOR above, every user's photo list.

### 2.6 SSRF (bonus)

Log in, go to **Account → Avatar from URL**, and submit:
```
http://127.0.0.1:3000/internal/debug-config
```
The server fetches that URL itself (`axios.get(url)`, no allowlist, no
scheme/host restriction) and you can read the response back — a stand-in for
reaching cloud metadata (`169.254.169.254`) or internal-only services that a
browser could never reach directly in a real deployment.

### 2.7 Prototype Pollution (bonus)

Go to **Account → Preferences** and submit:
```json
{"constructor":{"prototype":{"isAdmin":true}}}
```
(Note: a literal `"__proto__"` key parsed by `JSON.parse` becomes an
*own property* named `__proto__`, not a live prototype link — it won't
trigger the bug on its own. The `constructor.prototype` path is the actual
documented CVE-2019-10744 exploit vector, since `defaultsDeep` recurses into
it and ends up assigning through the object's real `[[Prototype]]`.)

This is forwarded to `_.defaultsDeep({}, req.body, defaults)` on the server
(lodash `4.17.11`, CVE-2019-10744), which pollutes `Object.prototype`. Now
click **"GET /api/admin/users"** — even though you're logged in as `alice`,
`requireAdmin`'s `flags.isAdmin` check on a *fresh empty object* now resolves
to `true` for everyone, and you get the full user table, plaintext passwords
included.

### 2.8 Weak/Hardcoded JWT Secret (bonus)

Open a photo's lightbox and click **"Get share link"** — this signs a JWT
with a 5-minute expiry using the secret `vp2024`, hardcoded in `server.js`
(anyone who reads the source, e.g. after forking the repo, knows it). Forge
your own long-lived token for any photo id with a tool like
[jwt.io](https://jwt.io) (offline, paste the secret manually — don't submit
real secrets to a public tool) or `jsonwebtoken` directly:

```js
require('jsonwebtoken').sign({ photoId: 6 }, 'vp2024', { expiresIn: '10y' });
```
`GET /shared/<forged-token>` now serves photo 6 (admin's) with a 10-year
token the app never intended to issue.

---

## 3. Remediation Exercises

Fork the repository and, for each vulnerability, submit a PR that fixes it.
Suggested acceptance criteria per fix:

1. **SQL Injection** — Replace all string-concatenated queries in
   `server.js` (`/api/login`, `/api/register`, `/api/search`, `/api/photos`)
   with parameterized queries (`db.get(query, [params], cb)`).
   *Acceptance:* `username = "' OR '1'='1"` no longer logs anyone in;
   `sqlite3` placeholders (`?`) used everywhere.

2. **XSS** — Stop building DOM via `innerHTML` with untrusted strings in
   `public/js/app.js` and `public/js/login.js`. Use `textContent`, DOM APIs
   (`createElement` + `.textContent`), or an escaping helper.
   *Acceptance:* uploading `<img src=x onerror=alert(1)>` as a title renders
   as literal text, not a live element; no `alert()` fires anywhere in the
   app for any stored or reflected input.

3. **IDOR** — Add an authorization check to `/api/users/:id/photos` and
   `/api/photos/:id` (and any other resource route) that verifies
   `req.session.user.id == :id` (or ownership of the resource), returning
   `403` otherwise. Consider a reusable `requireOwnership` middleware.
   *Acceptance:* `bob` can no longer fetch `/api/users/1/photos` (alice's).

4. **CSRF** — Add anti-CSRF tokens (e.g. `csurf`/`csrf-csrf`, or a
   double-submit cookie) to every state-changing route, set
   `cookie: { sameSite: 'lax' }` (or `'strict'`) on the session, and remove
   the `GET`-based delete route entirely (state changes must never be `GET`).
   *Acceptance:* `attacker/csrf-delete.html` no longer changes the victim's
   email or deletes their photo.

5. **CORS** — Replace the Origin-reflecting middleware with an explicit
   allowlist of trusted origins (or remove `Access-Control-Allow-Credentials`
   if credentials genuinely aren't needed cross-origin).
   *Acceptance:* `attacker/cors-steal.html`'s fetches fail with a CORS error
   in the browser console.

6. **SSRF** — Validate/allowlist the `url` in
   `/api/account/avatar-from-url` (block loopback/private ranges, restrict to
   `http(s)`, consider an allowlist of domains or disabling server-side URL
   fetch entirely in favor of client-side upload).
   *Acceptance:* `http://127.0.0.1:3000/internal/debug-config` and
   `http://169.254.169.254/...`-style targets are rejected.

7. **Prototype Pollution** — Stop merging untrusted `req.body` directly with
   `_.defaultsDeep`/`_.merge`. Either upgrade lodash and use
   `_.defaultsDeep` only on validated, allowlisted keys, or use
   `Object.create(null)` / a schema validator (e.g. `zod`, `joi`) before
   merging.
   *Acceptance:* posting `{"constructor":{"prototype":{"isAdmin":true}}}` to
   `/api/settings` no longer makes `/api/admin/users` return data for a
   non-admin session.

8. **Hardcoded/Weak Secrets** — Move `JWT_SECRET` and the session `secret`
   out of source into environment variables, generate them randomly
   (`crypto.randomBytes(32).toString('hex')`), and add `algorithms: ['HS256']`
   to `jwt.verify` explicitly.
   *Acceptance:* secrets aren't present in git history; a forged token signed
   with the old hardcoded value is rejected after rotation.

9. **Runtime & Dependencies** — Upgrade to an actively supported Node.js LTS
   and bump every dependency in `package.json` to a patched version (see
   `KNOWN_VULNERABILITIES.md`). Run `npm audit` until it's clean (or document
   any accepted risk explicitly).
   *Acceptance:* `node --version` is a maintained LTS; `npm audit` reports no
   high/critical findings.

For each exercise, write a short note in your PR describing: what the
vulnerability allowed an attacker to do, the root cause, and how your fix
addresses it (not just "made the error go away").
