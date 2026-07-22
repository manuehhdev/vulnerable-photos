# Remediation Prompt (for Claude Code)

Paste this into Claude Code, running inside a fork of this repo, to fix the
vulnerabilities cataloged in `LAB_GUIDE.md` and `KNOWN_VULNERABILITIES.md`.

---

```
This repo (VulnerablePhotos) is an intentionally vulnerable Node.js lab app.
Fix every vulnerability listed below so the app is secure, while keeping it
fully functional (login, upload, search, gallery, sharing, account settings).

Read LAB_GUIDE.md and KNOWN_VULNERABILITIES.md first for full context on
each issue, then work through this list. For each item, explain the root
cause and your fix in the commit message — don't just make errors disappear.

1. SQL Injection (server.js: /api/login, /api/register, /api/search,
   /api/photos) — replace every string-concatenated SQL query with
   parameterized queries using sqlite3's `?` placeholders.

2. Stored & Reflected XSS (public/js/app.js, public/js/login.js) — stop
   building the DOM with innerHTML for untrusted data (titles,
   descriptions, search terms, error messages). Use textContent/DOM APIs or
   a proper escaping helper everywhere user input reaches the page.

3. Broken Access Control / IDOR (server.js: GET /api/users/:id/photos,
   GET /api/photos/:id, and any other resource route) — add an
   authorization check that the requesting session actually owns the
   resource before returning it; return 403 otherwise.

4. CSRF (server.js: POST /api/photos/:id/delete, GET /api/photos/:id/delete,
   POST /api/account/email) — add anti-CSRF tokens (e.g. csrf-csrf or a
   double-submit cookie) to all state-changing routes, set the session
   cookie's SameSite to 'lax' or 'strict', and delete the GET-based delete
   route entirely (state changes must never be a GET).

5. Misconfigured CORS (server.js CORS middleware) — replace the
   Origin-reflecting logic with an explicit allowlist of trusted origins;
   don't set Access-Control-Allow-Credentials unless it's genuinely needed
   for an allowlisted origin.

6. SSRF (server.js: POST /api/account/avatar-from-url) — validate and
   restrict the target URL (block loopback/private/link-local IP ranges,
   restrict to http/https, and re-validate after any redirect, not just the
   initial URL).

7. Prototype Pollution (server.js: POST /api/settings, requireAdmin) —
   stop merging raw req.body with _.defaultsDeep/_.merge. Validate/allowlist
   the accepted keys (e.g. with zod or joi) before merging, and remove the
   "empty object with default flags" pattern in requireAdmin in favor of an
   explicit session-based admin check.

8. Hardcoded/Weak Secrets (server.js: JWT_SECRET, session secret) — move
   both out of source into environment variables, generate them randomly,
   and make jwt.verify explicit about accepted algorithms
   (algorithms: ['HS256']).

9. Insecure credential storage (db/schema.sql, db/seed.js, server.js) —
   stop storing passwords in plaintext; hash them with bcrypt (or argon2)
   on registration and verify with a hash comparison on login.

10. Session cookie hardening (server.js) — set httpOnly: true on the
    session cookie (it's currently false on purpose for the XSS demo) and
    use a strong random session secret from an environment variable.

11. Runtime & dependencies (package.json, .nvmrc) — upgrade to an actively
    supported Node.js LTS and bump every dependency to a patched version.
    Run `npm audit` until it reports no high/critical findings, or document
    any accepted/unavoidable risk explicitly.

12. Remove or clearly gate the lab-only attack surface (attacker/ folder,
    /internal/debug-config route) since it has no purpose in a secured app.

After fixing everything, re-run through each exploit step in LAB_GUIDE.md
and confirm it no longer works, then run `npm audit` and paste the summary.
```
