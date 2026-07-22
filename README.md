# VulnerablePhotos

> ⚠️ **INTENTIONALLY INSECURE.** This is a training application for a security
> workshop. It contains deliberate SQL injection, XSS, IDOR, CSRF, CORS
> misconfiguration, SSRF, prototype pollution, and hardcoded-secret
> vulnerabilities, and it runs on an end-of-life Node.js version and outdated
> dependencies **on purpose**. Run it only on `127.0.0.1`, only on a machine
> you control, never on a shared or internet-facing host, and never with real
> credentials or personal data.

A local, Google-Photos-styled image gallery built with Express + SQLite +
vanilla HTML/CSS/JS, used to teach students how to find and fix common web
vulnerabilities.

## Quick start

Requires [nvm](https://github.com/nvm-sh/nvm) with Node 16 installed
(`nvm install 16`).

```bash
nvm use            # picks up Node 16 from .nvmrc
npm install         # installs pinned, deliberately outdated/vulnerable deps
npm run seed        # creates db/gallery.db and seeds demo users + photos
npm start            # http://127.0.0.1:3000
```

Seed accounts: `alice / alice123`, `bob / bob123`, `admin / admin123`.

## What's here

- `server.js` — Express app with every vulnerability, commented inline as `VULN:`.
- `public/` — the frontend (vanilla HTML/CSS/JS, Google-Photos-style UI).
- `attacker/` — standalone pages that demonstrate the CSRF and CORS exploits
  from a separate origin.
- `LAB_GUIDE.md` — step-by-step exploitation walkthrough + remediation exercises.
- `KNOWN_VULNERABILITIES.md` — CVE inventory for Node 16 and every pinned
  package, with risk level and attacker impact.

Start with `LAB_GUIDE.md`.
