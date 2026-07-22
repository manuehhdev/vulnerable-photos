# KNOWN_VULNERABILITIES.md

This app is pinned to **Node.js 16** and a set of **deliberately outdated
npm packages** so the workshop can teach supply-chain risk alongside the
application-layer vulnerabilities in `server.js`. This document catalogues
what's known-vulnerable in this exact stack, at what risk level, and what an
attacker can actually achieve with it.

> Versions and CVE ranges below reflect public advisories at the time this
> lab was written. Before using this doc for a live session, regenerate the
> ground truth with `npm audit` (`npm run audit:report`) and reconcile any
> differences — advisories get added retroactively.

## Risk levels

| Level | Meaning |
|---|---|
| **Critical** | Remote code execution, full auth bypass, or unrestricted data exfiltration with low attacker effort |
| **High** | Significant data exposure, privilege escalation, or DoS with realistic preconditions |
| **Medium** | Exploitable but needs specific conditions, or impact is limited/contained |
| **Low** | Theoretical/edge-case, or the real risk is "unmaintained" rather than a specific known exploit |

---

## 1. Node.js 16 runtime

**Node.js 16 reached End-of-Life on 2023-09-11.** No security patches — for
vulnerabilities already known at EOL *or* discovered since — will ever be
backported to this line. That absence of future patching is itself the
headline risk; the CVEs below are illustrative of the kind of issues the 16.x
line has had, and of what "no more patches" now means going forward.

| CVE | Risk | What it affects | What an attacker achieves |
|---|---|---|---|
| CVE-2023-44487 (HTTP/2 Rapid Reset) | **Critical** | Any Node.js HTTP/2 server, disclosed Oct 2023 — *after* Node 16's EOL date | Trivial, cheap denial-of-service: floods of stream-reset requests exhaust server resources. Because 16 was already EOL when this was disclosed, **it was never patched on this line and never will be**. |
| CVE-2023-32002 / -32003 / -32004 / -32006 (Node.js Policy feature bypasses) | High | Node's experimental Policy/permissions feature, fixed in 16.20.1 | Bypasses module-loading restrictions intended to sandbox untrusted code — relevant if this app (or a fork of it) ever adopts Node's policy manifests as a defense. |
| CVE-2022-32212 (DNS rebinding via `--inspect`) | High | Node's inspector/debug protocol, fixed in 16.16.0 | If a developer runs the app with `--inspect` open, a malicious webpage can rebind DNS and gain a debugger connection into the running process — effectively remote code execution in the dev's own machine. |
| CVE-2021-22930 / CVE-2021-22940 (HTTP/2 use-after-free) | Critical | Node's http2 implementation, fixed early in 16.x | Memory-corruption bugs in http2 stream handling — can crash the process (DoS) or, in the worst case, be leveraged toward RCE. |

**The point for the lab:** even where the 16.20.2 binary you're running has
already patched the *historical* CVEs above, the runtime itself is frozen.
The next HTTP/2, TLS, or V8 vulnerability disclosed for any actively
maintained line (18/20/22+) will **not** be fixed here, indefinitely.

---

## 2. npm package inventory

Confirmed by actually running `npm install && npm audit` on this project
under Node 16 — **27 vulnerabilities (5 low, 2 moderate, 15 high, 5
critical)** were reported. The table below maps each pinned package to its
real advisories (GHSA links, from the live audit output) and what an
attacker achieves.

| Package | Pinned version | Advisories (from `npm audit`) | Risk | What an attacker achieves |
|---|---|---|---|---|
| `lodash` | 4.17.11 | Critical — [Command Injection](https://github.com/advisories/GHSA-35jh-r3h4-6jhm), [Prototype Pollution ×2](https://github.com/advisories/GHSA-jf85-cpcp-j695), [ReDoS](https://github.com/advisories/GHSA-29mw-wpgm-hmr9), [`_.template` code injection](https://github.com/advisories/GHSA-r5fr-rjxr-66jc) | **Critical** | Demonstrated live in this app: `_.defaultsDeep` prototype pollution via `/api/settings` flips the `isAdmin` default used by `requireAdmin()`, turning any authenticated user into an admin. The command-injection and `_.template` advisories show how far this class of bug can go in other codebases (arbitrary code execution). |
| `request` (+ transitive `form-data`, `tough-cookie`, `tar`) | 2.88.2 | **Critical** — [form-data unsafe random boundary](https://github.com/advisories/GHSA-fjxv-7rqg-78g4) (*no fix available*), [form-data CRLF injection](https://github.com/advisories/GHSA-hmw2-7cc7-3qxx); Moderate — [tough-cookie prototype pollution](https://github.com/advisories/GHSA-72xf-g2v4-qvf3) (*no fix available*) | **Critical** | `request` itself has been **officially deprecated since Feb 2020** — no releases, ever again. Its bundled `form-data` has *no available fix* for a critical advisory, meaning even upgrading within the `request` tree can't resolve it; the only real fix is migrating off the package entirely. |
| `jsonwebtoken` | 8.5.1 | High — [insecure key-retrieval → forgeable tokens](https://github.com/advisories/GHSA-hjrf-2m68-5959), [signature-validation bypass via insecure default algorithm](https://github.com/advisories/GHSA-qwph-4952-7xr6), [unrestricted key type / legacy key usage](https://github.com/advisories/GHSA-8cf7-32gw-wr33) | **Critical** | Combined with this app's hardcoded `JWT_SECRET` (`server.js`), an attacker who reads the source — trivial, it's a public fork — can forge arbitrary share-link tokens with any expiry for any photo. The signature-bypass advisory shows the *package itself* can be tricked into accepting bad signatures even without a leaked secret, in vulnerable usage patterns. |
| `minimist` | 1.2.5 | Critical — [Prototype Pollution](https://github.com/advisories/GHSA-xvch-5gv4-984h) | **Critical** | Same impact class as the `lodash` finding above — any code path (including build tooling) that parses untrusted args through this version can pollute `Object.prototype` app-wide. |
| `tar` (transitive, via `sqlite3`/`node-pre-gyp`) | bundled | Critical — 14 advisories including [arbitrary file overwrite](https://github.com/advisories/GHSA-3jfq-g458-7qm9) and [symlink poisoning](https://github.com/advisories/GHSA-8qq5-rm4j-mr97) | **Critical** | Only reachable if something extracts an attacker-supplied tarball at install/build time — but it's a stark supply-chain example: a "just a build dependency" transitively drags in 14 file-system-corruption advisories. |
| `axios` | 0.21.1 | High — [SSRF/credential leakage via absolute URL](https://github.com/advisories/GHSA-jr5f-v2jv-69x6), [ReDoS](https://github.com/advisories/GHSA-cph5-m8f7-6c5x), [CSRF](https://github.com/advisories/GHSA-wf5p-g6vw-rhxx), plus numerous prototype-pollution-gadget advisories in later disclosures | **High** | Directly compounds this app's own SSRF demo (`/api/account/avatar-from-url`): even a naive allowlist on the *initial* URL can be undermined by axios's own request-construction bugs. The ReDoS advisory enables cheap DoS on any endpoint parsing attacker strings. |
| `marked` | 0.3.9 | High — [Inefficient Regular Expression Complexity ×2](https://github.com/advisories/GHSA-rrrm-qjm4-v8hf), [ReDoS](https://github.com/advisories/GHSA-p9wx-2529-fp83) | **High** | Rendering any user-supplied Markdown as HTML without a sanitizer (this version predates all of marked's later sanitization guidance) is a direct stored-XSS vector, and crafted input can hang the render thread via the ReDoS advisories. |
| `moment` | 2.24.0 | High — [Path Traversal in `moment.locale`](https://github.com/advisories/GHSA-8hfj-j24r-96c4), [Inefficient Regular Expression Complexity](https://github.com/advisories/GHSA-wc69-rhjr-hc9g) | **High** | The locale path-traversal advisory can be used to read/require unexpected files off disk if an attacker-controlled locale string reaches the filesystem loader; the ReDoS advisory hangs the process on a crafted date string. |
| `qs` (Express's query parser) | pulled in transitively | High — [Prototype Pollution](https://github.com/advisories/GHSA-hrpp-h998-j3pp), [`arrayLimit` bypass → memory-exhaustion DoS](https://github.com/advisories/GHSA-6rw7-vpxm-498p) | **High** | Same impact class as `lodash`/`minimist` — but reachable through ordinary query-string parsing on *every* request, no special endpoint needed. |
| `express` (+ transitive `path-to-regexp`, `send`, `serve-static`, `body-parser`) | 4.16.4 | High — [`path-to-regexp` ReDoS ×3](https://github.com/advisories/GHSA-9wv6-86v2-598j), [`send` template-injection XSS](https://github.com/advisories/GHSA-m6fv-jmcg-4jfg), [`body-parser` DoS ×2](https://github.com/advisories/GHSA-qwcr-r2fm-qrc7) | **High** | Route-matching ReDoS can hang the whole server on a single crafted request path; the `send` advisory is a template-injection-driven XSS in static-file serving — i.e. `express.static('/uploads', ...)` in this very app. |
| `express-session` (+ transitive `cookie`, `on-headers`) | 1.15.6 | Moderate — [`cookie` accepts out-of-bounds characters](https://github.com/advisories/GHSA-pxg6-pf52-xh8x), [`on-headers` response-header manipulation](https://github.com/advisories/GHSA-76c9-3jph-rj3q) | Medium | Widens the header/cookie-manipulation surface that compounds this app's own missing `SameSite`/`httpOnly` session hardening (see `LAB_GUIDE.md` CSRF/XSS sections). |
| `multer` (+ transitive `busboy`, `dicer`) | 1.4.2 | High — [`dicer` header-parser crash](https://github.com/advisories/GHSA-wm7h-9275-46v2) (CVE-2022-24434 class) | **High** | A single malformed `multipart/form-data` upload (the photo-upload endpoint) can crash the request handler — denial of service for any authenticated user. |
| `sqlite3` (+ transitive `node-pre-gyp`) | 5.0.2 | High — [DoS on invalid bound parameters](https://github.com/advisories/GHSA-9qrh-qjmc-5w2p), [code execution via Object coercion](https://github.com/advisories/GHSA-jqv5-7xpx-qj74) | **High** | The Object-coercion advisory is a reminder that even the "safe," parameterized-query layer this lab tells students to migrate *to* isn't automatically risk-free — it still needs to be kept current. |

> Two advisories above (`form-data`, `tough-cookie`) show **"No fix
> available"** in `npm audit` at the time of writing — a concrete example of
> risk that literally cannot be patched away within the current dependency
> tree, only removed by migrating off the package.

---

## 3. Why this matters beyond "run `npm audit`"

`npm audit` will flag most of the table above automatically — that's by
design, so students can compare the tool's output to this document. The
teaching point is threefold:

1. **Runtime EOL is invisible to `npm audit`.** It only audits packages, not
   the Node.js binary itself — a project can have a perfectly clean audit and
   still be running on a runtime that will never receive a security patch
   again.
2. **Deprecated ≠ vulnerable (yet), but it becomes vulnerable eventually.**
   `request` may show zero *current* findings in some audit snapshots even
   though it's dead — the risk is that nobody is watching for the next one.
3. **Chained impact is worse than any single finding.** The `lodash`
   prototype-pollution CVE alone is "High" in isolation; chained with this
   app's own broken `requireAdmin` logic, it becomes a full authentication
   bypass — see the walkthrough in `LAB_GUIDE.md` §2.7.
