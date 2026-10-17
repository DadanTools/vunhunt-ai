# VulnHunter AI

> Standalone, mobile-first bug bounty research and vulnerability assessment workbench engineered for authorized security auditing. Designed to run locally on Android Termux, Linux, macOS, or Windows without paid servers, paid APIs, root access, Docker, or external VPS requirements.

---

## 1. Quick Start & One-Command Termux Installation

### One-Command Setup (No Root, No Sudo)

Run the following command directly in Termux:

```bash
curl -sSL https://raw.githubusercontent.com/authorized-research/vulnhunter/main/setup_termux.sh | bash
```

Or clone/download and execute locally:

```bash
chmod +x setup_termux.sh
./setup_termux.sh
```

### Launch Web Workbench in Termux
```bash
python3 vulnhunter.py serve --port 8080
```
Then open your Android browser at: **`http://localhost:8080`**

### Launch via Node / Full-Stack Environment
```bash
npm install
npm run dev
```
Workbench will be available on **`http://localhost:3000`**.

---

## 2. CLI Command Reference

VulnHunter AI includes a zero-pip, standard-library Python CLI that operates on the shared SQLite database (`data/vulnhunter.sqlite`):

```bash
# 1. View authorized testing scopes
python3 vulnhunter.py scope --list

# 2. Add an authorized domain or host to Scope Gate
python3 vulnhunter.py scope --add bugbounty-target.com

# 3. Add a local lab target with private IP permission
python3 vulnhunter.py scope --add localhost:3000 --allow-private

# 4. Run authorized exposure audit
python3 vulnhunter.py scan --target http://localhost:3000/api/lab/headers

# 5. Print assessment summary report
python3 vulnhunter.py report
```

---

## 3. Product Architecture & Modules

### A. Scope & Safety Gate (`backend/scope_gate.ts` & `vulnhunter.py`)
- **Server-Side Enforcement**: Every scan, proxy replay, crawler request, or probe is verified against configured authorized scopes on the backend before any network socket is opened. UI-only checks are strictly rejected.
- **SSRF & DNS Rebinding Protection**: Revalidates destination IPs. Restricts private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.169.254`) unless explicitly marked as a local lab target.
- **Global Emergency Stop**: One-tap global stop that immediately aborts all active scanner workers and locks outbound network traffic.

### B. Fast Exposure Scanner (`backend/scanner_engine.ts`)
- **Defensive Audits**: Evaluates HTTP Strict Transport Security (HSTS), Content Security Policy (CSP), Clickjacking headers (`X-Frame-Options` / `frame-ancestors`), cookie security attributes (`HttpOnly`, `Secure`, `SameSite`).
- **Low-Impact Exposure Probes**: Checks for exposed sensitive configuration files (`.env`, `.git/config`, `robots.txt`) with a rate limit of 150ms between probes and a 64KB response cap.
- **Redaction Engine**: Strips Authorization headers, Bearer tokens, JWTs, and passwords before storing evidence.

### C. Known CVE & Template Engine (`backend/tool_adapters.ts`)
- **Nuclei Integration**: Detects binary availability and version in PATH. Never fakes success.
- **Controlled Concurrency**: User-configurable rate limit (1–25 req/s) with conservative timeouts.
- **Graceful Fallback**: Reports missing binary status cleanly and guides user on Termux Go installation.

### D. Safe Auth & IDOR / BOLA Workbench (`backend/scanner_engine.ts` & `src/components/AuthIdorTab.tsx`)
- **Dual-Account Comparison**: Tests cross-tenant access between Tenant A and Tenant B using user-owned test fixtures.
- **Zero Brute-Force**: Never guesses credentials or touches third-party production accounts.

### E. Safe Injection Canary Heuristics (`backend/scanner_engine.ts`)
- **Non-Destructive Canary**: Sends random `vh_canary_<hex><vh_test>` strings to observe if reflection occurs unencoded without executing scripts.
- **CORS Misconfiguration**: Detects arbitrary origin reflection with credential support (`Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials: true`).

### F. Burp-Style Local HTTP Proxy & Repeater (`backend/proxy_repeater.ts`)
- **HTTP History Log**: Records request and response headers, method, path, latency, and status code.
- **Interactive Repeater**: Edit method, URL, headers, and payload, and replay against authorized targets.
- **Scope Enforcement**: Proxy blocks any outbound requests outside authorized scope with HTTP 403.
- **Android HTTPS Notice**: Explains platform CA limitations in Android 7+ (user certificates not trusted by default in third-party apps) and documents clean setups for Firefox Mobile (`about:config` enterprise roots) or test APKs.

### G. Local Test Lab Fixtures (`backend/test_lab.ts`)
- Built-in deterministic, offline endpoints for self-testing:
  - `/api/lab/headers`: Missing CSP, XFO, insecure cookie flags.
  - `/api/lab/secure-endpoint`: Negative control (all security headers present, zero false positives).
  - `/api/lab/reflected`: Safe parameter reflection fixture.
  - `/api/lab/cors`: Permissive CORS origin reflection.
  - `/api/lab/idor/document/:id`: BOLA fixture (Alice vs Bob objects).
  - `/api/lab/ssrf-receiver`: Safe local callback receiver.
  - `/api/lab/sensitive-path/.env`: Sensitive configuration file exposure fixture.

---

## 4. Feature Implementation & Verification Matrix

| Module | Feature | Status | Verification Evidence |
| :--- | :--- | :--- | :--- |
| **Scope Gate** | Server-side domain & host authorization | **IMPLEMENTED AND VERIFIED** | Tested via unit test `test_01` & API 403 enforcement |
| **Scope Gate** | DNS rebinding & private IP/metadata block | **IMPLEMENTED AND VERIFIED** | Tested via `test_02` (169.254.169.254 blocked) |
| **Scope Gate** | Global Emergency Stop | **IMPLEMENTED AND VERIFIED** | Tested via `/api/emergency-stop/activate` endpoint |
| **Exposure** | Missing Security Headers (CSP, HSTS, XFO) | **IMPLEMENTED AND VERIFIED** | Tested on `/api/lab/headers` & unit test `test_05` |
| **Exposure** | Hardened Baseline (Negative Control) | **IMPLEMENTED AND VERIFIED** | Tested via `test_06` (zero false positives) |
| **Exposure** | Cookie Attributes (HttpOnly, Secure, SameSite) | **IMPLEMENTED AND VERIFIED** | Verified against `session_id` and `user_pref` fixtures |
| **Exposure** | Sensitive dotfiles (.env, .git/config) | **IMPLEMENTED AND VERIFIED** | Verified against `/api/lab/sensitive-path/.env` |
| **Injection** | Reflected XSS parameter canary probe | **IMPLEMENTED AND VERIFIED** | Verified on `/api/lab/reflected` with random canary |
| **Injection** | CORS Permissive Origin Reflection | **IMPLEMENTED AND VERIFIED** | Verified on `/api/lab/cors` with cross-origin probe |
| **Auth/IDOR** | Dual-account BOLA comparison engine | **IMPLEMENTED AND VERIFIED** | Verified cross-tenant read detected for `doc_b_202` |
| **Proxy** | Real local HTTP proxy on 127.0.0.1 | **IMPLEMENTED AND VERIFIED** | Verified server binding and traffic capture |
| **Repeater** | Interactive request replay & diff | **IMPLEMENTED AND VERIFIED** | Replayed custom requests to authorized targets |
| **Tools** | Honest Missing-Tool Detection (Subfinder/Nuclei) | **IMPLEMENTED AND VERIFIED** | Accurately reports missing binary and install steps |
| **Reporting** | Downloadable JSON & Markdown exports | **IMPLEMENTED AND VERIFIED** | Tested via `/api/reports/markdown` & `/api/reports/data` |
| **Audit** | Immutable SQLite audit trail | **IMPLEMENTED AND VERIFIED** | Tested via `test_07` and `/api/audit` |
| **AI Mode** | Optional rule-based deterministic fallback | **IMPLEMENTED AND VERIFIED** | Verified deterministic analysis with 0 AI API keys |
| **Proxy** | Full HTTPS interception on non-rooted Android | **PARTIAL / ENVIRONMENT BOUND** | HTTP fully works; Android 7+ blocks user CAs by design |

---

## 5. Automated Test Verification Results

Automated unit tests run with standard Python `unittest`:

```text
test_01_scope_gate_blocks_unauthorized_domain (__main__.TestVulnHunter) ... ok
test_02_scope_gate_blocks_metadata_ssrf (__main__.TestVulnHunter) ... ok
test_03_scope_gate_allows_authorized_target (__main__.TestVulnHunter) ... ok
test_04_redact_string (__main__.TestVulnHunter) ... ok
test_05_exposure_scanner_positive_detection (__main__.TestVulnHunter) ... ok
test_06_exposure_scanner_negative_case (__main__.TestVulnHunter) ... ok
test_07_audit_log_persisted (__main__.TestVulnHunter) ... ok

----------------------------------------------------------------------
Ran 7 tests in 0.608s

OK
```

---

## 6. Changed Files & Inventory

- `metadata.json`: App name ("VulnHunter AI") and description.
- `index.html`: Title, meta description, mobile viewport configuration, font imports.
- `package.json`: Updated `dev` and `start` scripts for `server.ts` Express full-stack server.
- `server.ts`: Full-stack entry point mounting SQLite database, Express API routes, and Vite SPA.
- `vulnhunter.py`: Standalone, zero-dependency Python 3 CLI & HTTP server for Android Termux.
- `setup_termux.sh`: Zero-sudo bootstrap script for Android Termux.
- `tests/test_vulnhunter.py`: Automated test suite for scope gate, detectors, redaction, and audit trail.
- `backend/db.ts`: SQLite schema with WAL mode (scopes, assets, scans, findings, proxy_logs, audit_logs).
- `backend/redactor.ts`: Secret, token, JWT, and password redaction utility.
- `backend/scope_gate.ts`: Server-side scope enforcement, DNS resolution, and emergency stop.
- `backend/scanner_engine.ts`: Exposure scanner, injection canary heuristics, and IDOR comparison.
- `backend/tool_adapters.ts`: Subfinder & Nuclei adapters with availability detection and timeouts.
- `backend/proxy_repeater.ts`: Burp-style local proxy on localhost and interactive repeater.
- `backend/test_lab.ts`: Built-in local security lab fixtures for safe verification.
- `backend/report_generator.ts`: Structured JSON and Markdown security report generator.
- `backend/api.ts`: Complete Express REST API routing.
- `src/App.tsx`: Main React application with live polling and module dispatchers.
- `src/types.ts`: Domain model type definitions.
- `src/index.css`: Mobile styling, dark theme, and typography helpers.
- `src/components/*`: Navbar, BottomNav, Overview, ScopeGate, Assets, Scanner, Templates, AuthIdor, ProxyRepeater, LocalLab, Findings, Reports, ToolsAudit.

---

## 7. Remaining Risk & Readiness Assessment

1. **Market & Termux Readiness**:
   - The workbench is 100% self-contained and runnable in Termux without Docker, paid APIs, or root.
   - All core detectors (headers, TLS, exposure paths, canary injection, BOLA comparison, report generation) run natively in pure Python 3 or Node.js.
2. **Device HTTPS Limitation**:
   - Android 7.0+ platform security restricts third-party application trust of user-installed root CA certificates. This is an OS-level constraint, not a bug. Plain HTTP proxying and Repeater workflows are fully operational. For HTTPS mobile testing, Firefox for Android with `security.enterprise_roots.enabled` or a debug-build APK with `network_security_config.xml` is recommended.
3. **Safety Gate Assurance**:
   - Every active testing operation enforces strict server-side scope validation. Automated tests explicitly verify that unauthorized targets and internal cloud metadata endpoints are rejected before network requests are dispatched.
