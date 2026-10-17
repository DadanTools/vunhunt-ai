# VulnHunter AI: Production-Grade Security Assessment & Pentest Workbench

This document details the architectural specifications and execution plan for **VulnHunter AI**, a real-world, production-grade vulnerability assessment workbench engineered for **Android Termux** and modern web browsers. It eliminates reliance on broken dependencies or mock tools, providing genuine, non-destructive security auditing with zero external API requirements.

---

## 1. System Vision & Non-Negotiable Engineering Standards

- **100% Real Functionality**: Every check executes authentic network requests, analyzes actual HTTP responses, inspects TLS handshake metadata, and parses real server banners. Zero placeholder data or simulated results.
- **Dual Target Ingestion**: Seamlessly processes both bare domains (`example.com` with auto-protocol probing) and deep endpoint URLs (`https://example.com/api/user?id=101`).
- **Dual Reporting Engines**: Outputs both **Bug Bounty Submission format** (HackerOne/Bugcrowd with CVSS ratings and reproduction commands) and **Enterprise Compliance format** (executive summary, risk heatmaps, OWASP Top 10 / CWE mapping).
- **Zero-Failure Termux Compatibility**: The entire engine is implemented in pure Python 3 standard library (`urllib.request`, `sqlite3`, `ssl`, `http.server`, `socket`), guaranteeing it runs on any Android Termux installation without compilation errors or root access.

---

## 2. Technical Architecture & Multi-Vector Audit Pipeline

```
+-------------------------------------------------------------------------------+
|                       TARGET INGESTION (Bare Domain or Full URL)              |
|              e.g., "example.com" OR "https://example.com/api/profile?id=42"    |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                   STAGE 0: AUTO-SCOPE GATE & PRE-FLIGHT                       |
|  - Normalizes target into origin and path.                                    |
|  - Revalidates DNS & blocks private IP / cloud metadata SSRF (169.254.169.254)|
|  - Auto-authorizes target into local SQLite database.                         |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                   STAGE 1: FAST INFRASTRUCTURE & EXPOSURE AUDIT               |
|  [1.1] TLS/SSL Inspection: Protocol, cipher suite, cert validity & expiration. |
|  [1.2] Security Headers: CSP, HSTS (preload), X-Frame-Options, nosniff, CORS. |
|  [1.3] Cookie Security: HttpOnly, Secure, SameSite, session token entropy.    |
|  [1.4] Server Fingerprinting: Server, X-Powered-By, ASP.NET leakage banners.  |
|  [1.5] Sensitive Path Probing (150ms rate-limited):                           |
|        .env, .git/HEAD, .git/config, robots.txt, sitemap.xml, backup.sql      |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                   STAGE 2: DEEP HEURISTIC EXPLORATION                         |
|  [2.1] Unencoded Parameter Canary: Unique dynamic token reflection probe.     |
|  [2.2] Permissive CORS Inspection: Origin spoofing + Credential exposure.     |
|  [2.3] Open Parameter Redirect: Safe destination reflection detection.        |
|  [2.4] BOLA / IDOR Verification: Dual-tenant token cross-read comparison.     |
+---------------------------------------+---------------------------------------+
                                        |
                                        v
+-------------------------------------------------------------------------------+
|                   STAGE 3: DUAL-FORMAT REPORTING GENERATOR                    |
|  [Report A] Bug Bounty Standard (HackerOne / Bugcrowd):                       |
|             - CVSS v3.1 Severity Score & Vector                               |
|             - CWE & OWASP Top 10 Classification                               |
|             - Step-by-Step Reproduction Guide with Safe cURL Commands         |
|             - Sanitized Evidence (All tokens/keys redacted)                   |
|             - Business Impact & Remediation Patches                           |
|  [Report B] Enterprise Security Audit Report:                                 |
|             - Executive Posture Matrix & Severity Distribution                |
|             - Technical Root-Cause Explanations                               |
|             - Code & Web Server Fixes (Nginx, Apache, Node, Python)           |
+-------------------------------------------------------------------------------+
```

---

## 3. Implementation Details

### Step 1: Enhanced Target Normalization & Ingestion (`vulnhunter.py`)
- Automatically detects if input is a bare domain (`target.com`) or full URL (`https://target.com/page?q=test`).
- If bare domain: Automatically tests `https://` first with fallback to `http://`, handles port detection, and identifies root redirects.
- Injects target into `scopes` table with active permission.

### Step 2: Expanded Vulnerability Detection Vectors
Implement deep heuristic checks in `vulnhunter.py` (matching the full TypeScript backend):
1. **SSL/TLS & Protocol Audit**: Extracts certificate validity, issuer, and expiration date using standard `ssl.SSLSocket`.
2. **Defensive Headers Audit**: Evaluates CSP completeness, HSTS configuration, clickjacking defense (`frame-ancestors` / `DENY`), and MIME-sniffing prevention.
3. **Cookie Security Audit**: Parses all `Set-Cookie` directives, flagging missing `HttpOnly`, `Secure`, and `SameSite` attributes.
4. **Sensitive Dotfile Reconnaissance**: Probes `.env`, `.git/config`, `robots.txt`, `.DS_Store`, and `sitemap.xml` with rate-limiting and response verification.
5. **CORS Misconfiguration**: Sends crafted `Origin: https://attacker-lab.com` and verifies if `Access-Control-Allow-Origin` reflects the untrusted origin alongside `Access-Control-Allow-Credentials: true`.
6. **Reflected Canary Analysis**: Inject unique `vh_<random>` string into query parameters and checks if it reflects verbatim without HTML entity encoding.

### Step 3: Dual Report Generators
Implement two distinct reporting formats in the Python CLI and web API:
1. **Bug Bounty Submission Report (`<target>_bounty_report.md`)**:
   - Formatted specifically for submission on HackerOne or Bugcrowd.
   - Includes CVSS v3.1 calculation, CWE identifier, impact analysis, exact `curl` reproduction command, and redacted proof.
2. **Enterprise Security Audit Report (`<target>_executive_audit.md`)**:
   - Includes executive summary table, compliance breakdown, risk level charts, and web server configuration patches (Nginx/Apache snippets).

### Step 4: Unified Command Syntax
Provide one-line simplicity in Termux:
```bash
# Automatic comprehensive audit of a bare domain
python3 vulnhunter.py auto target.com

# Automatic deep audit of a specific endpoint URL
python3 vulnhunter.py auto "https://target.com/api/search?q=test"

# Explicit report format selection
python3 vulnhunter.py auto target.com --format bounty    # HackerOne style
python3 vulnhunter.py auto target.com --format enterprise # Corporate style
python3 vulnhunter.py auto target.com --format both       # Generates both reports
```

---

## 4. Testing & Verification Plan

1. **Automated Unit Testing**:
   - Run `python3 tests/test_vulnhunter.py -v` to verify scope validation, SSRF blocking, redaction, positive exposure detection, and negative control baseline (zero false positives on hardened fixture).
2. **End-to-End Real Target Verification**:
   - Run `python3 vulnhunter.py auto localhost:3000/api/lab/headers --format both`
   - Verify that:
     - Target is auto-authorized.
     - Both Stage 1 (Exposure) and Stage 2 (Deep Heuristics) execute cleanly.
     - Both `bounty_report.md` and `enterprise_audit.md` are generated with valid reproduction commands and sanitized evidence.
3. **Web Dashboard Integration**:
   - Ensure the React mobile dashboard displays the findings with filtering, status toggling, and instant download buttons.
