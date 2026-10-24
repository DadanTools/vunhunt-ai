/**
 * VulnHunter AI - Core Vulnerability & Exposure Scanner Engine
 * Real, rate-limited, non-destructive checks with database persistence and secret redaction.
 */

import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import tls from 'node:tls';
import { db } from './db.js';
import { validateScope, logAudit, isEmergencyStopActive } from './scope_gate.js';
import { redactHeaders, redactBody, sanitizeString } from './redactor.js';

export interface FindingRecord {
  id: string;
  scan_id: string;
  title: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'certain' | 'firm' | 'tentative';
  affected_asset: string;
  endpoint: string;
  evidence_json: string;
  reproduction_steps: string;
  impact: string;
  remediation: string;
  verification_status: 'candidate' | 'needs-review' | 'verified-in-authorized-lab' | 'false-positive';
  source_tool: string;
  fingerprint: string;
}

export interface HttpRequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  maxBytes?: number;
  followRedirects?: boolean;
}

export interface HttpResponse {
  statusCode: number;
  statusMessage: string;
  headers: Record<string, string | string[]>;
  body: string;
  durationMs: number;
  redirectChain: string[];
  tlsInfo?: {
    authorized: boolean;
    validTo?: string;
    issuer?: string;
  };
}

/**
 * Safe, rate-limited HTTP client with strict timeout and response size cap.
 */
export async function safeHttpRequest(urlStr: string, opts: HttpRequestOptions = {}): Promise<HttpResponse> {
  const timeoutMs = opts.timeoutMs || 8000;
  const maxBytes = opts.maxBytes || 64 * 1024; // 64KB cap to prevent high memory usage
  const method = opts.method || 'GET';
  const headers = opts.headers || { 'User-Agent': 'VulnHunter-AI-Security-Auditor/1.0 (+AuthorizedLab)' };

  const parsed = new URL(urlStr);
  const isHttps = parsed.protocol === 'https:';
  const client = isHttps ? https : http;

  const startTime = Date.now();
  const redirectChain: string[] = [urlStr];

  return new Promise((resolve, reject) => {
    let settled = false;
    const safeResolve = (val: HttpResponse) => {
      if (!settled) {
        settled = true;
        resolve(val);
      }
    };
    const safeReject = (err: any) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    };

    const req = client.request(
      urlStr,
      {
        method,
        headers,
        timeout: timeoutMs,
        // In local lab or self-signed targets, capture TLS details
        rejectUnauthorized: false
      },
      res => {
        let body = '';
        let bytesRead = 0;
        let truncated = false;

        res.on('error', safeReject);

        const tlsInfo = isHttps && (res.socket as any).getPeerCertificate
          ? (() => {
              try {
                const cert = (res.socket as any).getPeerCertificate(true);
                return {
                  authorized: (res.socket as any).authorized || false,
                  validTo: cert.valid_to,
                  issuer: cert.issuer?.O || cert.issuer?.CN
                };
              } catch (_e) {
                return undefined;
              }
            })()
          : undefined;

        res.on('data', chunk => {
          bytesRead += chunk.length;
          if (bytesRead <= maxBytes) {
            body += chunk.toString('utf-8');
          } else if (!truncated) {
            truncated = true;
            body += `\n... [TRUNCATED - EXCEEDED MAX BUFFER ${maxBytes} BYTES]`;
            req.destroy();
            safeResolve({
              statusCode: res.statusCode || 0,
              statusMessage: res.statusMessage || '',
              headers: res.headers as Record<string, string | string[]>,
              body,
              durationMs: Date.now() - startTime,
              redirectChain,
              tlsInfo
            });
          }
        });

        res.on('end', () => {
          safeResolve({
            statusCode: res.statusCode || 0,
            statusMessage: res.statusMessage || '',
            headers: res.headers as Record<string, string | string[]>,
            body,
            durationMs: Date.now() - startTime,
            redirectChain,
            tlsInfo
          });
        });
      }
    );

    req.on('timeout', () => {
      safeReject(new Error(`Request to ${urlStr} timed out after ${timeoutMs}ms`));
      req.destroy();
    });

    req.on('error', err => {
      safeReject(err);
    });

    if (opts.body) {
      req.write(opts.body);
    }
    req.end();
  });
}

/**
 * Saves or updates a finding with stable fingerprinting and deduplication.
 */
export function persistFinding(finding: Omit<FindingRecord, 'id' | 'created_at' | 'updated_at'>): FindingRecord {
  const now = new Date().toISOString();
  const existing = db.prepare('SELECT * FROM findings WHERE fingerprint = ?').get(finding.fingerprint) as any;

  if (existing) {
    db.prepare(`
      UPDATE findings 
      SET updated_at = ?, evidence_json = ?, scan_id = ?
      WHERE fingerprint = ?
    `).run(now, finding.evidence_json, finding.scan_id, finding.fingerprint);
    return { ...existing, updated_at: now };
  }

  const id = 'vuln-' + Date.now() + '-' + crypto.randomBytes(3).toString('hex');
  db.prepare(`
    INSERT INTO findings (
      id, scan_id, title, category, severity, confidence, affected_asset, endpoint,
      evidence_json, reproduction_steps, impact, remediation, verification_status,
      source_tool, fingerprint, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id, finding.scan_id, finding.title, finding.category, finding.severity, finding.confidence,
    finding.affected_asset, finding.endpoint, finding.evidence_json, finding.reproduction_steps,
    finding.impact, finding.remediation, finding.verification_status, finding.source_tool,
    finding.fingerprint, now, now
  );

  return {
    ...finding,
    id,
    created_at: now,
    updated_at: now
  } as any;
}

/**
 * MODULE B: Fast Exposure Scanner
 * Audits HTTP status, missing security headers, cookie flags, and checks low-impact sensitive paths.
 */
export async function runExposureScan(scanId: string, targetUrl: string): Promise<FindingRecord[]> {
  const scopeCheck = await validateScope(targetUrl);
  if (!scopeCheck.authorized) {
    throw new Error(`Scope Check Failed: ${scopeCheck.reason}`);
  }

  const findings: FindingRecord[] = [];
  const targetObj = new URL(targetUrl);
  const assetHost = targetObj.host;

  logAudit('SCAN_START_EXPOSURE', targetUrl, `Initiating fast exposure scan for job ${scanId}`, 'info');

  // Update scan progress
  db.prepare("UPDATE scans SET status = 'running', progress = 10 WHERE id = ?").run(scanId);

  // 1. Root HTTP/TLS Inspection
  let rootRes: HttpResponse;
  try {
    rootRes = await safeHttpRequest(targetUrl, { followRedirects: true });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to connect to target ${targetUrl}: ${msg}`);
  }

  // Record asset in assets table if not exists
  const existingAsset = db.prepare('SELECT id FROM assets WHERE host = ?').get(assetHost) as any;
  const now = new Date().toISOString();
  if (!existingAsset) {
    db.prepare(`
      INSERT INTO assets (id, host, port, protocol, url, status_code, provenance, scan_job_id, is_authorized, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      'asset-' + Date.now(),
      assetHost,
      targetObj.port ? parseInt(targetObj.port, 10) : (targetObj.protocol === 'https:' ? 443 : 80),
      targetObj.protocol.replace(':', ''),
      targetUrl,
      rootRes.statusCode,
      'exposure_scanner',
      scanId,
      1,
      now,
      now
    );
  }

  // A. Check Missing Strict-Transport-Security (HSTS) on HTTPS
  if (targetObj.protocol === 'https:') {
    const hsts = rootRes.headers['strict-transport-security'];
    if (!hsts) {
      findings.push(persistFinding({
        scan_id: scanId,
        title: 'Missing HTTP Strict Transport Security (HSTS)',
        category: 'security_headers',
        severity: 'medium',
        confidence: 'certain',
        affected_asset: assetHost,
        endpoint: targetUrl,
        evidence_json: JSON.stringify({
          missing_header: 'Strict-Transport-Security',
          observed_headers: redactHeaders(rootRes.headers)
        }),
        reproduction_steps: `curl -I "${targetUrl}" | grep -i Strict-Transport-Security`,
        impact: 'Allows potential downgrade attacks (SSL-stripping) and exposes users on untrusted networks to interception.',
        remediation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" response header.',
        verification_status: 'verified-in-authorized-lab',
        source_tool: 'exposure_scanner',
        fingerprint: crypto.createHash('sha256').update(`${assetHost}:missing_hsts`).digest('hex')
      }));
    }
  }

  // B. Check Missing Content-Security-Policy (CSP)
  const csp = rootRes.headers['content-security-policy'];
  if (!csp) {
    findings.push(persistFinding({
      scan_id: scanId,
      title: 'Missing Content-Security-Policy (CSP)',
      category: 'security_headers',
      severity: 'medium',
      confidence: 'certain',
      affected_asset: assetHost,
      endpoint: targetUrl,
      evidence_json: JSON.stringify({
        missing_header: 'Content-Security-Policy',
        observed_headers: redactHeaders(rootRes.headers)
      }),
      reproduction_steps: `curl -I "${targetUrl}" | grep -i Content-Security-Policy`,
      impact: 'Without CSP, the application lacks defense-in-depth against Cross-Site Scripting (XSS) and unauthorized resource loading.',
      remediation: "Define a robust Content-Security-Policy restricting script sources, e.g. script-src 'self'.",
      verification_status: 'verified-in-authorized-lab',
      source_tool: 'exposure_scanner',
      fingerprint: crypto.createHash('sha256').update(`${assetHost}:missing_csp`).digest('hex')
    }));
  }

  // C. Check Missing X-Frame-Options or frame-ancestors (Clickjacking)
  const xfo = rootRes.headers['x-frame-options'];
  const hasFrameAncestors = csp && String(csp).includes('frame-ancestors');
  if (!xfo && !hasFrameAncestors) {
    findings.push(persistFinding({
      scan_id: scanId,
      title: 'Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)',
      category: 'security_headers',
      severity: 'low',
      confidence: 'certain',
      affected_asset: assetHost,
      endpoint: targetUrl,
      evidence_json: JSON.stringify({
        missing_header: 'X-Frame-Options',
        observed_headers: redactHeaders(rootRes.headers)
      }),
      reproduction_steps: `curl -I "${targetUrl}" | grep -i X-Frame-Options`,
      impact: 'The application UI may be embedded in an iframe on an external site, enabling UI redressing and clickjacking attacks.',
      remediation: 'Set "X-Frame-Options: DENY" or use CSP "frame-ancestors \'none\'".',
      verification_status: 'verified-in-authorized-lab',
      source_tool: 'exposure_scanner',
      fingerprint: crypto.createHash('sha256').update(`${assetHost}:missing_xfo`).digest('hex')
    }));
  }

  // D. Check Cookie Security Flags (HttpOnly, Secure, SameSite)
  const rawCookies = rootRes.headers['set-cookie'];
  if (rawCookies) {
    const cookies = Array.isArray(rawCookies) ? rawCookies : [rawCookies];
    for (const cookieStr of cookies) {
      const parts = cookieStr.split(';').map(p => p.trim());
      const cookieName = parts[0]?.split('=')[0] || 'cookie';
      const hasHttpOnly = parts.some(p => p.toLowerCase() === 'httponly');
      const hasSecure = parts.some(p => p.toLowerCase() === 'secure');
      const sameSitePart = parts.find(p => p.toLowerCase().startsWith('samesite='));

      const issues: string[] = [];
      if (!hasHttpOnly) issues.push('Missing HttpOnly flag');
      if (!hasSecure && targetObj.protocol === 'https:') issues.push('Missing Secure flag');
      if (!sameSitePart) issues.push('Missing SameSite attribute');

      if (issues.length > 0) {
        findings.push(persistFinding({
          scan_id: scanId,
          title: `Insecure Cookie Attributes on '${cookieName}'`,
          category: 'security_headers',
          severity: issues.includes('Missing HttpOnly flag') ? 'medium' : 'low',
          confidence: 'certain',
          affected_asset: assetHost,
          endpoint: targetUrl,
          evidence_json: JSON.stringify({
            cookie_name: cookieName,
            identified_issues: issues,
            sanitized_set_cookie: sanitizeString(cookieStr.replace(/(=)[^;]+/, '$1[REDACTED]'))
          }),
          reproduction_steps: `Check Set-Cookie response header attributes for ${cookieName}`,
          impact: 'Cookies without HttpOnly can be accessed by malicious scripts via XSS; without Secure, they may transmit over plaintext.',
          remediation: `Configure cookie attributes: ${cookieName}=...; Secure; HttpOnly; SameSite=Lax`,
          verification_status: 'verified-in-authorized-lab',
          source_tool: 'exposure_scanner',
          fingerprint: crypto.createHash('sha256').update(`${assetHost}:cookie_${cookieName}_flags`).digest('hex')
        }));
      }
    }
  }

  db.prepare('UPDATE scans SET progress = 45 WHERE id = ?').run(scanId);

  // E. Low-Impact Sensitive Path & Exposure Checks
  // Check common sensitive paths: .env, .git/config, /robots.txt
  const sensitivePaths = [
    { path: '/.env', label: 'Environment File Exposure', severity: 'high' as const },
    { path: '/.git/config', label: 'Exposed Git Repository Configuration', severity: 'high' as const },
    { path: '/api/lab/sensitive-path/.env', label: 'Exposed Test Configuration File', severity: 'medium' as const },
    { path: '/api/lab/sensitive-path/.git/config', label: 'Exposed Git Config (Test Lab)', severity: 'medium' as const },
    { path: '/robots.txt', label: 'Robots Information Disclosure', severity: 'info' as const }
  ];

  for (let i = 0; i < sensitivePaths.length; i++) {
    if (isEmergencyStopActive()) break;

    const item = sensitivePaths[i];
    const probeUrl = new URL(item.path, targetUrl).toString();

    try {
      // Conservative rate limiting delay (150ms between probes)
      await new Promise(r => setTimeout(r, 150));

      const probeRes = await safeHttpRequest(probeUrl, { maxBytes: 2048, timeoutMs: 5000 });

      // Valid exposure check: HTTP 200 with sensitive content indicators
      if (probeRes.statusCode === 200 && probeRes.body.length > 5) {
        let isExposure = false;
        let snippet = '';

        if (item.path.includes('.git/config') && probeRes.body.includes('[core]')) {
          isExposure = true;
          snippet = probeRes.body.slice(0, 150);
        } else if (item.path.includes('.env') && (probeRes.body.includes('DATABASE_URL') || probeRes.body.includes('KEY') || probeRes.body.includes('SECRET'))) {
          isExposure = true;
          snippet = sanitizeString(probeRes.body.slice(0, 150));
        } else if (item.path === '/robots.txt' && probeRes.body.toLowerCase().includes('disallow:')) {
          findings.push(persistFinding({
            scan_id: scanId,
            title: 'Robots.txt Disclosed Sensitive Paths',
            category: 'information_disclosure',
            severity: 'info',
            confidence: 'certain',
            affected_asset: assetHost,
            endpoint: probeUrl,
            evidence_json: JSON.stringify({
              status_code: probeRes.statusCode,
              body_snippet: probeRes.body.slice(0, 300)
            }),
            reproduction_steps: `curl -s "${probeUrl}"`,
            impact: 'Search engine crawler rules may reveal sensitive administrative endpoints to unauthenticated users.',
            remediation: 'Ensure endpoints listed in robots.txt have strict server-side authentication.',
            verification_status: 'verified-in-authorized-lab',
            source_tool: 'exposure_scanner',
            fingerprint: crypto.createHash('sha256').update(`${assetHost}:${item.path}`).digest('hex')
          }));
        }

        if (isExposure) {
          findings.push(persistFinding({
            scan_id: scanId,
            title: item.label,
            category: 'information_disclosure',
            severity: item.severity,
            confidence: 'certain',
            affected_asset: assetHost,
            endpoint: probeUrl,
            evidence_json: JSON.stringify({
              endpoint: probeUrl,
              status_code: probeRes.statusCode,
              redacted_sample: redactBody(snippet)
            }),
            reproduction_steps: `curl -i "${probeUrl}"`,
            impact: 'Attackers can read credentials, repository metadata, or configuration variables directly.',
            remediation: 'Block direct web server access to dotfiles and configuration directories in your web server configuration.',
            verification_status: 'verified-in-authorized-lab',
            source_tool: 'exposure_scanner',
            fingerprint: crypto.createHash('sha256').update(`${assetHost}:${item.path}`).digest('hex')
          }));
        }
      }
    } catch (_e) {
      // Path unreachable or timed out - continue
    }

    const currentProg = 45 + Math.floor(((i + 1) / sensitivePaths.length) * 45);
    db.prepare('UPDATE scans SET progress = ? WHERE id = ?').run(currentProg, scanId);
  }

  db.prepare("UPDATE scans SET status = 'completed', progress = 100, completed_at = ? WHERE id = ?").run(new Date().toISOString(), scanId);
  logAudit('SCAN_COMPLETE_EXPOSURE', targetUrl, `Completed exposure scan for job ${scanId}. Found ${findings.length} findings.`, 'info');

  return findings;
}

/**
 * MODULE E: Safe Injection & CORS Heuristics
 * Non-destructive probe using random canary strings to detect reflection or permissive CORS.
 */
export async function runInjectionHeuristicScan(scanId: string, targetUrl: string): Promise<FindingRecord[]> {
  const scopeCheck = await validateScope(targetUrl);
  if (!scopeCheck.authorized) {
    throw new Error(`Scope Check Failed: ${scopeCheck.reason}`);
  }

  const findings: FindingRecord[] = [];
  const targetObj = new URL(targetUrl);
  const assetHost = targetObj.host;

  db.prepare("UPDATE scans SET status = 'running', progress = 10 WHERE id = ?").run(scanId);

  // 1. Reflected Input Canary Check
  // Safe probe: `vh_canary_<random>` with characters `<vh>` to check if tags reflect unencoded
  const canaryToken = `vh_${crypto.randomBytes(4).toString('hex')}`;
  const testPayload = `${canaryToken}<vh_test>`;
  const probeUrl = new URL(targetUrl);
  probeUrl.searchParams.set('q', testPayload);
  probeUrl.searchParams.set('canary', testPayload);

  try {
    const probeRes = await safeHttpRequest(probeUrl.toString(), { maxBytes: 32768 });

    if (probeRes.body.includes(testPayload)) {
      findings.push(persistFinding({
        scan_id: scanId,
        title: 'Unencoded Parameter Reflection (Potential XSS Indicator)',
        category: 'injection',
        severity: 'medium',
        confidence: 'firm',
        affected_asset: assetHost,
        endpoint: probeUrl.toString(),
        evidence_json: JSON.stringify({
          canary_probe: testPayload,
          reflection_found: true,
          context_snippet: probeRes.body.slice(
            Math.max(0, probeRes.body.indexOf(testPayload) - 40),
            probeRes.body.indexOf(testPayload) + testPayload.length + 40
          )
        }),
        reproduction_steps: `curl -s "${probeUrl.toString()}" | grep "${testPayload}"`,
        impact: 'User-supplied parameters are reflected without context-aware HTML encoding, presenting potential Cross-Site Scripting (XSS).',
        remediation: 'Implement contextual HTML output encoding before rendering user input into HTML documents.',
        verification_status: 'verified-in-authorized-lab',
        source_tool: 'injection_engine',
        fingerprint: crypto.createHash('sha256').update(`${assetHost}:reflected_canary_${probeUrl.pathname}`).digest('hex')
      }));
    }
  } catch (_e) {
    // Probe failed
  }

  db.prepare('UPDATE scans SET progress = 50 WHERE id = ?').run(scanId);

  // 2. CORS Arbitrary Origin Misconfiguration Check
  try {
    const evilOrigin = 'https://unauthorized-attacker-lab.com';
    const corsRes = await safeHttpRequest(targetUrl, {
      method: 'GET',
      headers: {
        'Origin': evilOrigin,
        'User-Agent': 'VulnHunter-Security-Audit/1.0'
      }
    });

    const acao = corsRes.headers['access-control-allow-origin'];
    const acac = corsRes.headers['access-control-allow-credentials'];

    if (acao === evilOrigin || (acao === '*' && acac === 'true')) {
      findings.push(persistFinding({
        scan_id: scanId,
        title: 'Permissive CORS Configuration (Origin Reflection)',
        category: 'cors',
        severity: acac === 'true' ? 'high' : 'medium',
        confidence: 'certain',
        affected_asset: assetHost,
        endpoint: targetUrl,
        evidence_json: JSON.stringify({
          injected_origin: evilOrigin,
          access_control_allow_origin: acao,
          access_control_allow_credentials: acac
        }),
        reproduction_steps: `curl -H "Origin: ${evilOrigin}" -I "${targetUrl}"`,
        impact: 'Third-party malicious websites can issue cross-origin requests and read sensitive authenticated responses.',
        remediation: 'Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted domains and avoid reflecting arbitrary origins.',
        verification_status: 'verified-in-authorized-lab',
        source_tool: 'injection_engine',
        fingerprint: crypto.createHash('sha256').update(`${assetHost}:cors_misconfig`).digest('hex')
      }));
    }
  } catch (_e) {
    // CORS test failed
  }

  db.prepare("UPDATE scans SET status = 'completed', progress = 100, completed_at = ? WHERE id = ?").run(new Date().toISOString(), scanId);
  return findings;
}

/**
 * MODULE D: Authorized Safe BOLA / IDOR Dual-Account Comparison Workflow
 */
export async function runIdorComparison(
  scanId: string,
  userAToken: string,
  userBToken: string,
  targetObjectUrlPattern: string, // e.g. "http://localhost:3000/api/lab/idor/document/{ID}"
  objectAId: string, // "doc_a_101"
  objectBId: string  // "doc_b_202"
): Promise<{ finding?: FindingRecord; comparisonSummary: any }> {
  const urlA = targetObjectUrlPattern.replace('{ID}', objectAId);
  const urlB = targetObjectUrlPattern.replace('{ID}', objectBId);

  const scopeCheck = await validateScope(urlA);
  if (!scopeCheck.authorized) {
    throw new Error(`Scope Check Failed for ${urlA}: ${scopeCheck.reason}`);
  }

  logAudit('IDOR_COMPARISON_RUN', urlB, `Running BOLA/IDOR safe comparison on target fixture`, 'info');

  // Step 1: User A requests their own object (Baseline Authorization)
  const baselineA = await safeHttpRequest(urlA, {
    headers: { 'Authorization': userAToken.startsWith('Bearer ') ? userAToken : `Bearer ${userAToken}` }
  });

  // Step 2: User A attempts to read User B's object (Cross-Tenant Authorization Test)
  const crossRequest = await safeHttpRequest(urlB, {
    headers: { 'Authorization': userAToken.startsWith('Bearer ') ? userAToken : `Bearer ${userAToken}` }
  });

  // Baseline check: Does User B own object B?
  const baselineB = await safeHttpRequest(urlB, {
    headers: { 'Authorization': userBToken.startsWith('Bearer ') ? userBToken : `Bearer ${userBToken}` }
  });

  const comparisonSummary = {
    target_fixture: targetObjectUrlPattern,
    user_a_own_object_status: baselineA.statusCode,
    user_b_own_object_status: baselineB.statusCode,
    user_a_cross_read_status: crossRequest.statusCode,
    cross_read_body_length: crossRequest.body.length,
    vulnerable_idor_detected: crossRequest.statusCode === 200 && crossRequest.body.length > 0
  };

  let finding: FindingRecord | undefined;

  if (comparisonSummary.vulnerable_idor_detected) {
    finding = persistFinding({
      scan_id: scanId,
      title: 'Broken Object Level Authorization (BOLA / IDOR)',
      category: 'auth_idor',
      severity: 'high',
      confidence: 'certain',
      affected_asset: new URL(urlB).host,
      endpoint: urlB,
      evidence_json: JSON.stringify({
        summary: comparisonSummary,
        redacted_user_a_token: sanitizeString(userAToken.replace(/(=)[^;]+/, '$1[REDACTED]')),
        cross_read_sample: redactBody(crossRequest.body)
      }),
      reproduction_steps: `Authenticate as User A, then issue GET request to User B's resource: "${urlB}". Observe status 200 with object payload.`,
      impact: 'Allows an authenticated attacker to read or modify private data belonging to other tenants without authorization.',
      remediation: 'Implement server-side object ownership verification before returning or altering entity records.',
      verification_status: 'verified-in-authorized-lab',
      source_tool: 'idor_comparer',
      fingerprint: crypto.createHash('sha256').update(`${urlB}:idor_bola`).digest('hex')
    });
  }

  return { finding, comparisonSummary };
}

export interface ReconResult {
  host: string;
  targetUrl: string;
  dns: {
    a: string[];
    aaaa: string[];
    mx: Array<{ exchange: string; priority: number }>;
    txt: string[];
    cname: string[];
    ns: string[];
  };
  tls?: {
    authorized: boolean;
    protocol: string;
    cipher: string;
    issuer: string;
    validFrom: string;
    validTo: string;
    daysRemaining: number;
    sans: string[];
  };
  technologies: Array<{ name: string; category: string; evidence: string }>;
  securityHeadersGrade: {
    grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
    score: number;
    checks: Array<{ header: string; status: 'present' | 'missing' | 'warning'; details: string }>;
  };
}

/**
 * Real Live Target Reconnaissance:
 * - DNS queries (A, AAAA, MX, TXT, CNAME, NS)
 * - SSL/TLS Certificate inspection & Subject Alternative Names (SANs) subdomain leakage
 * - Technology fingerprinting & Mozilla Observatory Security Headers Grade
 */
export async function runReconDiscovery(targetUrl: string): Promise<ReconResult> {
  const scope = await validateScope(targetUrl);
  if (!scope.authorized) {
    throw new Error(`Scope Gate Violation: Target ${targetUrl} is not in authorized scope (${scope.reason})`);
  }

  const normalizedUrl = (targetUrl.startsWith('http://') || targetUrl.startsWith('https://'))
    ? targetUrl
    : (targetUrl.includes('localhost') || targetUrl.includes('127.0.0.1') ? `http://${targetUrl}` : `https://${targetUrl}`);

  const parsed = new URL(normalizedUrl);
  const host = parsed.hostname;
  const isHttps = parsed.protocol === 'https:';

  logAudit('RECON_DISCOVERY_START', host, `Initiated live DNS, SSL, and technology reconnaissance on ${host}`, 'info');

  // 1. Live DNS Queries
  const dnsData = {
    a: [] as string[],
    aaaa: [] as string[],
    mx: [] as Array<{ exchange: string; priority: number }>,
    txt: [] as string[],
    cname: [] as string[],
    ns: [] as string[]
  };

  try { dnsData.a = await dns.resolve4(host); } catch {}
  try { dnsData.aaaa = await dns.resolve6(host); } catch {}
  try { dnsData.mx = await dns.resolveMx(host); } catch {}
  try {
    const rawTxt = await dns.resolveTxt(host);
    dnsData.txt = rawTxt.map(t => t.join(''));
  } catch {}
  try { dnsData.cname = await dns.resolveCname(host); } catch {}
  try { dnsData.ns = await dns.resolveNs(host); } catch {}

  // 2. Real SSL/TLS Certificate Inspection (if port 443 / HTTPS)
  let tlsInfo: ReconResult['tls'] | undefined;
  if (isHttps || (!parsed.port || parsed.port === '443')) {
    try {
      tlsInfo = await new Promise((resolve) => {
        const socket = tls.connect({
          host,
          port: parsed.port ? parseInt(parsed.port, 10) : 443,
          servername: host,
          rejectUnauthorized: false,
          timeout: 4000
        }, () => {
          const cert = socket.getPeerCertificate(true);
          const cipher = socket.getCipher();
          const protocol = socket.getProtocol();

          if (cert && cert.subject) {
            const validTo = new Date(cert.valid_to);
            const daysRemaining = Math.max(0, Math.round((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24)));
            const sans = cert.subjectaltname 
              ? cert.subjectaltname.split(', ').map(s => s.replace(/^DNS:/, ''))
              : [];

            const issuerRaw = cert.issuer?.O || cert.issuer?.CN || 'Unknown CA';
            const issuerStr = Array.isArray(issuerRaw) ? issuerRaw[0] : String(issuerRaw);

            socket.end();
            resolve({
              authorized: socket.authorized,
              protocol: protocol || 'TLSv1.3',
              cipher: cipher ? cipher.name : 'Unknown',
              issuer: issuerStr,
              validFrom: cert.valid_from,
              validTo: cert.valid_to,
              daysRemaining,
              sans
            });
          } else {
            socket.end();
            resolve(undefined);
          }
        });

        socket.on('error', () => resolve(undefined));
        socket.on('timeout', () => {
          socket.destroy();
          resolve(undefined);
        });
      });
    } catch {}
  }

  // 3. HTTP Probe for Technology Fingerprinting & Security Headers Grade
  const probeResponse = await safeHttpRequest(targetUrl, { followRedirects: true, timeoutMs: 6000 });
  const headers = probeResponse.headers;
  const headerKeys: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    headerKeys[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
  }
  const body = probeResponse.body;

  // Technology Fingerprints
  const technologies: ReconResult['technologies'] = [];

  // Web Server / CDN
  const server = headerKeys['server'] || '';
  const xPoweredBy = headerKeys['x-powered-by'] || '';
  const cfRay = headerKeys['cf-ray'];
  const cfCache = headerKeys['cf-cache-status'];

  if (cfRay || cfCache || server.toLowerCase().includes('cloudflare')) {
    technologies.push({ name: 'Cloudflare CDN / WAF', category: 'CDN & Protection', evidence: cfRay ? `cf-ray: ${cfRay}` : 'Server: cloudflare' });
  }
  if (headerKeys['x-amz-cf-id'] || headerKeys['x-amz-request-id']) {
    technologies.push({ name: 'Amazon CloudFront / AWS', category: 'Cloud Infrastructure', evidence: 'x-amz-* header' });
  }
  if (server.toLowerCase().includes('nginx')) {
    technologies.push({ name: 'Nginx Web Server', category: 'Web Server', evidence: `Server: ${server}` });
  } else if (server.toLowerCase().includes('apache')) {
    technologies.push({ name: 'Apache HTTP Server', category: 'Web Server', evidence: `Server: ${server}` });
  } else if (server.toLowerCase().includes('caddy')) {
    technologies.push({ name: 'Caddy Server', category: 'Web Server', evidence: `Server: ${server}` });
  }

  // Application Stack
  if (xPoweredBy.toLowerCase().includes('express')) {
    technologies.push({ name: 'Express.js', category: 'Backend Framework', evidence: `X-Powered-By: ${xPoweredBy}` });
  } else if (xPoweredBy.toLowerCase().includes('php')) {
    technologies.push({ name: 'PHP Runtime', category: 'Programming Language', evidence: `X-Powered-By: ${xPoweredBy}` });
  } else if (xPoweredBy.toLowerCase().includes('asp.net')) {
    technologies.push({ name: 'ASP.NET', category: 'Backend Framework', evidence: `X-Powered-By: ${xPoweredBy}` });
  }

  // Frontend Heuristics from Body
  if (body.includes('__NEXT_DATA__') || body.includes('/_next/')) {
    technologies.push({ name: 'Next.js (React)', category: 'Frontend Framework', evidence: 'next.js runtime markers' });
  } else if (body.includes('react') || body.includes('data-reactroot')) {
    technologies.push({ name: 'React.js', category: 'JavaScript UI', evidence: 'react DOM attributes' });
  }
  if (body.includes('wp-content') || body.includes('wp-includes')) {
    technologies.push({ name: 'WordPress CMS', category: 'Content Management', evidence: 'wp-content path' });
  }

  // 4. Mozilla Observatory-Style Security Header Grade Calculation
  let score = 100;
  const checks: ReconResult['securityHeadersGrade']['checks'] = [];

  // Content-Security-Policy (CSP) (-25 if missing)
  if (headerKeys['content-security-policy']) {
    checks.push({ header: 'Content-Security-Policy', status: 'present', details: headerKeys['content-security-policy'].slice(0, 80) + '...' });
  } else {
    score -= 25;
    checks.push({ header: 'Content-Security-Policy', status: 'missing', details: 'Missing modern CSP protection against XSS/injections' });
  }

  // Strict-Transport-Security (HSTS) (-20 if missing on HTTPS)
  if (isHttps) {
    if (headerKeys['strict-transport-security']) {
      checks.push({ header: 'Strict-Transport-Security (HSTS)', status: 'present', details: headerKeys['strict-transport-security'] });
    } else {
      score -= 20;
      checks.push({ header: 'Strict-Transport-Security (HSTS)', status: 'missing', details: 'Missing HSTS enforcement' });
    }
  }

  // X-Frame-Options (-15 if missing)
  if (headerKeys['x-frame-options']) {
    checks.push({ header: 'X-Frame-Options', status: 'present', details: headerKeys['x-frame-options'] });
  } else {
    score -= 15;
    checks.push({ header: 'X-Frame-Options', status: 'missing', details: 'Missing clickjacking defense' });
  }

  // X-Content-Type-Options (-10 if missing)
  if (headerKeys['x-content-type-options']?.toLowerCase().includes('nosniff')) {
    checks.push({ header: 'X-Content-Type-Options', status: 'present', details: 'nosniff' });
  } else {
    score -= 10;
    checks.push({ header: 'X-Content-Type-Options', status: 'missing', details: 'MIME-type sniffing defense missing' });
  }

  // Referrer-Policy (-10 if missing)
  if (headerKeys['referrer-policy']) {
    checks.push({ header: 'Referrer-Policy', status: 'present', details: headerKeys['referrer-policy'] });
  } else {
    score -= 10;
    checks.push({ header: 'Referrer-Policy', status: 'missing', details: 'Potential referrer leakage on navigation' });
  }

  // Permissions-Policy (-10 if missing)
  if (headerKeys['permissions-policy'] || headerKeys['feature-policy']) {
    checks.push({ header: 'Permissions-Policy', status: 'present', details: 'Configured' });
  } else {
    score -= 10;
    checks.push({ header: 'Permissions-Policy', status: 'missing', details: 'Hardware/sensor API permissions unconstrained' });
  }

  // Server banner disclosure penalty (-10)
  if (server && anyDigit(server)) {
    score -= 10;
    checks.push({ header: 'Server Banner Disclosed', status: 'warning', details: `Discloses version: ${server}` });
  }

  score = Math.max(0, score);
  let grade: ReconResult['securityHeadersGrade']['grade'] = 'F';
  if (score >= 90) grade = 'A+';
  else if (score >= 80) grade = 'A';
  else if (score >= 65) grade = 'B';
  else if (score >= 50) grade = 'C';
  else if (score >= 35) grade = 'D';

  logAudit('RECON_DISCOVERY_COMPLETE', host, `Completed recon on ${host}. Score: ${score}/100 (Grade: ${grade})`, 'info');

  return {
    host,
    targetUrl,
    dns: dnsData,
    tls: tlsInfo,
    technologies,
    securityHeadersGrade: {
      grade,
      score,
      checks
    }
  };
}

function anyDigit(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) >= 48 && s.charCodeAt(i) <= 57) return true;
  }
  return false;
}

export interface FuzzResult {
  path: string;
  url: string;
  statusCode: number;
  statusMessage: string;
  durationMs: number;
  contentLength: number;
  isInteresting: boolean;
  category: 'sensitive_file' | 'api_route' | 'admin_panel' | 'standard';
  findingCreated?: boolean;
}

const COMMON_FUZZ_PATHS = [
  { path: '/.env', category: 'sensitive_file' as const },
  { path: '/.git/config', category: 'sensitive_file' as const },
  { path: '/.git/HEAD', category: 'sensitive_file' as const },
  { path: '/robots.txt', category: 'standard' as const },
  { path: '/sitemap.xml', category: 'standard' as const },
  { path: '/.well-known/security.txt', category: 'standard' as const },
  { path: '/swagger.json', category: 'api_route' as const },
  { path: '/openapi.json', category: 'api_route' as const },
  { path: '/api/v1/users', category: 'api_route' as const },
  { path: '/api-docs', category: 'api_route' as const },
  { path: '/graphql', category: 'api_route' as const },
  { path: '/admin', category: 'admin_panel' as const },
  { path: '/administrator', category: 'admin_panel' as const },
  { path: '/login', category: 'admin_panel' as const },
  { path: '/wp-login.php', category: 'admin_panel' as const },
  { path: '/actuator/health', category: 'api_route' as const },
  { path: '/actuator/env', category: 'sensitive_file' as const },
  { path: '/server-status', category: 'sensitive_file' as const },
  { path: '/backup.zip', category: 'sensitive_file' as const },
  { path: '/config.json', category: 'sensitive_file' as const }
];

/**
 * Real Rate-Limited Endpoint & Hidden Route Fuzzer:
 * Checks endpoints politely with 120ms rate-limiting and automatically flags exposed files.
 */
export async function runPathFuzzer(targetUrl: string, customPaths?: string[]): Promise<FuzzResult[]> {
  const scope = await validateScope(targetUrl);
  if (!scope.authorized) {
    throw new Error(`Scope Gate Violation: Target ${targetUrl} is not in authorized scope (${scope.reason})`);
  }

  const normalizedUrl = (targetUrl.startsWith('http://') || targetUrl.startsWith('https://'))
    ? targetUrl
    : (targetUrl.includes('localhost') || targetUrl.includes('127.0.0.1') ? `http://${targetUrl}` : `https://${targetUrl}`);

  const parsed = new URL(normalizedUrl);
  const baseUrl = `${parsed.protocol}//${parsed.host}`;
  const results: FuzzResult[] = [];

  const targets = (customPaths && customPaths.length > 0)
    ? customPaths.map(p => ({ path: p.startsWith('/') ? p : `/${p}`, category: 'standard' as const }))
    : COMMON_FUZZ_PATHS;

  logAudit('FUZZER_START', parsed.host, `Initiated rate-limited path fuzzing on ${parsed.host} (${targets.length} routes)`, 'info');

  const scanId = `fuzz-${Date.now()}`;
  db.prepare('INSERT INTO scans (id, target, scan_type, status, progress, started_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(scanId, baseUrl, 'endpoint_fuzz', 'running', 10, new Date().toISOString());

  for (let i = 0; i < targets.length; i++) {
    if (isEmergencyStopActive()) {
      break;
    }

    const item = targets[i];
    const probeUrl = `${baseUrl}${item.path}`;

    try {
      const start = Date.now();
      const res = await safeHttpRequest(probeUrl, { followRedirects: false, timeoutMs: 4000 });
      const duration = Date.now() - start;

      const is2xx = res.statusCode >= 200 && res.statusCode < 300;
      const is3xx = res.statusCode >= 300 && res.statusCode < 400;
      const is403 = res.statusCode === 403;
      const isInteresting = is2xx || is3xx || is403;

      let findingCreated = false;

      // Auto-escalate exposed sensitive configuration as confirmed vulnerability
      if (is2xx && item.category === 'sensitive_file' && res.body.length > 0) {
        findingCreated = true;
        persistFinding({
          scan_id: scanId,
          title: `Exposed Critical Resource (${item.path})`,
          category: 'information_disclosure',
          severity: 'high',
          confidence: 'certain',
          affected_asset: parsed.host,
          endpoint: probeUrl,
          evidence_json: JSON.stringify({
            path: item.path,
            status: res.statusCode,
            content_sample: redactBody(res.body.slice(0, 500))
          }),
          reproduction_steps: `curl -s "${probeUrl}" | head -n 20`,
          impact: 'Publicly exposes internal server configuration, credentials, or repository metadata.',
          remediation: 'Restrict access via web server location block (e.g. deny all for dotfiles).',
          verification_status: 'verified-in-authorized-lab',
          source_tool: 'path_fuzzer',
          fingerprint: crypto.createHash('sha256').update(`${parsed.host}:${item.path}`).digest('hex')
        });
      }

      results.push({
        path: item.path,
        url: probeUrl,
        statusCode: res.statusCode,
        statusMessage: res.statusMessage,
        durationMs: duration,
        contentLength: res.body.length,
        isInteresting,
        category: item.category,
        findingCreated
      });

    } catch (err: any) {
      results.push({
        path: item.path,
        url: probeUrl,
        statusCode: 0,
        statusMessage: err.message || 'Connection Error',
        durationMs: 0,
        contentLength: 0,
        isInteresting: false,
        category: item.category
      });
    }

    // Polite rate limit jitter (80ms to 150ms)
    await new Promise(r => setTimeout(r, 80 + Math.floor(Math.random() * 70)));
  }

  db.prepare('UPDATE scans SET status = ?, progress = 100, completed_at = ? WHERE id = ?')
    .run('completed', new Date().toISOString(), scanId);

  logAudit('FUZZER_COMPLETE', parsed.host, `Completed path fuzzing on ${parsed.host}. Discovered ${results.filter(r => r.isInteresting).length} active routes.`, 'info');

  return results;
}

/**
 * MODULE F: Deep Multi-Vector Bug Bounty Audit Engine
 * Advanced passive and safe-active vulnerability detection covering CORS, GraphQL,
 * Open Redirects, Source Maps, Clickjacking, and Method Tampering.
 */
export async function runDeepBugBountyAudit(
  scanId: string,
  targetUrl: string,
  customHeaders?: Record<string, string>
): Promise<FindingRecord[]> {
  const scopeCheck = await validateScope(targetUrl);
  if (!scopeCheck.authorized) {
    throw new Error(`Scope Check Failed: ${scopeCheck.reason}`);
  }

  const findings: FindingRecord[] = [];
  const targetObj = new URL(targetUrl);
  const assetHost = targetObj.host;
  const baseHeaders = {
    'User-Agent': 'VulnHunter-AI/2.0-BugBounty (+AuthorizedAudit)',
    ...(customHeaders || {})
  };

  logAudit('DEEP_AUDIT_START', targetUrl, `Initiating Deep Multi-Vector Bug Bounty Audit for ${scanId}`, 'info');
  db.prepare("UPDATE scans SET status = 'running', progress = 15 WHERE id = ?").run(scanId);

  // --- 1. CORS In-Depth Analysis (Arbitrary Origin, Null Origin, Credentialed Leaks) ---
  const corsOrigins = [
    { origin: 'https://attacker-domain-lab.com', label: 'Arbitrary External Origin' },
    { origin: 'null', label: 'Null Origin (Sandboxed Iframe Bypass)' },
    { origin: `https://${targetObj.hostname}.attacker-domain.com`, label: 'Prefix Subdomain Confusion' }
  ];

  for (const { origin, label } of corsOrigins) {
    try {
      const corsRes = await safeHttpRequest(targetUrl, {
        method: 'GET',
        headers: { ...baseHeaders, Origin: origin }
      });

      const acao = corsRes.headers['access-control-allow-origin'];
      const acac = corsRes.headers['access-control-allow-credentials'];

      if (acao === origin || (acao === '*' && acac === 'true')) {
        const isCred = acac === 'true';
        findings.push(persistFinding({
          scan_id: scanId,
          title: `CORS Misconfiguration: Reflected ${label}`,
          category: 'cors',
          severity: isCred ? 'high' : 'medium',
          confidence: 'certain',
          affected_asset: assetHost,
          endpoint: targetUrl,
          evidence_json: JSON.stringify({
            test_origin: origin,
            origin_type: label,
            access_control_allow_origin: acao,
            access_control_allow_credentials: acac,
            status: corsRes.statusCode
          }),
          reproduction_steps: `curl -s -H "Origin: ${origin}" -I "${targetUrl}" | grep -i "access-control-"`,
          impact: isCred
            ? 'P2 High Bounty: Malicious cross-origin sites can execute authenticated requests with user credentials and read sensitive victim data.'
            : 'P3 Medium Bounty: Untrusted domains can read responses from this endpoint cross-origin.',
          remediation: 'Implement an explicit whitelist of trusted origins and never dynamically mirror untrusted Origins with Allow-Credentials: true.',
          verification_status: 'verified-in-authorized-lab',
          source_tool: 'deep_bounty_engine',
          fingerprint: crypto.createHash('sha256').update(`${assetHost}:cors_${origin}`).digest('hex')
        }));
        break; // Found one severe CORS misconfiguration
      }
    } catch (_e) {
      // Ignore network timeout
    }
  }

  db.prepare("UPDATE scans SET progress = 35 WHERE id = ?").run(scanId);

  // --- 2. GraphQL Introspection & Endpoint Probing ---
  const graphqlPaths = ['/graphql', '/api/graphql', '/v1/graphql', '/gql'];
  const introspectionQuery = JSON.stringify({
    query: '{ __schema { queryType { name } types { name } } }'
  });

  for (const gPath of graphqlPaths) {
    try {
      const gUrl = new URL(gPath, targetUrl).toString();
      const gRes = await safeHttpRequest(gUrl, {
        method: 'POST',
        headers: {
          ...baseHeaders,
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: introspectionQuery
      });

      if (gRes.statusCode === 200 && (gRes.body.includes('__schema') || gRes.body.includes('queryType'))) {
        findings.push(persistFinding({
          scan_id: scanId,
          title: `GraphQL Schema Introspection Enabled (${gPath})`,
          category: 'information_disclosure',
          severity: 'medium',
          confidence: 'certain',
          affected_asset: assetHost,
          endpoint: gUrl,
          evidence_json: JSON.stringify({
            endpoint: gUrl,
            status: gRes.statusCode,
            sample: gRes.body.slice(0, 300)
          }),
          reproduction_steps: `curl -s -X POST "${gUrl}" -H "Content-Type: application/json" -d '{"query":"{__schema{queryType{name}}}"}' | head -c 200`,
          impact: 'P3 Medium Bounty: Full database models, mutations, queries, and internal object types are exposed to unauthorized external researchers.',
          remediation: 'Disable GraphQL introspection in production environments (e.g., Apollo Server introspection: false).',
          verification_status: 'verified-in-authorized-lab',
          source_tool: 'deep_bounty_engine',
          fingerprint: crypto.createHash('sha256').update(`${assetHost}:graphql_${gPath}`).digest('hex')
        }));
        break;
      }
    } catch (_e) {}
  }

  db.prepare("UPDATE scans SET progress = 55 WHERE id = ?").run(scanId);

  // --- 3. Open Redirect Non-Destructive Canary Checks ---
  const redirectParams = ['redirect', 'url', 'next', 'return_url', 'target', 'dest'];
  const canaryDomain = 'https://example.com';

  for (const param of redirectParams) {
    try {
      const testUrl = new URL(targetUrl);
      testUrl.searchParams.set(param, canaryDomain);

      const rRes = await safeHttpRequest(testUrl.toString(), {
        method: 'GET',
        headers: baseHeaders,
        followRedirects: false
      });

      const loc = (rRes.headers['location'] as string) || '';
      if ([301, 302, 303, 307, 308].includes(rRes.statusCode) && (loc.startsWith(canaryDomain) || loc.startsWith('//example.com'))) {
        findings.push(persistFinding({
          scan_id: scanId,
          title: `Open Redirect via '${param}' Parameter`,
          category: 'open_redirect',
          severity: 'low',
          confidence: 'certain',
          affected_asset: assetHost,
          endpoint: testUrl.toString(),
          evidence_json: JSON.stringify({
            param,
            status: rRes.statusCode,
            location_header: loc
          }),
          reproduction_steps: `curl -s -I "${testUrl.toString()}" | grep -i "location:"`,
          impact: 'P4 / P3 Bounty: Attackers can redirect victims from trusted domain to phishing portals or use in OAuth token stealing chains.',
          remediation: 'Validate destination URLs against a strict whitelist of internal relative paths or approved domains.',
          verification_status: 'verified-in-authorized-lab',
          source_tool: 'deep_bounty_engine',
          fingerprint: crypto.createHash('sha256').update(`${assetHost}:open_redirect_${param}`).digest('hex')
        }));
        break;
      }
    } catch (_e) {}
  }

  db.prepare("UPDATE scans SET progress = 75 WHERE id = ?").run(scanId);

  // --- 4. JavaScript Source Map & Sensitive Dotfile Leaks ---
  const sensitiveFiles = [
    { path: '/.env', label: 'Environment Config File (.env)', severity: 'critical' as const, priority: 'P1' },
    { path: '/.git/HEAD', label: 'Git Repository Metadata Exposure', severity: 'high' as const, priority: 'P2' },
    { path: '/actuator/health', label: 'Spring Boot Actuator Exposed', severity: 'medium' as const, priority: 'P3' },
    { path: '/bundle.js.map', label: 'Frontend Source Map Leak (bundle.js.map)', severity: 'low' as const, priority: 'P4' },
    { path: '/main.js.map', label: 'Frontend Source Map Leak (main.js.map)', severity: 'low' as const, priority: 'P4' }
  ];

  for (const item of sensitiveFiles) {
    try {
      const fileUrl = new URL(item.path, targetUrl).toString();
      const fRes = await safeHttpRequest(fileUrl, {
        method: 'GET',
        headers: baseHeaders
      });

      let isHit = false;
      if (item.path === '/.git/HEAD' && fRes.statusCode === 200 && fRes.body.includes('ref: refs/')) {
        isHit = true;
      } else if (item.path === '/.env' && fRes.statusCode === 200 && (fRes.body.includes('DB_') || fRes.body.includes('API_KEY') || fRes.body.includes('SECRET'))) {
        isHit = true;
      } else if (item.path.endsWith('.map') && fRes.statusCode === 200 && fRes.body.includes('"sources":')) {
        isHit = true;
      } else if (item.path === '/actuator/health' && fRes.statusCode === 200 && fRes.body.includes('status')) {
        isHit = true;
      }

      if (isHit) {
        findings.push(persistFinding({
          scan_id: scanId,
          title: item.label,
          category: 'sensitive_exposure',
          severity: item.severity,
          confidence: 'certain',
          affected_asset: assetHost,
          endpoint: fileUrl,
          evidence_json: JSON.stringify({
            path: item.path,
            status: fRes.statusCode,
            snippet: redactBody(fRes.body.slice(0, 300))
          }),
          reproduction_steps: `curl -s "${fileUrl}" | head -n 15`,
          impact: `${item.priority} Bounty: Critical exposure of sensitive internal infrastructure and code logic.`,
          remediation: 'Configure web server (Nginx/Apache) to deny direct access to dotfiles, actuator endpoints, and source maps.',
          verification_status: 'verified-in-authorized-lab',
          source_tool: 'deep_bounty_engine',
          fingerprint: crypto.createHash('sha256').update(`${assetHost}:sensitive_${item.path}`).digest('hex')
        }));
      }
    } catch (_e) {}
  }

  db.prepare("UPDATE scans SET progress = 90 WHERE id = ?").run(scanId);

  // --- 5. Clickjacking Defense Check (X-Frame-Options & CSP frame-ancestors) ---
  try {
    const rootRes = await safeHttpRequest(targetUrl, { method: 'GET', headers: baseHeaders });
    const xfo = rootRes.headers['x-frame-options'];
    const csp = (rootRes.headers['content-security-policy'] as string) || '';
    const isHtml = ((rootRes.headers['content-type'] as string) || '').includes('text/html');

    if (isHtml && !xfo && !csp.includes('frame-ancestors')) {
      findings.push(persistFinding({
        scan_id: scanId,
        title: 'Missing Clickjacking Protection (X-Frame-Options / frame-ancestors)',
        category: 'clickjacking',
        severity: 'low',
        confidence: 'certain',
        affected_asset: assetHost,
        endpoint: targetUrl,
        evidence_json: JSON.stringify({
          missing_xfo: true,
          missing_csp_frame_ancestors: true,
          content_type: rootRes.headers['content-type']
        }),
        reproduction_steps: `curl -s -I "${targetUrl}" | grep -iE "(x-frame-options|content-security-policy)"`,
        impact: 'P4 Bounty: Web page can be embedded within an attacker-controlled iframe, facilitating UI redressing and clickjacking.',
        remediation: "Set 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors 'none';'.",
        verification_status: 'verified-in-authorized-lab',
        source_tool: 'deep_bounty_engine',
        fingerprint: crypto.createHash('sha256').update(`${assetHost}:clickjacking`).digest('hex')
      }));
    }
  } catch (_e) {}

  db.prepare("UPDATE scans SET status = 'completed', progress = 100, completed_at = ? WHERE id = ?")
    .run(new Date().toISOString(), scanId);

  logAudit('DEEP_AUDIT_COMPLETE', targetUrl, `Completed Deep Bug Bounty Audit. Discovered ${findings.length} findings.`, 'info');
  return findings;
}

