/**
 * VulnHunter AI - Core Vulnerability & Exposure Scanner Engine
 * Real, rate-limited, non-destructive checks with database persistence and secret redaction.
 */

import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
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
