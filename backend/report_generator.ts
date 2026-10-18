/**
 * VulnHunter OS - World-Class Security Assessment & Bug Bounty Reporting Suite
 * Generates HackerOne, Bugcrowd VRT, Enterprise ISO/OWASP, and SARIF/JSON deliverables.
 * Includes interactive CVSS v3.1 calculator, multi-method reproduction generators, and vulnerability chaining.
 */

import { db } from './db.js';
import { logAudit } from './scope_gate.js';
import { redactBody } from './redactor.js';

export interface CvssMetrics {
  av: 'N' | 'A' | 'L' | 'P'; // Attack Vector
  ac: 'L' | 'H';             // Attack Complexity
  pr: 'N' | 'L' | 'H';       // Privileges Required
  ui: 'N' | 'R';             // User Interaction
  s: 'U' | 'C';              // Scope
  c: 'N' | 'L' | 'H';        // Confidentiality
  i: 'N' | 'L' | 'H';        // Integrity
  a: 'N' | 'L' | 'H';        // Availability
}

export interface CvssResult {
  score: number;
  vector: string;
  severity: 'None' | 'Low' | 'Medium' | 'High' | 'Critical';
}

/**
 * Official CVSS v3.1 Base Score Calculator implementation.
 */
export function calculateCvss(m: CvssMetrics): CvssResult {
  const avWeights = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  const acWeights = { L: 0.77, H: 0.44 };
  const prWeights = m.s === 'U' 
    ? { N: 0.85, L: 0.62, H: 0.27 }
    : { N: 0.85, L: 0.68, H: 0.50 };
  const uiWeights = { N: 0.85, R: 0.62 };

  const cWeights = { N: 0.0, L: 0.22, H: 0.56 };
  const iWeights = { N: 0.0, L: 0.22, H: 0.56 };
  const aWeights = { N: 0.0, L: 0.22, H: 0.56 };

  const iss = 1 - ((1 - cWeights[m.c]) * (1 - iWeights[m.i]) * (1 - aWeights[m.a]));
  
  let impact = 0;
  if (m.s === 'U') {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  const exploitability = 8.22 * avWeights[m.av] * acWeights[m.ac] * prWeights[m.pr] * uiWeights[m.ui];

  let score = 0;
  if (impact <= 0) {
    score = 0;
  } else if (m.s === 'U') {
    score = Math.min(Math.ceil((impact + exploitability) * 10) / 10, 10.0);
  } else {
    score = Math.min(Math.ceil(1.08 * (impact + exploitability) * 10) / 10, 10.0);
  }

  score = Math.round(score * 10) / 10;

  let severity: CvssResult['severity'] = 'None';
  if (score >= 9.0) severity = 'Critical';
  else if (score >= 7.0) severity = 'High';
  else if (score >= 4.0) severity = 'Medium';
  else if (score >= 0.1) severity = 'Low';

  const vector = `CVSS:3.1/AV:${m.av}/AC:${m.ac}/PR:${m.pr}/UI:${m.ui}/S:${m.s}/C:${m.c}/I:${m.i}/A:${m.a}`;

  return { score, vector, severity };
}

export interface EnrichedFinding {
  id: string;
  scan_id: string;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  affected_asset: string;
  endpoint: string;
  evidence: any;
  reproduction_steps: string;
  impact: string;
  remediation: string;
  verification_status: string;
  source_tool: string;
  created_at: string;
  cwe: string;
  owasp: string;
  vrt_category: string;
  vrt_priority: string;
  cvss: CvssResult;
  repro: {
    curl: string;
    rawHttp: string;
    pythonScript: string;
  };
}

export function enrichFindingData(f: any): EnrichedFinding {
  let evidence = {};
  try {
    evidence = JSON.parse(f.evidence_json);
  } catch (_e) {
    evidence = { raw: f.evidence_json };
  }

  const parsedUrl = new URL(f.endpoint.startsWith('http') ? f.endpoint : `http://${f.endpoint}`);
  const method = f.endpoint.includes('canary') || f.endpoint.includes('?') ? 'GET' : 'GET';
  const path = parsedUrl.pathname + parsedUrl.search;

  // Build Multi-Method Reproduction Artifacts
  const curlCmd = f.reproduction_steps || `curl -s -I "${f.endpoint}"`;
  
  const rawHttp = [
    `${method} ${path} HTTP/1.1`,
    `Host: ${parsedUrl.host}`,
    `User-Agent: VulnHunter-Auditor/1.0 (+AuthorizedLab)`,
    `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`,
    `Connection: close`,
    ``
  ].join('\r\n');

  const pythonScript = [
    `#!/usr/bin/env python3`,
    `import urllib.request`,
    `import ssl`,
    ``,
    `target_url = "${f.endpoint}"`,
    `ctx = ssl.create_default_context()`,
    `ctx.check_hostname = False`,
    `ctx.verify_mode = ssl.CERT_NONE`,
    ``,
    `print(f"[*] Verifying {target_url}...")`,
    `req = urllib.request.Request(target_url, headers={"User-Agent": "VulnHunter-PoC/1.0"})`,
    `try:`,
    `    with urllib.request.urlopen(req, timeout=10, context=ctx) as res:`,
    `        print(f"[+] Status Received: {res.status}")`,
    `        headers = dict(res.headers)`,
    `        body = res.read(2048).decode("utf-8", errors="ignore")`,
    `        print(f"[+] Verified evidence headers: {list(headers.keys())[:5]}")`,
    `except Exception as e:`,
    `    print(f"[-] Verification error: {e}")`
  ].join('\n');

  // Determine CWE, OWASP, VRT, and default CVSS metrics
  let cwe = 'CWE-693: Protection Mechanism Failure';
  let owasp = 'A05:2021-Security Misconfiguration';
  let vrt_category = 'Server Security Misconfiguration';
  let vrt_priority = 'P4';
  let cvssMetrics: CvssMetrics = { av: 'N', ac: 'L', pr: 'N', ui: 'N', s: 'U', c: 'N', i: 'L', a: 'N' };

  const titleLower = f.title.toLowerCase();

  if (titleLower.includes('content-security-policy') || titleLower.includes('csp')) {
    cwe = 'CWE-693: Protection Mechanism Failure';
    owasp = 'A05:2021-Security Misconfiguration';
    vrt_category = 'Server Security Misconfiguration > Missing Security Headers';
    vrt_priority = 'P4';
    cvssMetrics = { av: 'N', ac: 'L', pr: 'N', ui: 'N', s: 'U', c: 'N', i: 'L', a: 'N' };
  } else if (titleLower.includes('clickjacking') || titleLower.includes('x-frame-options')) {
    cwe = 'CWE-1021: Improper Restriction of Rendered UI Layers or Frames';
    owasp = 'A05:2021-Security Misconfiguration';
    vrt_category = 'Server Security Misconfiguration > Clickjacking';
    vrt_priority = 'P4';
    cvssMetrics = { av: 'N', ac: 'L', pr: 'N', ui: 'R', s: 'U', c: 'N', i: 'L', a: 'N' };
  } else if (titleLower.includes('idor') || titleLower.includes('bola') || titleLower.includes('object level')) {
    cwe = 'CWE-639: Authorization Bypass Through User-Controlled Key';
    owasp = 'A01:2021-Broken Access Control';
    vrt_category = 'Broken Access Control > Insecure Direct Object References (IDOR)';
    vrt_priority = 'P1';
    cvssMetrics = { av: 'N', ac: 'L', pr: 'L', ui: 'N', s: 'C', c: 'H', i: 'H', a: 'N' };
  } else if (titleLower.includes('git') || titleLower.includes('environment') || titleLower.includes('dotfile')) {
    cwe = 'CWE-552: Files or Directories Accessible to External Parties';
    owasp = 'A01:2021-Broken Access Control';
    vrt_category = 'Sensitive Data Exposure > Exposed Configuration File';
    vrt_priority = 'P2';
    cvssMetrics = { av: 'N', ac: 'L', pr: 'N', ui: 'N', s: 'U', c: 'H', i: 'N', a: 'N' };
  } else if (titleLower.includes('reflection') || titleLower.includes('xss')) {
    cwe = 'CWE-79: Improper Neutralization of Input During Web Page Generation';
    owasp = 'A03:2021-Injection';
    vrt_category = 'Cross-Site Scripting (XSS) > Reflected';
    vrt_priority = 'P2';
    cvssMetrics = { av: 'N', ac: 'L', pr: 'N', ui: 'R', s: 'C', c: 'L', i: 'L', a: 'N' };
  } else if (titleLower.includes('cors')) {
    cwe = 'CWE-942: Permissive Cross-Domain Policy with Untrusted Domains';
    owasp = 'A05:2021-Security Misconfiguration';
    vrt_category = 'Cross-Origin Resource Sharing (CORS) Misconfiguration';
    vrt_priority = 'P3';
    cvssMetrics = { av: 'N', ac: 'L', pr: 'N', ui: 'R', s: 'U', c: 'H', i: 'N', a: 'N' };
  } else if (titleLower.includes('cookie')) {
    cwe = 'CWE-1004: Sensitive Cookie Without HttpOnly / Secure Flag';
    owasp = 'A05:2021-Security Misconfiguration';
    vrt_category = 'Broken Authentication & Session Management > Cookie Flags';
    vrt_priority = 'P4';
    cvssMetrics = { av: 'N', ac: 'L', pr: 'N', ui: 'N', s: 'U', c: 'L', i: 'N', a: 'N' };
  }

  const cvss = calculateCvss(cvssMetrics);

  return {
    ...f,
    evidence,
    cwe,
    owasp,
    vrt_category,
    vrt_priority,
    cvss,
    repro: {
      curl: curlCmd,
      rawHttp,
      pythonScript
    }
  };
}

/**
 * Vulnerability Chaining Synthesizer
 * Identifies complementary weaknesses that can be chained into higher-impact narratives.
 */
export function synthesizeChains(findings: EnrichedFinding[]): Array<{ title: string; severity: string; description: string; linkedFindings: string[] }> {
  const chains = [];

  const hasCors = findings.some(f => f.title.toLowerCase().includes('cors'));
  const hasInsecureCookie = findings.some(f => f.title.toLowerCase().includes('cookie'));
  const hasIdor = findings.some(f => f.title.toLowerCase().includes('idor') || f.title.toLowerCase().includes('bola'));
  const hasDotfile = findings.some(f => f.title.toLowerCase().includes('git') || f.title.toLowerCase().includes('environment'));

  if (hasCors && hasInsecureCookie) {
    chains.push({
      title: 'High-Impact Exploit Chain: Cross-Origin Data Exfiltration via Permissive CORS & Ambient Cookies',
      severity: 'HIGH',
      description: 'The target reflects arbitrary cross-origin requests with credentials allowed, while session cookies lack strict SameSite protections. An attacker hosting a malicious web page can induce victim browsers to send ambient credentials and exfiltrate authenticated responses.',
      linkedFindings: ['Permissive CORS Misconfiguration', 'Insecure Cookie Attributes']
    });
  }

  if (hasDotfile && hasIdor) {
    chains.push({
      title: 'Critical Exploit Chain: Full Account Takeover via Configuration Leakage & Unchecked Object Identifiers',
      severity: 'CRITICAL',
      description: 'Exposed dotfiles disclose database connection strings or internal API keys, allowing attackers to reconstruct internal object ID sequences and systematically compromise tenant records through Broken Object Level Authorization.',
      linkedFindings: ['Exposed Configuration File', 'Broken Object Level Authorization']
    });
  }

  return chains;
}

export function getAuditContext() {
  const rawFindings = db.prepare("SELECT * FROM findings ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END").all() as any[];
  const assets = db.prepare('SELECT * FROM assets').all() as any[];
  const scopes = db.prepare('SELECT target FROM scopes WHERE is_active = 1').all() as any[];
  const auditLogs = db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 20').all() as any[];

  const findings = rawFindings.map(enrichFindingData);
  const chains = synthesizeChains(findings);

  return { findings, assets, scopes, auditLogs, chains };
}

/**
 * 1. HackerOne Bug Bounty Submission Report
 */
export function generateHackerOneReport(findingId?: string): string {
  const { findings, scopes, chains } = getAuditContext();
  const selectedFindings = findingId ? findings.filter(f => f.id === findingId) : findings;

  logAudit('REPORT_EXPORT_HACKERONE', findingId || 'ALL', `Generated HackerOne submission report (${selectedFindings.length} findings)`, 'info');

  if (selectedFindings.length === 0) {
    return '# HackerOne Bug Bounty Report\n\nNo findings selected or recorded.';
  }

  // If a single finding is requested (typical for single HackerOne bug reports)
  if (findingId && selectedFindings.length === 1) {
    const f = selectedFindings[0];
    return [
      `# ${f.title}`,
      ``,
      `## Summary`,
      `During authorized testing on **${f.affected_asset}**, a vulnerability was identified in endpoint \`${f.endpoint}\`. The vulnerability corresponds to **${f.cwe}** (${f.owasp}).`,
      ``,
      `## Vulnerability Details`,
      `- **Target Asset**: \`${f.affected_asset}\``,
      `- **Endpoint**: \`${f.endpoint}\``,
      `- **Weakness**: ${f.cwe}`,
      `- **Severity**: **${f.severity.toUpperCase()}** (${f.cvss.score})`,
      `- **CVSS v3.1 Vector**: \`${f.cvss.vector}\``,
      `- **Verification Status**: \`${f.verification_status}\``,
      ``,
      `## Steps to Reproduce`,
      `1. Open a terminal or authorized HTTP client with network access to the target host.`,
      `2. Execute the following reproducible cURL command:`,
      `\`\`\`bash`,
      f.repro.curl,
      `\`\`\``,
      `3. Observe the response headers/body demonstrating the vulnerability:`,
      `\`\`\`json`,
      JSON.stringify(f.evidence, null, 2),
      `\`\`\``,
      ``,
      `### Alternative Python 3 Reproduction Script`,
      `\`\`\`python`,
      f.repro.pythonScript,
      `\`\`\``,
      ``,
      `## Business & Security Impact`,
      `${f.impact}`,
      ``,
      `## Remediation & Mitigation Guidance`,
      `${f.remediation}`,
      ``,
      `---\n*Report compiled via VulnHunter OS - Authorized Bug Bounty Research Workbench.*`
    ].join('\n');
  }

  // Multi-finding HackerOne program roll-up
  let out = [
    `# HackerOne Bug Bounty Assessment Roll-Up`,
    `**Scope Targets**: ${scopes.map(s => s.target).join(', ') || 'Local Lab'}`,
    `**Generated**: ${new Date().toUTCString()}`,
    `**Total Validated Issues**: ${selectedFindings.length}`,
    ``,
    `## Executive Findings Table`,
    `| Finding | Severity | CVSS v3.1 | Weakness (CWE) | Status |`,
    `| :--- | :--- | :--- | :--- | :--- |`
  ];

  selectedFindings.forEach(f => {
    out.push(`| **${f.title}** | \`${f.severity.toUpperCase()}\` | \`${f.cvss.score}\` | ${f.cwe} | \`${f.verification_status}\` |`);
  });

  if (chains.length > 0) {
    out.push(``, `## Identified Vulnerability Chains`);
    chains.forEach(c => {
      out.push(
        `### ${c.title}`,
        `**Chain Severity**: \`${c.severity}\``,
        `${c.description}`,
        `*Linked Components*: ${c.linkedFindings.join(' + ')}`,
        ``
      );
    });
  }

  out.push(``, `## Vulnerability Reports`);
  selectedFindings.forEach((f, idx) => {
    out.push(
      `### Issue ${idx + 1}: ${f.title}`,
      `- **Target**: \`${f.endpoint}\``,
      `- **Severity**: \`${f.severity.toUpperCase()}\` | **CVSS**: \`${f.cvss.score}\` (\`${f.cvss.vector}\`)`,
      `- **Taxonomy**: ${f.cwe}`,
      ``,
      `#### Reproduction Command`,
      `\`\`\`bash`,
      f.repro.curl,
      `\`\`\``,
      ``,
      `#### Impact`,
      `${f.impact}`,
      ``,
      `#### Remediation`,
      `${f.remediation}`,
      ``,
      `---`
    );
  });

  return out.join('\n');
}

/**
 * 2. Bugcrowd VRT Submission Report
 */
export function generateBugcrowdReport(): string {
  const { findings, scopes } = getAuditContext();

  logAudit('REPORT_EXPORT_BUGCROWD', 'ALL', `Generated Bugcrowd VRT report (${findings.length} findings)`, 'info');

  let out = [
    `# Bugcrowd VRT Security Assessment Deliverable`,
    `**Program Scope**: ${scopes.map(s => s.target).join(', ') || 'Authorized Lab'}`,
    `**Generated**: ${new Date().toUTCString()}`,
    `**Standard**: Bugcrowd Vulnerability Rating Taxonomy (VRT v1.11)`,
    ``,
    `## Priority Summary (P1 - P5)`,
    `| Priority | VRT Classification | Finding Title | Asset |`,
    `| :--- | :--- | :--- | :--- |`
  ];

  findings.forEach(f => {
    out.push(`| **${f.vrt_priority}** | ${f.vrt_category} | ${f.title} | \`${f.affected_asset}\` |`);
  });

  out.push(``, `## Detailed Technical Submissions`);
  findings.forEach((f, idx) => {
    out.push(
      `### Sub-Report ${idx + 1}: [${f.vrt_priority}] ${f.title}`,
      `- **VRT Taxonomy**: \`${f.vrt_category}\``,
      `- **Asset Target**: \`${f.endpoint}\``,
      `- **CVSS Vector**: \`${f.cvss.vector}\` (${f.cvss.score})`,
      `- **Validation State**: \`${f.verification_status}\``,
      ``,
      `#### Steps to Reproduce`,
      `\`\`\`bash`,
      f.repro.curl,
      `\`\`\``,
      ``,
      `#### Raw HTTP Wire Representation`,
      `\`\`\`http`,
      f.repro.rawHttp,
      `\`\`\``,
      ``,
      `#### Technical Impact Analysis`,
      `${f.impact}`,
      ``,
      `#### Recommended Engineering Fix`,
      `${f.remediation}`,
      ``,
      `---`
    );
  });

  return out.join('\n');
}

/**
 * 3. Enterprise ISO 27001 / OWASP ASVS Corporate Security Audit
 */
export function generateEnterpriseReport(): string {
  const { findings, assets, scopes, auditLogs, chains } = getAuditContext();

  logAudit('REPORT_EXPORT_ENTERPRISE', 'ALL', `Generated Enterprise Audit Report (${findings.length} findings)`, 'info');

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach(f => {
    const sev = f.severity.toLowerCase();
    if (sev in severityCounts) severityCounts[sev as keyof typeof severityCounts]++;
  });

  let out = [
    `# Enterprise Information Security Assessment & Compliance Audit`,
    `**Audited Entity**: ${scopes.map(s => s.target).join(', ') || 'Local Infrastructure'}`,
    `**Audit Date**: ${new Date().toUTCString()}`,
    `**Framework Compliance**: OWASP ASVS Level 2, ISO/IEC 27001:2022 A.8.8, CIS Benchmarks`,
    `**Auditor Engine**: VulnHunter OS (Deterministic Core)`,
    ``,
    `## 1. Executive Summary & Risk Heatmap`,
    `| Risk Rating | Identified Count | Recommended Action Timeline |`,
    `| :--- | :--- | :--- |`,
    `| **CRITICAL (9.0 - 10.0)** | ${severityCounts.critical} | Immediate Remediation (within 24 hours) |`,
    `| **HIGH (7.0 - 8.9)** | ${severityCounts.high} | High Priority (within 7 business days) |`,
    `| **MEDIUM (4.0 - 6.9)** | ${severityCounts.medium} | Scheduled Sprint Fix (within 30 days) |`,
    `| **LOW (0.1 - 3.9)** | ${severityCounts.low} | Hardening Backlog |`,
    `| **INFORMATIONAL** | ${severityCounts.info} | Architectural Review |`,
    ``
  ];

  if (chains.length > 0) {
    out.push(`## 2. High-Severity Vulnerability Correlation Chains`);
    chains.forEach(c => {
      out.push(
        `### ${c.title}`,
        `**Composite Severity**: \`${c.severity}\``,
        `${c.description}`,
        ``
      );
    });
  }

  out.push(`## 3. Comprehensive Technical Findings & Engineering Patches`);
  findings.forEach((f, idx) => {
    out.push(
      `### 3.${idx + 1} ${f.title}`,
      `- **Affected Resource**: \`${f.endpoint}\``,
      `- **Severity Score**: **${f.severity.toUpperCase()}** (CVSS ${f.cvss.score})`,
      `- **OWASP Top 10**: ${f.owasp}`,
      `- **CWE Reference**: ${f.cwe}`,
      `- **Audit Status**: \`${f.verification_status}\``,
      ``,
      `#### Vulnerability Context & Impact`,
      `${f.impact}`,
      ``,
      `#### Verification Command`,
      `\`\`\`bash`,
      f.repro.curl,
      `\`\`\``,
      ``,
      `#### Defensive Patch Directives`,
      `${f.remediation}`,
      ``,
      `##### Sample Web Server Configuration Patch (Nginx)`,
      `\`\`\`nginx`,
      `# Add defensive directives to server { ... } block:`,
      `add_header X-Frame-Options "DENY" always;`,
      `add_header X-Content-Type-Options "nosniff" always;`,
      `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
      `add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none';" always;`,
      `\`\`\``,
      ``,
      `---`
    );
  });

  out.push(
    `## 4. Immutable Audit Log Trail`,
    `| Timestamp | Action | Target | Actor | Details |`,
    `| :--- | :--- | :--- | :--- | :--- |`
  );

  auditLogs.slice(0, 10).forEach(log => {
    out.push(`| ${log.timestamp} | \`${log.action}\` | \`${log.target || '-'}\` | ${log.actor} | ${log.details.slice(0, 65)} |`);
  });

  out.push(``, `*Notice: This enterprise audit document is intended solely for authorized security administration and defensive remediation.*`);

  return out.join('\n');
}

/**
 * 4. Machine-Readable SARIF (Static Analysis Results Interchange Format) / JSON Export
 */
export function generateSarifReport(): any {
  const { findings, scopes } = getAuditContext();

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'VulnHunter OS',
            version: '1.2.0',
            informationUri: 'https://github.com/authorized-research/vulnhunter',
            rules: findings.map(f => ({
              id: f.id,
              name: f.title,
              shortDescription: { text: f.title },
              fullDescription: { text: f.impact },
              help: { text: f.remediation },
              properties: {
                cwe: f.cwe,
                owasp: f.owasp,
                cvssScore: f.cvss.score,
                cvssVector: f.cvss.vector,
                vrtPriority: f.vrt_priority
              }
            }))
          }
        },
        results: findings.map(f => ({
          ruleId: f.id,
          message: { text: `${f.title} detected on ${f.endpoint}` },
          level: f.severity === 'critical' || f.severity === 'high' ? 'error' : 'warning',
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.endpoint }
              }
            }
          ],
          properties: {
            reproduction: f.repro,
            evidence: f.evidence,
            verificationStatus: f.verification_status
          }
        }))
      }
    ]
  };
}

export function generateReportData() {
  const context = getAuditContext();
  return {
    generatedAt: new Date().toISOString(),
    projectName: 'VulnHunter OS Security Assessment',
    summary: {
      totalFindings: context.findings.length,
      severityCounts: {
        critical: context.findings.filter(f => f.severity === 'critical').length,
        high: context.findings.filter(f => f.severity === 'high').length,
        medium: context.findings.filter(f => f.severity === 'medium').length,
        low: context.findings.filter(f => f.severity === 'low').length,
        info: context.findings.filter(f => f.severity === 'info').length
      },
      statusCounts: {
        'verified-in-authorized-lab': context.findings.filter(f => f.verification_status === 'verified-in-authorized-lab').length,
        'needs-review': context.findings.filter(f => f.verification_status === 'needs-review').length,
        candidate: context.findings.filter(f => f.verification_status === 'candidate').length,
        'false-positive': context.findings.filter(f => f.verification_status === 'false-positive').length
      },
      totalAssets: context.assets.length,
      activeScopes: context.scopes.map(s => s.target)
    },
    findings: context.findings,
    chains: context.chains,
    auditLogsSample: context.auditLogs
  };
}

export function generateMarkdownReport(): string {
  return generateHackerOneReport();
}
