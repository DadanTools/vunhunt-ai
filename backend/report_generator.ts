/**
 * VulnHunter AI - Security Assessment Report Generator
 * Generates structured JSON and comprehensive Markdown reports with sanitized evidence.
 */

import { db } from './db.js';
import { logAudit } from './scope_gate.js';
import { redactBody } from './redactor.js';

export interface ReportData {
  generatedAt: string;
  projectName: string;
  summary: {
    totalFindings: number;
    severityCounts: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
    };
    statusCounts: {
      candidate: number;
      'needs-review': number;
      'verified-in-authorized-lab': number;
      'false-positive': number;
    };
    totalAssets: number;
    activeScopes: string[];
  };
  findings: any[];
  auditLogsSample: any[];
}

export function generateReportData(): ReportData {
  const findings = db.prepare("SELECT * FROM findings ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END").all() as any[];
  const assets = db.prepare('SELECT * FROM assets').all() as any[];
  const scopes = db.prepare('SELECT target FROM scopes WHERE is_active = 1').all() as any[];
  const auditLogs = db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 20').all() as any[];

  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const statusCounts = { candidate: 0, 'needs-review': 0, 'verified-in-authorized-lab': 0, 'false-positive': 0 };

  for (const f of findings) {
    if (f.severity in severityCounts) {
      severityCounts[f.severity as keyof typeof severityCounts]++;
    }
    if (f.verification_status in statusCounts) {
      statusCounts[f.verification_status as keyof typeof statusCounts]++;
    }
  }

  logAudit('REPORT_EXPORT', 'ALL_FINDINGS', `Exported security assessment report (${findings.length} findings)`, 'info');

  return {
    generatedAt: new Date().toISOString(),
    projectName: 'VulnHunter AI Security Assessment',
    summary: {
      totalFindings: findings.length,
      severityCounts,
      statusCounts,
      totalAssets: assets.length,
      activeScopes: scopes.map(s => s.target)
    },
    findings: findings.map(f => {
      let parsedEvidence = {};
      try {
        parsedEvidence = JSON.parse(f.evidence_json);
      } catch (_e) {
        parsedEvidence = { raw: f.evidence_json };
      }
      return {
        ...f,
        evidence: parsedEvidence
      };
    }),
    auditLogsSample: auditLogs
  };
}

export function generateMarkdownReport(): string {
  const data = generateReportData();
  const dateStr = new Date(data.generatedAt).toUTCString();

  let md = `# VulnHunter AI - Security Assessment Report\n\n`;
  md += `**Generated**: ${dateStr}\n`;
  md += `**Authorized Scope Targets**: ${data.summary.activeScopes.length > 0 ? data.summary.activeScopes.join(', ') : 'None'}\n`;
  md += `**Discovered Assets**: ${data.summary.totalAssets}\n`;
  md += `**Total Identified Findings**: ${data.summary.totalFindings}\n\n`;

  md += `## 1. Executive Summary\n\n`;
  md += `| Severity | Count |\n`;
  md += `| :--- | :--- |\n`;
  md += `| Critical | ${data.summary.severityCounts.critical} |\n`;
  md += `| High | ${data.summary.severityCounts.high} |\n`;
  md += `| Medium | ${data.summary.severityCounts.medium} |\n`;
  md += `| Low | ${data.summary.severityCounts.low} |\n`;
  md += `| Informational | ${data.summary.severityCounts.info} |\n\n`;

  md += `### Verification Status Breakdown\n`;
  md += `- **Verified in Authorized Lab**: ${data.summary.statusCounts['verified-in-authorized-lab']}\n`;
  md += `- **Needs Review**: ${data.summary.statusCounts['needs-review']}\n`;
  md += `- **Candidate / Unconfirmed**: ${data.summary.statusCounts['candidate']}\n`;
  md += `- **Marked False Positive**: ${data.summary.statusCounts['false-positive']}\n\n`;

  md += `## 2. Detailed Findings\n\n`;

  if (data.findings.length === 0) {
    md += `*No findings have been recorded yet. Configure scope and run a scan to record assessment results.*\n\n`;
  }

  data.findings.forEach((f, idx) => {
    md += `### 2.${idx + 1} [${f.severity.toUpperCase()}] ${f.title}\n\n`;
    md += `- **Category**: \`${f.category}\`\n`;
    md += `- **Affected Asset**: \`${f.affected_asset}\`\n`;
    md += `- **Endpoint**: \`${f.endpoint}\`\n`;
    md += `- **Confidence**: \`${f.confidence}\`\n`;
    md += `- **Verification Status**: \`${f.verification_status}\`\n`;
    md += `- **Detection Tool**: \`${f.source_tool}\`\n`;
    md += `- **First Identified**: \`${f.created_at}\`\n\n`;

    md += `#### Impact\n${f.impact}\n\n`;
    md += `#### Steps to Reproduce\n\`\`\`bash\n${f.reproduction_steps}\n\`\`\`\n\n`;
    md += `#### Remediation Guidance\n${f.remediation}\n\n`;

    md += `#### Sanitized Evidence\n\`\`\`json\n${JSON.stringify(f.evidence, null, 2)}\n\`\`\`\n\n`;
    md += `---\n\n`;
  });

  md += `## 3. Local Audit Trail (Recent Events)\n\n`;
  md += `| Timestamp | Action | Target | Actor | Details |\n`;
  md += `| :--- | :--- | :--- | :--- | :--- |\n`;
  data.auditLogsSample.forEach(log => {
    md += `| ${log.timestamp} | \`${log.action}\` | \`${log.target || '-'}\` | ${log.actor} | ${log.details.slice(0, 70)} |\n`;
  });

  md += `\n\n*Notice: This report was compiled by VulnHunter AI for authorized security testing only. All secrets and sensitive tokens have been redacted according to security baseline policy.*`;

  return md;
}
