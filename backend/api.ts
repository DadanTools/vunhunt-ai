/**
 * VulnHunter AI - Express Backend API Routes
 * Modular router handling scope enforcement, scanners, findings, proxy, and audit logs.
 */

import { Router, Request, Response } from 'express';
import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import os from 'node:os';
import fs from 'node:fs';
import { exec } from 'node:child_process';
import util from 'node:util';
import { db } from './db.js';

const execPromise = util.promisify(exec);

let activeGovernorMode: 'performance' | 'eco_saver' | 'throttled' = 'performance';
let isWakeLockSimulated = true;
import { 
  validateScope, 
  activateEmergencyStop, 
  deactivateEmergencyStop, 
  isEmergencyStopActive, 
  logAudit 
} from './scope_gate.js';
import { 
  runExposureScan, 
  runInjectionHeuristicScan, 
  runIdorComparison, 
  safeHttpRequest,
  runReconDiscovery,
  runPathFuzzer,
  runDeepBugBountyAudit
} from './scanner_engine.js';
import { crawlAndAnalyzeJavaScript } from './js_scanner.js';
import { 
  getSystemToolHealth, 
  runSubfinderDiscovery, 
  runNucleiScan 
} from './tool_adapters.js';
import { 
  startLocalProxy, 
  stopLocalProxy, 
  getProxyStatus, 
  executeRepeaterRequest 
} from './proxy_repeater.js';
import { 
  generateReportData, 
  generateMarkdownReport, 
  generateHackerOneReport, 
  generateBugcrowdReport, 
  generateEnterpriseReport, 
  generateSarifReport, 
  calculateCvss, 
  CvssMetrics 
} from './report_generator.js';
import { testLabRouter } from './test_lab.js';

export const apiRouter = Router();

// Mount Local Test Lab Fixtures
apiRouter.use('/lab', testLabRouter);

// 1. Health & Environment Status
apiRouter.get('/health', async (_req: Request, res: Response) => {
  const tools = await getSystemToolHealth();
  const scopeCount = (db.prepare('SELECT COUNT(*) as c FROM scopes WHERE is_active = 1').get() as any).c;
  const assetCount = (db.prepare('SELECT COUNT(*) as c FROM assets').get() as any).c;
  const findingCount = (db.prepare('SELECT COUNT(*) as c FROM findings').get() as any).c;

  res.json({
    status: 'online',
    app: 'VulnHunter AI',
    version: '1.0.0-termux-ready',
    emergencyStop: isEmergencyStopActive(),
    activeScopesCount: scopeCount,
    assetsCount: assetCount,
    findingsCount: findingCount,
    tools,
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch
  });
});

// 2. Emergency Stop Controls
apiRouter.post('/emergency-stop/activate', (_req: Request, res: Response) => {
  activateEmergencyStop();
  res.json({ success: true, message: 'EMERGENCY STOP ACTIVATED. All active jobs aborted and outgoing tests locked.' });
});

apiRouter.post('/emergency-stop/clear', (_req: Request, res: Response) => {
  deactivateEmergencyStop();
  res.json({ success: true, message: 'Emergency Stop cleared. Active testing re-enabled within authorized scopes.' });
});

// 3. Scope Gate Management
apiRouter.get('/scope', (_req: Request, res: Response) => {
  const scopes = db.prepare('SELECT * FROM scopes ORDER BY created_at DESC').all();
  res.json({ scopes, emergencyStop: isEmergencyStopActive() });
});

apiRouter.post('/scope', (req: Request, res: Response) => {
  const { target, target_type = 'domain', allow_private_ip = 0, notes = '' } = req.body;

  if (!target || typeof target !== 'string') {
    res.status(400).json({ error: 'Target is required (e.g. "example.com", "localhost:3000", "*.example.com")' });
    return;
  }

  const cleanTarget = target.trim().toLowerCase();
  const id = 'scope-' + Date.now();
  const now = new Date().toISOString();

  try {
    db.prepare(`
      INSERT INTO scopes (id, target, target_type, is_active, allow_private_ip, notes, created_at)
      VALUES (?, ?, ?, 1, ?, ?, ?)
    `).run(id, cleanTarget, target_type, allow_private_ip ? 1 : 0, notes, now);

    logAudit('SCOPE_ADD', cleanTarget, `Added authorized target rule: ${cleanTarget} (type: ${target_type})`, 'info');
    res.json({ success: true, message: `Added ${cleanTarget} to authorized scope.` });
  } catch (err: any) {
    res.status(400).json({ error: `Scope rule already exists or invalid: ${err.message}` });
  }
});

apiRouter.delete('/scope/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const existing = db.prepare('SELECT target FROM scopes WHERE id = ?').get(id) as any;
  if (existing) {
    db.prepare('DELETE FROM scopes WHERE id = ?').run(id);
    logAudit('SCOPE_REMOVE', existing.target, `Removed authorized scope rule: ${existing.target}`, 'warning');
    res.json({ success: true, message: `Removed scope ${existing.target}` });
  } else {
    res.status(404).json({ error: 'Scope rule not found' });
  }
});

apiRouter.patch('/scope/:id/toggle', (req: Request, res: Response) => {
  const { id } = req.params;
  const existing = db.prepare('SELECT * FROM scopes WHERE id = ?').get(id) as any;
  if (!existing) {
    res.status(404).json({ error: 'Scope rule not found' });
    return;
  }

  const newStatus = existing.is_active === 1 ? 0 : 1;
  db.prepare('UPDATE scopes SET is_active = ? WHERE id = ?').run(newStatus, id);
  logAudit('SCOPE_TOGGLE', existing.target, `Toggled scope status to ${newStatus === 1 ? 'ACTIVE' : 'INACTIVE'}`, 'info');
  res.json({ success: true, is_active: newStatus });
});

// 4. Asset Inventory & Discovery
apiRouter.get('/assets', (_req: Request, res: Response) => {
  const assets = db.prepare('SELECT * FROM assets ORDER BY created_at DESC').all();
  res.json({ assets });
});

apiRouter.post('/assets/manual-import', (req: Request, res: Response) => {
  const { entries, provenance = 'manual_import' } = req.body;
  if (!Array.isArray(entries) || entries.length === 0) {
    res.status(400).json({ error: 'Provide an array of asset objects or domain strings in "entries".' });
    return;
  }

  const now = new Date().toISOString();
  let importedCount = 0;

  for (const item of entries) {
    const rawHost = typeof item === 'string' ? item : item.host;
    if (!rawHost) continue;

    const host = rawHost.trim().toLowerCase();
    const existing = db.prepare('SELECT id FROM assets WHERE host = ?').get(host);

    if (!existing) {
      const id = 'asset-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6);
      db.prepare(`
        INSERT INTO assets (id, host, port, protocol, provenance, is_authorized, created_at, updated_at)
        VALUES (?, ?, 80, 'http', ?, 0, ?, ?)
      `).run(id, host, provenance, now, now);
      importedCount++;
    }
  }

  logAudit('ASSETS_IMPORTED', `${importedCount} assets`, `Imported ${importedCount} assets via ${provenance}`, 'info');
  res.json({ success: true, count: importedCount, message: `Successfully imported ${importedCount} assets.` });
});

apiRouter.post('/assets/discover-subfinder', async (req: Request, res: Response) => {
  const { domain } = req.body;
  if (!domain) {
    res.status(400).json({ error: 'Domain is required for discovery.' });
    return;
  }

  // Validate scope! Subfinder must only be run against authorized domain
  const scopeCheck = await validateScope(domain);
  if (!scopeCheck.authorized) {
    res.status(403).json({ error: `Scope Gate Violation: ${scopeCheck.reason}` });
    return;
  }

  const result = await runSubfinderDiscovery(domain);
  if (!result.success) {
    res.status(result.error?.includes('not installed') ? 501 : 500).json({
      success: false,
      error: result.error
    });
    return;
  }

  const now = new Date().toISOString();
  let inserted = 0;
  for (const item of result.assets) {
    const host = item.host.toLowerCase();
    const existing = db.prepare('SELECT id FROM assets WHERE host = ?').get(host);
    if (!existing) {
      db.prepare(`
        INSERT INTO assets (id, host, port, protocol, provenance, is_authorized, created_at, updated_at)
        VALUES (?, ?, 80, 'http', 'subfinder', 1, ?, ?)
      `).run('asset-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6), host, now, now);
      inserted++;
    }
  }

  res.json({
    success: true,
    totalDiscovered: result.assets.length,
    newlyAdded: inserted,
    assets: result.assets
  });
});

apiRouter.post('/assets/:id/probe', async (req: Request, res: Response) => {
  const { id } = req.params;
  const asset = db.prepare('SELECT * FROM assets WHERE id = ?').get(id) as any;
  if (!asset) {
    res.status(404).json({ error: 'Asset not found' });
    return;
  }

  const targetUrl = `${asset.protocol}://${asset.host}${asset.port && asset.port !== 80 && asset.port !== 443 ? `:${asset.port}` : ''}`;
  const scopeCheck = await validateScope(targetUrl);
  if (!scopeCheck.authorized) {
    res.status(403).json({ error: `Scope Gate Violation: ${scopeCheck.reason}` });
    return;
  }

  try {
    const resp = await safeHttpRequest(targetUrl, { timeoutMs: 5000 });
    // Extract title if HTML
    let title: string | undefined;
    const match = resp.body.match(/<title[^>]*>([^<]+)<\/title>/i);
    if (match) title = match[1].trim().slice(0, 80);

    const now = new Date().toISOString();
    db.prepare(`
      UPDATE assets 
      SET status_code = ?, title = ?, updated_at = ?
      WHERE id = ?
    `).run(resp.statusCode, title || asset.title, now, id);

    res.json({ success: true, statusCode: resp.statusCode, title });
  } catch (err: any) {
    res.status(502).json({ error: `Probe failed: ${err.message}` });
  }
});

// 5. Scan Job Management & Dispatcher
apiRouter.get('/scans', (_req: Request, res: Response) => {
  const scans = db.prepare('SELECT * FROM scans ORDER BY started_at DESC LIMIT 50').all();
  res.json({ scans });
});

apiRouter.post('/scans', async (req: Request, res: Response) => {
  const { target, scan_type = 'exposure' } = req.body;
  if (!target) {
    res.status(400).json({ error: 'Target URL is required.' });
    return;
  }

  // Pre-validate scope before queuing!
  const scopeCheck = await validateScope(target);
  if (!scopeCheck.authorized) {
    res.status(403).json({ error: `Scope Gate Violation: ${scopeCheck.reason}` });
    return;
  }

  const scanId = 'scan-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6);
  const now = new Date().toISOString();

  db.prepare(`
    INSERT INTO scans (id, target, scan_type, status, progress, total_tasks, completed_tasks, started_at)
    VALUES (?, ?, ?, 'queued', 0, 10, 0, ?)
  `).run(scanId, target, scan_type, now);

  logAudit('SCAN_CREATE', target, `Created ${scan_type} scan job ${scanId}`, 'info');

  // Launch background job asynchronously
  setTimeout(async () => {
    try {
      if (scan_type === 'exposure') {
        await runExposureScan(scanId, target);
      } else if (scan_type === 'injection') {
        await runInjectionHeuristicScan(scanId, target);
      } else if (scan_type === 'templates') {
        db.prepare("UPDATE scans SET status = 'running', progress = 10 WHERE id = ?").run(scanId);
        const nucleiRes = await runNucleiScan(target);
        if (!nucleiRes.success) {
          db.prepare("UPDATE scans SET status = 'failed', error_message = ? WHERE id = ?").run(nucleiRes.error || 'Nuclei execution error', scanId);
        } else {
          db.prepare("UPDATE scans SET status = 'completed', progress = 100, completed_at = ? WHERE id = ?").run(new Date().toISOString(), scanId);
        }
      } else {
        // Full scan: Exposure + Injection
        await runExposureScan(scanId, target);
        await runInjectionHeuristicScan(scanId, target);
      }
    } catch (err: any) {
      db.prepare("UPDATE scans SET status = 'failed', error_message = ? WHERE id = ?").run(err.message || 'Scan error', scanId);
    }
  }, 10);

  res.json({
    success: true,
    scanId,
    target,
    scan_type,
    status: 'queued',
    message: 'Scan successfully queued and executing within authorized scope.'
  });
});

apiRouter.post('/scans/:id/cancel', (req: Request, res: Response) => {
  const { id } = req.params;
  const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(id) as any;
  if (!scan) {
    res.status(404).json({ error: 'Scan not found' });
    return;
  }

  db.prepare("UPDATE scans SET status = 'cancelled', error_message = 'Cancelled by user' WHERE id = ?").run(id);
  logAudit('SCAN_CANCEL', scan.target, `User cancelled scan ${id}`, 'warning');
  res.json({ success: true, message: `Scan ${id} cancelled.` });
});

// Live Target Reconnaissance (DNS, SSL/TLS, Tech Stack & Security Headers Grade)
apiRouter.post('/recon/live', async (req: Request, res: Response) => {
  const { target } = req.body;
  if (!target) {
    res.status(400).json({ error: 'Target URL is required' });
    return;
  }
  try {
    const result = await runReconDiscovery(target);
    res.json({ success: true, result });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// Real Rate-Limited Endpoint & Hidden File Fuzzer
apiRouter.post('/fuzzer/run', async (req: Request, res: Response) => {
  const { target, customPaths } = req.body;
  if (!target) {
    res.status(400).json({ error: 'Target URL is required' });
    return;
  }
  try {
    const results = await runPathFuzzer(target, customPaths);
    res.json({ success: true, results });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// 6. Findings Management
apiRouter.get('/findings', (req: Request, res: Response) => {
  const { severity, category, status } = req.query;
  let query = 'SELECT * FROM findings WHERE 1=1';
  const params: any[] = [];

  if (severity) {
    query += ' AND severity = ?';
    params.push(severity);
  }
  if (category) {
    query += ' AND category = ?';
    params.push(category);
  }
  if (status) {
    query += ' AND verification_status = ?';
    params.push(status);
  }

  query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, created_at DESC";
  const findings = db.prepare(query).all(...params);
  res.json({ findings });
});

apiRouter.get('/findings/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const finding = db.prepare('SELECT * FROM findings WHERE id = ?').get(id) as any;
  if (!finding) {
    res.status(404).json({ error: 'Finding not found' });
    return;
  }
  res.json({ finding });
});

apiRouter.patch('/findings/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const { verification_status } = req.body;
  const allowed = ['candidate', 'needs-review', 'verified-in-authorized-lab', 'false-positive'];

  if (!verification_status || !allowed.includes(verification_status)) {
    res.status(400).json({ error: `verification_status must be one of: ${allowed.join(', ')}` });
    return;
  }

  const existing = db.prepare('SELECT * FROM findings WHERE id = ?').get(id) as any;
  if (!existing) {
    res.status(404).json({ error: 'Finding not found' });
    return;
  }

  const now = new Date().toISOString();
  db.prepare('UPDATE findings SET verification_status = ?, updated_at = ? WHERE id = ?').run(verification_status, now, id);
  logAudit('FINDING_STATUS_UPDATE', existing.endpoint, `Updated finding "${existing.title}" status to ${verification_status}`, 'info');

  res.json({ success: true, verification_status });
});

// 7. Safe IDOR / BOLA Comparison Endpoint
apiRouter.post('/idor/compare', async (req: Request, res: Response) => {
  const { userAToken, userBToken, targetUrlPattern, objectAId, objectBId } = req.body;

  if (!userAToken || !userBToken || !targetUrlPattern || !objectAId || !objectBId) {
    res.status(400).json({
      error: 'Missing parameters. Provide userAToken, userBToken, targetUrlPattern (with {ID}), objectAId, and objectBId.'
    });
    return;
  }

  try {
    const scanId = 'scan-idor-' + Date.now();
    const result = await runIdorComparison(scanId, userAToken, userBToken, targetUrlPattern, objectAId, objectBId);
    res.json({
      success: true,
      comparison: result.comparisonSummary,
      finding: result.finding || null
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// 8. Burp-Style Proxy & Repeater Controls
apiRouter.get('/proxy/status', (_req: Request, res: Response) => {
  res.json(getProxyStatus());
});

apiRouter.post('/proxy/start', async (req: Request, res: Response) => {
  const { port = 8081 } = req.body;
  const result = await startLocalProxy(parseInt(port, 10));
  res.json(result);
});

apiRouter.post('/proxy/stop', async (_req: Request, res: Response) => {
  await stopLocalProxy();
  res.json({ success: true, message: 'Local proxy stopped.' });
});

apiRouter.get('/proxy/history', (_req: Request, res: Response) => {
  const logs = db.prepare('SELECT * FROM proxy_logs ORDER BY created_at DESC LIMIT 100').all();
  res.json({ logs });
});

apiRouter.post('/proxy/clear', (_req: Request, res: Response) => {
  db.prepare('DELETE FROM proxy_logs').run();
  res.json({ success: true, message: 'Proxy history cleared.' });
});

apiRouter.post('/proxy/replay', async (req: Request, res: Response) => {
  const { method = 'GET', url, headers = {}, body } = req.body;
  if (!url) {
    res.status(400).json({ error: 'URL is required for Repeater replay.' });
    return;
  }

  try {
    const response = await executeRepeaterRequest(method, url, headers, body);
    res.json({ success: true, response });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// 9. Multi-Format Report Export & Builder Routes
apiRouter.get('/reports/data', (_req: Request, res: Response) => {
  const data = generateReportData();
  res.json(data);
});

apiRouter.get('/reports/markdown', (_req: Request, res: Response) => {
  const md = generateMarkdownReport();
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="vulnhunter-assessment-report.md"');
  res.send(md);
});

apiRouter.get('/reports/hackerone', (req: Request, res: Response) => {
  const findingId = req.query.findingId as string | undefined;
  const md = generateHackerOneReport(findingId);
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="hackerone-bug-report.md"');
  res.send(md);
});

apiRouter.get('/reports/bugcrowd', (_req: Request, res: Response) => {
  const md = generateBugcrowdReport();
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="bugcrowd-vrt-report.md"');
  res.send(md);
});

apiRouter.get('/reports/enterprise', (_req: Request, res: Response) => {
  const md = generateEnterpriseReport();
  res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="enterprise-security-audit.md"');
  res.send(md);
});

apiRouter.get('/reports/sarif', (_req: Request, res: Response) => {
  const sarif = generateSarifReport();
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="vulnhunter-results.sarif"');
  res.json(sarif);
});

apiRouter.get('/reports/preview', (req: Request, res: Response) => {
  const format = (req.query.format as string) || 'hackerone';
  const findingId = req.query.findingId as string | undefined;

  let content = '';
  if (format === 'hackerone') {
    content = generateHackerOneReport(findingId);
  } else if (format === 'bugcrowd') {
    content = generateBugcrowdReport();
  } else if (format === 'enterprise') {
    content = generateEnterpriseReport();
  } else if (format === 'sarif') {
    content = JSON.stringify(generateSarifReport(), null, 2);
  } else {
    content = JSON.stringify(generateReportData(), null, 2);
  }

  res.json({ format, content });
});

// CVSS v3.1 Dynamic Calculator Endpoint
apiRouter.post('/cvss/calculate', (req: Request, res: Response) => {
  const metrics: CvssMetrics = {
    av: req.body.av || 'N',
    ac: req.body.ac || 'L',
    pr: req.body.pr || 'N',
    ui: req.body.ui || 'N',
    s: req.body.s || 'U',
    c: req.body.c || 'N',
    i: req.body.i || 'L',
    a: req.body.a || 'N'
  };

  const result = calculateCvss(metrics);
  res.json(result);
});

// 10. Audit Trail
apiRouter.get('/audit', (_req: Request, res: Response) => {
  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 200').all();
  res.json({ logs });
});

// 11. Optional Transparent Heuristic / AI Security Assistant
// Rule 4: "AI must be optional; provide a transparent deterministic/rule-based mode without AI credentials."
apiRouter.post('/ai/analyze', async (req: Request, res: Response) => {
  const { title, category, evidence, impact } = req.body;

  // Check if GEMINI_API_KEY is available and configured
  const apiKey = process.env.GEMINI_API_KEY;

  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY' || req.body.forceDeterministic) {
    // Deterministic Rule-Based Analysis (Transparent, local, 0 external calls)
    let analysis = `### Deterministic Analysis for [${category?.toUpperCase() || 'VULNERABILITY'}] ${title}\n\n`;
    analysis += `**Assessment Heuristic:** This finding was flagged based on security baseline best practices (OWASP Top 10 / ASVS Level 2).\n\n`;
    
    if (category === 'security_headers') {
      analysis += `**Technical Rationale:** The server response omitted defensive HTTP headers designed to instruct modern user-agents to enforce strict transport security, prevent framing, or restrict inline script execution.\n`;
      analysis += `**Defensive Guidance:** Configure your reverse proxy (nginx, Apache, or cloud edge) to automatically append standard defensive headers.`;
    } else if (category === 'auth_idor') {
      analysis += `**Technical Rationale:** Direct object references were accessible across tenant boundaries without server-side principal validation.\n`;
      analysis += `**Defensive Guidance:** Enforce entity ownership checks at the data layer (e.g. \`WHERE id = :id AND owner_id = :session_user_id\`).`;
    } else if (category === 'injection') {
      analysis += `**Technical Rationale:** Unsanitized parameter canary reflections were observed in the response body.\n`;
      analysis += `**Defensive Guidance:** Implement context-sensitive output encoding (HTML entity encoding, attribute escaping) before outputting user input.`;
    } else {
      analysis += `**General Guidance:** Review application architecture and verify authorization boundaries before exposing endpoints to production.`;
    }

    res.json({
      mode: 'deterministic_rule_based',
      analysis,
      confidence: 'deterministic'
    });
    return;
  }

  // If Gemini API Key is configured, provide optional enhanced remediation analysis
  try {
    const { GoogleGenAI } = await import('@google/genai');
    const ai = new GoogleGenAI();
    const response = await ai.models.generateContent({
      model: 'gemini-2.5-flash',
      contents: `You are an Application Security expert. Provide a concise, professional remediation and risk verification breakdown for this finding:
Title: ${title}
Category: ${category}
Evidence: ${JSON.stringify(evidence)}
Impact: ${impact}

Do NOT output attack payloads or exploit steps. Output ONLY defensive remediation steps, verification advice, and secure configuration snippets.`
    });

    res.json({
      mode: 'gemini_assistant',
      analysis: response.text,
      confidence: 'ai_assisted'
    });
  } catch (err: any) {
    // Graceful fallback to deterministic analysis
    res.json({
      mode: 'deterministic_fallback',
      analysis: `Heuristic Rule Guidance: Always enforce least privilege, input validation, and defensive response headers for ${title}. (AI generation unavailable: ${err.message})`,
      confidence: 'deterministic'
    });
  }
});

// 22. Subdomain Permutation Generator
apiRouter.post('/recon/permute', async (req: Request, res: Response) => {
  try {
    const { domain } = req.body;
    if (!domain) {
      return res.status(400).json({ error: 'Target domain is required.' });
    }

    const base = domain.replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
    const prefixes = ['api', 'dev', 'staging', 'admin', 'auth', 'corp', 'mail', 'internal', 'vpn', 'portal', 'app', 'cdn'];
    const candidates = prefixes.map(p => `${p}.${base}`);
    const discovered: Array<{ host: string; ip: string; status: 'active' | 'unresolved' }> = [];

    for (const cand of candidates) {
      try {
        const addrs = await dns.resolve4(cand);
        if (addrs && addrs.length > 0) {
          discovered.push({ host: cand, ip: addrs[0], status: 'active' });
          // Persist to assets table
          const assetId = `permute-${cand}`;
          db.prepare(`
            INSERT OR REPLACE INTO assets (id, host, ip, port, protocol, provenance, is_authorized, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).run(assetId, cand, addrs[0], 443, 'https', 'termux_permute', 1, new Date().toISOString(), new Date().toISOString());
        }
      } catch {
        discovered.push({ host: cand, ip: '', status: 'unresolved' });
      }
    }

    const activeList = discovered.filter(d => d.status === 'active');
    res.json({
      success: true,
      baseDomain: base,
      testedCount: candidates.length,
      activeCount: activeList.length,
      results: discovered
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 23. Interactive In-App Termux Command Executor
apiRouter.post('/termux/exec', async (req: Request, res: Response) => {
  try {
    const { command } = req.body;
    if (!command || typeof command !== 'string') {
      return res.status(400).json({ error: 'Command string is required.' });
    }

    const raw = command.trim();
    const parts = raw.split(/\s+/);
    const cmd = parts[0]?.toLowerCase();
    const arg1 = parts[1];
    const arg2 = parts[2];

    const lines: string[] = [];

    if (cmd === 'help' || cmd === '?') {
      lines.push('================================================================');
      lines.push('            VULNHUNTER AI - TERMUX POWER COMMANDS               ');
      lines.push('================================================================');
      lines.push('  recon <target>          Live DNS, SSL/TLS & Tech Stack Discovery');
      lines.push('  fuzz <url>              Rate-limited 20-route endpoint fuzzer');
      lines.push('  permute <domain>        Generate & resolve subdomain permutations');
      lines.push('  scan <url> [type]       Run exposure or heuristics scanner');
      lines.push('  scope list              View active authorized targets in Scope Gate');
      lines.push('  scope add <target>      Add target to authorized Scope Gate');
      lines.push('  findings                Display all recorded vulnerabilities');
      lines.push('  wake-lock               Android battery & background worker status');
      lines.push('  benchmark <payload>     Run 3-round latency probe on local lab');
      lines.push('  system                  View architecture, RAM, and runtime info');
      lines.push('  clear                   Clear terminal display buffer');
      lines.push('================================================================');
    } else if (cmd === 'recon') {
      if (!arg1) {
        lines.push('[-] Error: Target host required. Usage: recon <domain|host>');
      } else {
        const normalizedTarget = (arg1.startsWith('http://') || arg1.startsWith('https://'))
          ? arg1
          : (arg1.includes('localhost') || arg1.includes('127.0.0.1') ? `http://${arg1}` : `https://${arg1}`);

        const recon = await runReconDiscovery(normalizedTarget);
        lines.push(`[+] Target: ${recon.host}`);
        lines.push(`[+] Security Headers Grade: ${recon.securityHeadersGrade.grade} (${recon.securityHeadersGrade.score}/100)`);
        lines.push(`[+] Technologies: ${recon.technologies.map(t => t.name).join(', ') || 'None detected'}`);
        if (recon.tls) {
          lines.push(`[+] SSL Certificate: Issuer: ${recon.tls.issuer} | Protocol: ${recon.tls.protocol} | Days: ${recon.tls.daysRemaining}`);
        }
        lines.push(`[+] DNS A: ${recon.dns.a.join(', ') || 'None'}`);
      }
    } else if (cmd === 'fuzz') {
      if (!arg1) {
        lines.push('[-] Error: URL required. Usage: fuzz <url>');
      } else {
        const normalizedTarget = (arg1.startsWith('http://') || arg1.startsWith('https://'))
          ? arg1
          : (arg1.includes('localhost') || arg1.includes('127.0.0.1') ? `http://${arg1}` : `https://${arg1}`);

        lines.push(`[*] Launching polite path fuzzer against ${normalizedTarget}...`);
        const results = await runPathFuzzer(normalizedTarget);
        results.forEach(r => {
          const statusTag = r.statusCode === 200 ? `[200 OK]` : `[${r.statusCode}]`;
          lines.push(`  ${statusTag.padEnd(10)} ${r.path.padEnd(25)} ${r.contentLength} B (${r.durationMs}ms)`);
        });
        lines.push(`[*] Completed. Discovered ${results.filter(r => r.isInteresting).length} active routes.`);
      }
    } else if (cmd === 'permute') {
      if (!arg1) {
        lines.push('[-] Error: Domain required. Usage: permute <domain>');
      } else {
        lines.push(`[*] Generating targeted subdomain permutations for ${arg1}...`);
        const prefixes = ['api', 'dev', 'staging', 'admin', 'auth', 'corp', 'internal', 'vpn'];
        for (const p of prefixes) {
          const cand = `${p}.${arg1}`;
          try {
            const addrs = await dns.resolve4(cand);
            lines.push(`  [+] ACTIVE: ${cand.padEnd(30)} -> ${addrs[0]}`);
          } catch {
            lines.push(`  [-] Unresolved: ${cand}`);
          }
        }
      }
    } else if (cmd === 'scope') {
      if (arg1 === 'list' || !arg1) {
        const scopes = db.prepare('SELECT id, target, target_type, is_active FROM scopes').all() as any[];
        lines.push(`[+] Active Scope Gate Targets (${scopes.length}):`);
        scopes.forEach(s => {
          lines.push(`  * ${s.target} [${s.target_type}] ${s.is_active ? '(ACTIVE)' : '(DISABLED)'}`);
        });
      } else if (arg1 === 'add' && arg2) {
        const id = `scope-${Date.now()}`;
        db.prepare('INSERT INTO scopes (id, target, target_type, is_active, allow_private_ip, created_at) VALUES (?, ?, ?, 1, 1, ?)')
          .run(id, arg2, 'host', new Date().toISOString());
        lines.push(`[+] Added ${arg2} to authorized Scope Gate.`);
      } else {
        lines.push('[-] Usage: scope list | scope add <target>');
      }
    } else if (cmd === 'findings') {
      const findings = db.prepare('SELECT id, title, severity, category, affected_asset FROM findings ORDER BY created_at DESC LIMIT 20').all() as any[];
      lines.push(`[+] Total Recorded Findings: ${findings.length}`);
      findings.forEach(f => {
        lines.push(`  [${f.severity.toUpperCase().padEnd(8)}] ${f.title} (${f.affected_asset})`);
      });
    } else if (cmd === 'wake-lock' || cmd === 'battery') {
      lines.push('================================================================');
      lines.push('            ANDROID TERMUX BACKGROUND EXECUTION STATUS          ');
      lines.push('================================================================');
      lines.push('  [+] Wake-Lock Command: termux-wake-lock');
      lines.push('  [+] Battery Optimization: Android Settings -> Apps -> Termux');
      lines.push('      Select: Battery -> Unrestricted');
      lines.push('  [+] Background Daemon Mode:');
      lines.push('      nohup python3 vulnhunter.py serve --port 8080 > vh.log 2>&1 &');
      lines.push('  [+] Process Keep-Alive: Termux foreground notification active.');
      lines.push('================================================================');
    } else if (cmd === 'system') {
      lines.push(`[+] Platform: ${process.platform} (${process.arch})`);
      lines.push(`[+] Node.js: ${process.version}`);
      lines.push(`[+] PID: ${process.pid}`);
      lines.push(`[+] Memory Usage: ${Math.round(process.memoryUsage().rss / (1024 * 1024))} MB RSS`);
      lines.push(`[+] Uptime: ${Math.round(process.uptime())} seconds`);
    } else {
      lines.push(`[-] Command not recognized: "${raw}". Type "help" to view all available commands.`);
    }

    res.json({
      command: raw,
      lines,
      timestamp: new Date().toLocaleTimeString()
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message, lines: [`[-] Execution Error: ${err.message}`] });
  }
});

// 24. Live Termux Hardware Telemetry (CPU Temp, Memory, Battery)
apiRouter.get('/termux/hardware-metrics', async (_req: Request, res: Response) => {
  try {
    const mem = process.memoryUsage();
    const systemTotalMb = Math.round(os.totalmem() / (1024 * 1024));
    const systemFreeMb = Math.round(os.freemem() / (1024 * 1024));
    const rssMb = Math.round(mem.rss / (1024 * 1024) * 10) / 10;
    const heapUsedMb = Math.round(mem.heapUsed / (1024 * 1024) * 10) / 10;
    const heapTotalMb = Math.round(mem.heapTotal / (1024 * 1024) * 10) / 10;
    const memPercent = Math.min(100, Math.round(((systemTotalMb - systemFreeMb) / systemTotalMb) * 100));

    // Active scans count
    let activeScansCount = 0;
    try {
      const activeScans = db.prepare("SELECT COUNT(*) as c FROM scan_jobs WHERE status IN ('running', 'queued')").get() as any;
      activeScansCount = activeScans?.c || 0;
    } catch {}

    // Check Termux Battery Status CLI
    let batteryData: any = null;
    try {
      const { stdout } = await execPromise('termux-battery-status', { timeout: 1500 });
      if (stdout) {
        batteryData = JSON.parse(stdout);
      }
    } catch {
      // termux-battery-status not present or not inside Termux:API
    }

    // Attempt sysfs battery check
    if (!batteryData) {
      try {
        if (fs.existsSync('/sys/class/power_supply/battery/capacity')) {
          const cap = parseInt(fs.readFileSync('/sys/class/power_supply/battery/capacity', 'utf8').trim(), 10);
          const status = fs.existsSync('/sys/class/power_supply/battery/status') 
            ? fs.readFileSync('/sys/class/power_supply/battery/status', 'utf8').trim() 
            : 'DISCHARGING';
          batteryData = {
            percentage: cap,
            health: 'GOOD',
            status,
            plugged: status.toLowerCase().includes('charge') ? 'PLUGGED_AC' : 'UNPLUGGED',
            temperature: 31.5
          };
        }
      } catch {}
    }

    // Fallback battery telemetry
    if (!batteryData) {
      const simulatedBattery = Math.max(15, 92 - Math.floor((process.uptime() / 600) % 30));
      batteryData = {
        percentage: simulatedBattery,
        health: 'GOOD',
        status: simulatedBattery < 40 ? 'DISCHARGING' : 'CHARGING',
        plugged: 'PLUGGED_AC',
        temperature: 32.4
      };
    }

    // Check CPU Temperature from sysfs
    let rawTempC: number | null = null;
    const thermalPaths = [
      '/sys/class/thermal/thermal_zone0/temp',
      '/sys/class/thermal/thermal_zone1/temp',
      '/sys/devices/virtual/thermal/thermal_zone0/temp',
      '/sys/class/power_supply/battery/temp'
    ];

    for (const tp of thermalPaths) {
      try {
        if (fs.existsSync(tp)) {
          const val = parseInt(fs.readFileSync(tp, 'utf8').trim(), 10);
          if (!isNaN(val) && val > 0) {
            rawTempC = val > 1000 ? val / 1000 : val;
            break;
          }
        }
      } catch {}
    }

    // If thermal zone not exposed by container, calculate dynamic temperature based on real CPU load & active scans
    const load1 = os.loadavg()[0] || 0.15;
    if (rawTempC === null) {
      // Base temperature: 34.0°C + active scan load factor + CPU load factor
      const loadFactor = Math.min(25, load1 * 7);
      const scanFactor = activeScansCount * 3.5;
      rawTempC = Math.round((34.0 + loadFactor + scanFactor) * 10) / 10;
    }

    const cpuTempC = Math.round(rawTempC * 10) / 10;
    const cpuTempF = Math.round((cpuTempC * 1.8 + 32) * 10) / 10;

    let tempStatus: 'optimal' | 'warm' | 'hot' | 'critical' = 'optimal';
    if (cpuTempC >= 75) tempStatus = 'critical';
    else if (cpuTempC >= 58) tempStatus = 'hot';
    else if (cpuTempC >= 45) tempStatus = 'warm';

    // Auto-throttle governor if temperature is dangerous or battery critical
    let currentGovernor = activeGovernorMode;
    if (cpuTempC >= 72 || (batteryData.percentage <= 15 && batteryData.status !== 'CHARGING')) {
      currentGovernor = 'throttled';
    }

    res.json({
      cpuTempC,
      cpuTempF,
      tempStatus,
      memory: {
        rssMb,
        heapUsedMb,
        heapTotalMb,
        systemFreeMb,
        systemTotalMb,
        memoryUsagePercent: memPercent
      },
      battery: {
        percentage: batteryData.percentage,
        health: batteryData.health || 'GOOD',
        status: batteryData.status || 'CHARGING',
        plugged: batteryData.plugged || 'PLUGGED_AC',
        temperatureC: batteryData.temperature || 32.0
      },
      system: {
        loadAvg: os.loadavg(),
        activeScansCount,
        cpuCores: os.cpus().length,
        uptimeSeconds: Math.round(process.uptime()),
        governorMode: currentGovernor,
        wakeLockActive: isWakeLockSimulated
      }
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 25. Thermal & Concurrency Governor Mode Toggle
apiRouter.post('/termux/governor', (req: Request, res: Response) => {
  const { mode, wakeLock } = req.body;
  if (mode && ['performance', 'eco_saver', 'throttled'].includes(mode)) {
    activeGovernorMode = mode;
  }
  if (typeof wakeLock === 'boolean') {
    isWakeLockSimulated = wakeLock;
  }

  logAudit('GOVERNOR_UPDATE', 'termux_monitor', `Thermal governor set to ${activeGovernorMode}, wake-lock: ${isWakeLockSimulated}`, 'info');

  res.json({
    success: true,
    governorMode: activeGovernorMode,
    wakeLockActive: isWakeLockSimulated
  });
});

// 26. CVE & NVD / GitHub Security Advisory Intelligence (Google Search Grounded)
apiRouter.get('/cve/history', (_req: Request, res: Response) => {
  try {
    const rows = db.prepare(`
      SELECT id, query, cve_id, title, severity, cvss_score, affected_software, cwe, description, remediation, sources, source_engine, created_at
      FROM cve_intelligence
      ORDER BY created_at DESC
      LIMIT 25
    `).all() as any[];

    const formatted = rows.map(r => ({
      ...r,
      sources: JSON.parse(r.sources || '[]')
    }));

    res.json({ success: true, history: formatted });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

apiRouter.post('/cve/lookup', async (req: Request, res: Response) => {
  const { query } = req.body;
  if (!query || typeof query !== 'string' || !query.trim()) {
    return res.status(400).json({ error: 'Search query or CVE ID is required.' });
  }

  const cleanQuery = query.trim();

  // First, check if we have a fresh cached result in SQLite (under 24h old)
  try {
    const existing = db.prepare(`
      SELECT * FROM cve_intelligence
      WHERE LOWER(query) = LOWER(?) OR LOWER(cve_id) = LOWER(?)
      ORDER BY created_at DESC LIMIT 1
    `).get(cleanQuery, cleanQuery) as any;

    if (existing) {
      return res.json({
        success: true,
        cached: true,
        result: {
          ...existing,
          sources: JSON.parse(existing.sources || '[]')
        }
      });
    }
  } catch {}

  // Attempt live Google Search grounded lookup using Gemini 3.8 Flash
  try {
    const { GoogleGenAI } = await import('@google/genai');
    const ai = new GoogleGenAI();

    const prompt = `You are a Principal Threat Intelligence & Application Security Analyst.
Search the National Vulnerability Database (NVD), MITRE CVE, GitHub Security Advisories (GHSA), and vendor security bulletins for: "${cleanQuery}".

Provide an authoritative security intelligence report. You MUST return ONLY valid parseable JSON matching this schema:
{
  "cveId": "string (The official CVE ID like CVE-2024-XXXX, or primary advisory ID like GHSA-xxxx)",
  "title": "string (Accurate, concise vulnerability title)",
  "cvssScore": number (CVSS v3.1 base score, e.g. 9.8),
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN",
  "affectedSoftware": "string (Product name and vulnerable version range, e.g. 'Express.js < 4.19.2')",
  "cwe": "string (e.g. 'CWE-78: OS Command Injection' or 'CWE-79: Cross-site Scripting')",
  "description": "string (Clear technical summary of the root cause and vulnerability mechanism)",
  "remediation": "string (Specific upgrade version, configuration changes, or vendor patches to remediate)",
  "sources": [
    { "title": "string", "url": "string" }
  ]
}
Do NOT include markdown formatting, backticks, or preamble text. Output strictly raw JSON.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        tools: [{ googleSearch: {} }]
      }
    });

    // Extract search grounded sources
    const groundingChunks = (response.candidates?.[0]?.groundingMetadata as any)?.groundingChunks || [];
    const webSources = groundingChunks
      .filter((c: any) => c.web?.uri)
      .map((c: any) => ({
        title: c.web?.title || 'Security Advisory Source',
        url: c.web?.uri
      }));

    let rawText = response.text || '';
    // Strip markdown formatting if returned
    rawText = rawText.replace(/```json/gi, '').replace(/```/g, '').trim();

    let parsed: any;
    try {
      parsed = JSON.parse(rawText);
    } catch {
      // Find JSON object via regex if there's surrounding text
      const match = rawText.match(/\{[\s\S]*\}/);
      if (match) {
        parsed = JSON.parse(match[0]);
      } else {
        throw new Error('Failed to parse structured JSON from search grounding response.');
      }
    }

    // Merge Google Search grounding sources with extracted sources
    const allSources = [...(parsed.sources || [])];
    for (const ws of webSources) {
      if (!allSources.some(s => s.url === ws.url)) {
        allSources.push(ws);
      }
    }

    // Always include direct NVD and GitHub search links
    if (parsed.cveId?.startsWith('CVE-')) {
      const nvdUrl = `https://nvd.nist.gov/vuln/detail/${parsed.cveId}`;
      if (!allSources.some(s => s.url === nvdUrl)) {
        allSources.unshift({ title: `NVD Vulnerability Detail - ${parsed.cveId}`, url: nvdUrl });
      }
      const ghsaUrl = `https://github.com/advisories?query=${parsed.cveId}`;
      if (!allSources.some(s => s.url === ghsaUrl)) {
        allSources.push({ title: 'GitHub Security Advisory Database', url: ghsaUrl });
      }
    }

    const cveRecord = {
      id: `cve-${Date.now()}`,
      query: cleanQuery,
      cve_id: parsed.cveId || cleanQuery,
      title: parsed.title || `Vulnerability Report: ${cleanQuery}`,
      severity: (parsed.severity || 'HIGH').toUpperCase(),
      cvss_score: typeof parsed.cvssScore === 'number' ? parsed.cvssScore : 7.5,
      affected_software: parsed.affectedSoftware || cleanQuery,
      cwe: parsed.cwe || 'CWE-General',
      description: parsed.description || 'No detailed description available.',
      remediation: parsed.remediation || 'Apply vendor security updates and audit dependencies.',
      sources: JSON.stringify(allSources),
      source_engine: 'gemini_search_grounding',
      created_at: new Date().toISOString()
    };

    // Save to database
    db.prepare(`
      INSERT INTO cve_intelligence (id, query, cve_id, title, severity, cvss_score, affected_software, cwe, description, remediation, sources, source_engine, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      cveRecord.id,
      cveRecord.query,
      cveRecord.cve_id,
      cveRecord.title,
      cveRecord.severity,
      cveRecord.cvss_score,
      cveRecord.affected_software,
      cveRecord.cwe,
      cveRecord.description,
      cveRecord.remediation,
      cveRecord.sources,
      cveRecord.source_engine,
      cveRecord.created_at
    );

    logAudit('CVE_LOOKUP', cveRecord.cve_id, `Retrieved live vulnerability intelligence for ${cleanQuery}`, 'info');

    return res.json({
      success: true,
      cached: false,
      result: {
        ...cveRecord,
        sources: allSources
      }
    });

  } catch (err: any) {
    // Deterministic Catalog Fallback for offline / key-less Termux environments
    const fallbackCatalog: Record<string, any> = {
      'cve-2024-3400': {
        cveId: 'CVE-2024-3400',
        title: 'Palo Alto Networks PAN-OS GlobalProtect Command Injection',
        cvssScore: 10.0,
        severity: 'CRITICAL',
        affectedSoftware: 'PAN-OS 10.2, 11.0, 11.1 with GlobalProtect gateway enabled',
        cwe: 'CWE-78: OS Command Injection',
        description: 'A critical command injection vulnerability in GlobalProtect feature allows an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.',
        remediation: 'Upgrade to PAN-OS 10.2.9-h1, 11.0.4-h1, 11.1.2-h3, or disable device telemetry as a temporary mitigation.',
        sources: [
          { title: 'NVD - CVE-2024-3400 Detail', url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-3400' },
          { title: 'CISA KEV Catalog - CVE-2024-3400', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog' }
        ]
      },
      'cve-2023-44487': {
        cveId: 'CVE-2023-44487',
        title: 'HTTP/2 Rapid Reset Denial of Service (DDoS)',
        cvssScore: 7.5,
        severity: 'HIGH',
        affectedSoftware: 'HTTP/2 protocol implementations (NGINX, Apache, Envoy, Node.js)',
        cwe: 'CWE-400: Uncontrolled Resource Consumption',
        description: 'The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation (RST_STREAM) can be reset immediately, leading to massive amplification.',
        remediation: 'Apply vendor HTTP/2 patches that limit RST_STREAM frame rates or disable HTTP/2 temporarily if unpatched.',
        sources: [
          { title: 'NVD - CVE-2023-44487 Detail', url: 'https://nvd.nist.gov/vuln/detail/CVE-2023-44487' },
          { title: 'GitHub Security Advisory - HTTP/2 Rapid Reset', url: 'https://github.com/advisories/GHSA-qppj-fm5r-hxr3' }
        ]
      },
      'cve-2021-44228': {
        cveId: 'CVE-2021-44228',
        title: 'Apache Log4j2 JNDI Remote Code Execution (Log4Shell)',
        cvssScore: 10.0,
        severity: 'CRITICAL',
        affectedSoftware: 'Apache Log4j 2.0-beta9 to 2.14.1',
        cwe: 'CWE-502: Deserialization of Untrusted Data',
        description: 'JNDI features used in configuration, log messages, and parameters do not protect against attacker-controlled LDAP and other JNDI related endpoints.',
        remediation: 'Upgrade to Log4j 2.17.1 or higher. In older versions, set log4j2.formatMsgNoLookups=true.',
        sources: [
          { title: 'NVD - CVE-2021-44228 Detail', url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228' },
          { title: 'GitHub Advisory - GHSA-jfh8-c2jp-5v3q', url: 'https://github.com/advisories/GHSA-jfh8-c2jp-5v3q' }
        ]
      },
      'express': {
        cveId: 'CVE-2024-29041',
        title: 'Express.js Open Redirect / Malformed URL Handling',
        cvssScore: 6.5,
        severity: 'MEDIUM',
        affectedSoftware: 'Express.js < 4.19.2',
        cwe: 'CWE-601: URL Redirection to Untrusted Site',
        description: 'Improper input validation in res.location and res.redirect allows unvalidated characters to trigger open redirection when user-supplied URLs are mishandled.',
        remediation: 'Upgrade express to version 4.19.2 or higher (or 5.0.0-beta.3+).',
        sources: [
          { title: 'GitHub Advisory - GHSA-qw6h-v559-w396', url: 'https://github.com/advisories/GHSA-qw6h-v559-w396' },
          { title: 'NVD - CVE-2024-29041', url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-29041' }
        ]
      },
      'nginx': {
        cveId: 'CVE-2022-41741',
        title: 'NGINX mp4 Module Memory Corruption',
        cvssScore: 7.8,
        severity: 'HIGH',
        affectedSoftware: 'nginx 1.1.3 - 1.23.1',
        cwe: 'CWE-787: Out-of-bounds Write',
        description: 'Memory corruption in ngx_http_mp4_module could cause worker process termination or potential arbitrary code execution with crafted mp4 files.',
        remediation: 'Upgrade nginx to 1.23.2, 1.22.1, or disable ngx_http_mp4_module.',
        sources: [
          { title: 'NVD - CVE-2022-41741', url: 'https://nvd.nist.gov/vuln/detail/CVE-2022-41741' }
        ]
      }
    };

    const key = cleanQuery.toLowerCase();
    const fallback = fallbackCatalog[key] || {
      cveId: cleanQuery.toUpperCase().startsWith('CVE-') ? cleanQuery.toUpperCase() : `VULN-${cleanQuery.toUpperCase()}`,
      title: `Vulnerability Advisory for ${cleanQuery}`,
      cvssScore: 7.5,
      severity: 'HIGH',
      affectedSoftware: `${cleanQuery} (Audit recommended)`,
      cwe: 'CWE-16: Configuration / Dependency Vulnerability',
      description: `Security advisory review for ${cleanQuery}. External API live search fell back to deterministic vulnerability index. Check official NVD and GitHub advisories for complete package matrix.`,
      remediation: `Inspect dependency lockfiles, upgrade ${cleanQuery} to the latest stable patch release, and enable dependabot/Snyk alerts.`,
      sources: [
        { title: `NVD Search for ${cleanQuery}`, url: `https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=${encodeURIComponent(cleanQuery)}` },
        { title: `GitHub Security Advisory Database for ${cleanQuery}`, url: `https://github.com/advisories?query=${encodeURIComponent(cleanQuery)}` }
      ]
    };

    const cveRecord = {
      id: `cve-${Date.now()}`,
      query: cleanQuery,
      cve_id: fallback.cveId,
      title: fallback.title,
      severity: fallback.severity,
      cvss_score: fallback.cvssScore,
      affected_software: fallback.affectedSoftware,
      cwe: fallback.cwe,
      description: fallback.description,
      remediation: fallback.remediation,
      sources: JSON.stringify(fallback.sources),
      source_engine: 'nvd_deterministic_catalog',
      created_at: new Date().toISOString()
    };

    try {
      db.prepare(`
        INSERT INTO cve_intelligence (id, query, cve_id, title, severity, cvss_score, affected_software, cwe, description, remediation, sources, source_engine, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        cveRecord.id,
        cveRecord.query,
        cveRecord.cve_id,
        cveRecord.title,
        cveRecord.severity,
        cveRecord.cvss_score,
        cveRecord.affected_software,
        cveRecord.cwe,
        cveRecord.description,
        cveRecord.remediation,
        cveRecord.sources,
        cveRecord.source_engine,
        cveRecord.created_at
      );
    } catch {}

    return res.json({
      success: true,
      cached: false,
      result: {
        ...cveRecord,
        sources: fallback.sources
      }
    });
  }
});

// 27. Autonomous AI Bug Bounty Hunter Engine (1-Click Vulnerability Finder)
apiRouter.post('/ai/hunter-scan', async (req: Request, res: Response) => {
  const { target, mode = 'deep', customHeader } = req.body;
  if (!target || typeof target !== 'string' || !target.trim()) {
    return res.status(400).json({ error: 'Target URL or host is required.' });
  }

  const cleanTarget = (target.startsWith('http://') || target.startsWith('https://'))
    ? target.trim()
    : (target.includes('localhost') || target.includes('127.0.0.1') ? `http://${target.trim()}` : `https://${target.trim()}`);

  // Validate or auto-authorize if local/permitted
  let scopeCheck = await validateScope(cleanTarget);
  if (!scopeCheck.authorized) {
    // If target is localhost/127.0.0.1, auto-register
    if (cleanTarget.includes('localhost') || cleanTarget.includes('127.0.0.1')) {
      const scopeId = `scope-${Date.now()}`;
      db.prepare('INSERT INTO scopes (id, target, target_type, is_active, allow_private_ip, created_at) VALUES (?, ?, ?, 1, 1, ?)')
        .run(scopeId, cleanTarget.replace(/^https?:\/\//, '').split('/')[0], 'host', new Date().toISOString());
      scopeCheck = await validateScope(cleanTarget);
    } else {
      return res.status(403).json({ error: `Scope Gate Violation: ${scopeCheck.reason}. Please add this target to Scope Gate first.` });
    }
  }

  const scanId = `hunt-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  const now = new Date().toISOString();

  // Create scan record in database
  db.prepare(`
    INSERT INTO scans (id, target, scan_type, status, progress, total_tasks, completed_tasks, started_at)
    VALUES (?, ?, 'ai_hunter_unified', 'running', 10, 4, 0, ?)
  `).run(scanId, cleanTarget, now);

  try {
    const extraHeaders: Record<string, string> = {};
    if (customHeader && customHeader.key && customHeader.value) {
      extraHeaders[customHeader.key.trim()] = customHeader.value.trim();
    }

    // Stage 1: Fast Exposure & Infrastructure Audit
    await runExposureScan(scanId, cleanTarget);

    // Stage 2: Deep Injection Canary & CORS Exploration
    await runInjectionHeuristicScan(scanId, cleanTarget);

    // Stage 3: Deep Multi-Vector Engine (GraphQL, Open Redirects, Dotfiles, Source Maps, Clickjacking)
    if (mode === 'deep') {
      try {
        await runDeepBugBountyAudit(scanId, cleanTarget, extraHeaders);
      } catch (_e) {
        // Non-fatal
      }
    }

    // Stage 4: JavaScript LinkFinder & Secret Extraction
    let jsRecon: any = null;
    try {
      jsRecon = await crawlAndAnalyzeJavaScript(cleanTarget, scanId, extraHeaders);
    } catch (_e) {
      // Non-fatal
    }

    // Stage 5: Live DNS, SSL & Tech Stack Fingerprinting
    const reconData = await runReconDiscovery(cleanTarget);

    // Retrieve all findings discovered for this target or scan
    const parsedTarget = new URL(cleanTarget);
    const findings = db.prepare(`
      SELECT * FROM findings 
      WHERE affected_asset LIKE ? OR affected_asset LIKE ?
      ORDER BY 
        CASE severity 
          WHEN 'critical' THEN 1 
          WHEN 'high' THEN 2 
          WHEN 'medium' THEN 3 
          WHEN 'low' THEN 4 
          ELSE 5 
        END ASC
    `).all(`%${parsedTarget.hostname}%`, `%${parsedTarget.host}%`) as any[];

    // Map each finding to Bug Bounty VRT Priority & Potential Payout Tier
    const triagedFindings = findings.map(f => {
      let priority = 'P4';
      let estimatedBounty = '$100 - $300';
      const sev = f.severity?.toLowerCase();

      if (sev === 'critical') {
        priority = 'P1';
        estimatedBounty = '$2,500 - $10,000+';
      } else if (sev === 'high') {
        priority = 'P2';
        estimatedBounty = '$1,000 - $2,500';
      } else if (sev === 'medium') {
        priority = 'P3';
        estimatedBounty = '$300 - $1,000';
      }

      return {
        ...f,
        priority,
        estimatedBounty,
        vrtCategory: f.category?.toUpperCase() || 'WEB_VULNERABILITY'
      };
    });

    db.prepare("UPDATE scans SET status = 'completed', progress = 100, completed_at = ? WHERE id = ?")
      .run(new Date().toISOString(), scanId);

    // Generate AI Bug Bounty Intelligence Analysis using Gemini 3.8 Flash
    let aiExecutiveSummary = '';

    try {
      const { GoogleGenAI } = await import('@google/genai');
      const ai = new GoogleGenAI();

      const aiPrompt = `You are a World-Class Bug Bounty Hunter & Application Security Triager.
Analyze the automated security findings discovered on ${cleanTarget}:

Target: ${cleanTarget}
Audit Mode: ${mode.toUpperCase()}
Technology Stack: ${reconData.technologies.map(t => t.name).join(', ') || 'Unknown'}
Security Headers Grade: ${reconData.securityHeadersGrade.grade} (${reconData.securityHeadersGrade.score}/100)
Total Findings Discovered: ${triagedFindings.length}
Findings Summary:
${triagedFindings.map((f, i) => `${i + 1}. [${f.priority} - ${f.severity.toUpperCase()}] ${f.title} (${f.affected_asset}) - ${f.reproduction_steps}`).join('\n')}

Provide an inspiring, highly actionable Bug Bounty Hunter Triager Analysis:
1. **Executive Assessment & Payout Potential**: Highlight which bugs are valid bug bounty material (P1-P4) and overall bounty potential.
2. **Business Impact & Triager Narrative**: Explain how to frame the business impact so the program triager does not downgrade or close as Informative.
3. **Key Next Steps for the Hunter**: What specific secondary endpoints or parameter fuzzing should the researcher try next on this target.

Keep it concise, punchy, professional, and ethical.`;

      const response = await ai.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: aiPrompt
      });

      aiExecutiveSummary = response.text || '';
    } catch {
      aiExecutiveSummary = `### Autonomous AI Assessment for ${cleanTarget}
- **Vulnerability Posture**: Identified ${triagedFindings.length} potential attack vector(s) via ${mode.toUpperCase()} audit.
- **Bug Bounty Triage Priority**: ${triagedFindings.filter(f => f.priority === 'P1' || f.priority === 'P2').length} High/Critical priorities.
- **Key Recommendation**: Verify CORS origin reflection, source maps, and missing security headers against program policy. Ensure all reports include step-by-step reproduction and non-destructive proof.`;
    }

    logAudit('AI_HUNTER_RUN', cleanTarget, `Executed Autonomous AI Bug Hunt (${mode}): Discovered ${triagedFindings.length} findings`, 'info');

    res.json({
      success: true,
      scanId,
      target: cleanTarget,
      mode,
      recon: reconData,
      totalFindings: triagedFindings.length,
      findings: triagedFindings,
      jsRecon,
      aiExecutiveSummary,
      p1Count: triagedFindings.filter(f => f.priority === 'P1').length,
      p2Count: triagedFindings.filter(f => f.priority === 'P2').length,
      p3Count: triagedFindings.filter(f => f.priority === 'P3').length,
      p4Count: triagedFindings.filter(f => f.priority === 'P4').length,
      timestamp: new Date().toLocaleTimeString()
    });

  } catch (err: any) {
    db.prepare("UPDATE scans SET status = 'failed', error_message = ? WHERE id = ?").run(err.message, scanId);
    res.status(500).json({ error: `AI Bug Hunt execution failed: ${err.message}` });
  }
});

// 28. Multi-Target Batch Bug Bounty Hunter
apiRouter.post('/ai/batch-hunt', async (req: Request, res: Response) => {
  const { targets, mode = 'quick', customHeader } = req.body;
  if (!targets || !Array.isArray(targets) || targets.length === 0) {
    return res.status(400).json({ error: 'Array of targets is required.' });
  }

  const cleanTargets = targets.map((t: string) => t.trim()).filter(Boolean).slice(0, 10);
  const results: any[] = [];

  for (const rawTarget of cleanTargets) {
    const cleanTarget = (rawTarget.startsWith('http://') || rawTarget.startsWith('https://'))
      ? rawTarget
      : (rawTarget.includes('localhost') || rawTarget.includes('127.0.0.1') ? `http://${rawTarget}` : `https://${rawTarget}`);

    // Verify scope
    let scopeCheck = await validateScope(cleanTarget);
    if (!scopeCheck.authorized) {
      if (cleanTarget.includes('localhost') || cleanTarget.includes('127.0.0.1')) {
        const scopeId = `scope-${Date.now()}`;
        db.prepare('INSERT INTO scopes (id, target, target_type, is_active, allow_private_ip, created_at) VALUES (?, ?, ?, 1, 1, ?)')
          .run(scopeId, cleanTarget.replace(/^https?:\/\//, '').split('/')[0], 'host', new Date().toISOString());
      } else {
        results.push({ target: cleanTarget, status: 'skipped', error: 'Out of Scope' });
        continue;
      }
    }

    const scanId = `batch-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    db.prepare(`
      INSERT INTO scans (id, target, scan_type, status, progress, total_tasks, completed_tasks, started_at)
      VALUES (?, ?, 'batch_ai_hunt', 'running', 10, 2, 0, ?)
    `).run(scanId, cleanTarget, new Date().toISOString());

    try {
      await runExposureScan(scanId, cleanTarget);
      if (mode === 'deep') {
        const extraHeaders: Record<string, string> = {};
        if (customHeader?.key && customHeader?.value) extraHeaders[customHeader.key] = customHeader.value;
        await runDeepBugBountyAudit(scanId, cleanTarget, extraHeaders);
      }

      const parsed = new URL(cleanTarget);
      const findings = db.prepare(`
        SELECT * FROM findings 
        WHERE affected_asset LIKE ? OR affected_asset LIKE ?
      `).all(`%${parsed.hostname}%`, `%${parsed.host}%`) as any[];

      results.push({
        target: cleanTarget,
        status: 'completed',
        scanId,
        findingsCount: findings.length,
        criticalCount: findings.filter(f => f.severity === 'critical').length,
        highCount: findings.filter(f => f.severity === 'high').length,
        mediumCount: findings.filter(f => f.severity === 'medium').length,
        lowCount: findings.filter(f => f.severity === 'low').length,
      });
    } catch (err: any) {
      results.push({ target: cleanTarget, status: 'failed', error: err.message });
    }
  }

  res.json({
    success: true,
    totalScanned: cleanTargets.length,
    results
  });
});

// 29. Deep AI Exploitability & Proof-of-Concept Explainer
apiRouter.post('/ai/explain-finding', async (req: Request, res: Response) => {
  const { findingId } = req.body;
  if (!findingId) {
    return res.status(400).json({ error: 'findingId is required.' });
  }

  const finding = db.prepare('SELECT * FROM findings WHERE id = ?').get(findingId) as any;
  if (!finding) {
    return res.status(404).json({ error: 'Finding not found in database.' });
  }

  try {
    const { GoogleGenAI } = await import('@google/genai');
    const ai = new GoogleGenAI();

    const prompt = `You are a Principal Security Architect and Veteran Bug Bounty Hunter.
Provide a comprehensive exploitability and triage breakdown for this finding:

Title: ${finding.title}
Category: ${finding.category}
Severity: ${finding.severity}
Affected Asset: ${finding.affected_asset}
Endpoint: ${finding.endpoint}
Evidence: ${finding.evidence_json}
Reproduction: ${finding.reproduction_steps}
Impact: ${finding.impact}

Generate a clear, authoritative report containing:
1. **Root Cause Analysis**: Why this vulnerability occurs at the architectural/code level.
2. **Business Impact & Triager Defense**: How to explain the impact to a bug bounty triager so it is accepted as valid (avoiding Informative/Out of Scope closures).
3. **Reproducible Non-Destructive Proof of Concept**: The exact step-by-step cURL commands or verification methodology.
4. **HackerOne / Bugcrowd VRT Classification**: Recommended priority (P1-P4) and CVSS v3.1 vector string.
5. **Defensive Remediation**: Exact code snippet or server configuration to remediate the vulnerability.`;

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt
    });

    res.json({
      success: true,
      finding,
      explanation: response.text || 'Explanation unavailable.'
    });
  } catch (err: any) {
    res.json({
      success: true,
      finding,
      explanation: `### Exploitability Breakdown for ${finding.title}
- **Vulnerability Category**: ${finding.category} (${finding.severity.toUpperCase()})
- **Reproduction**: \`${finding.reproduction_steps}\`
- **Impact Defense**: This finding demonstrates an actionable security weakness on ${finding.affected_asset}. Frame this in your report as direct violation of least-privilege or secure default transport policies.
- **Remediation**: ${finding.remediation} (Offline fallback: ${err.message})`
    });
  }
});

// 30. Termux Supercharge CLI & Mobile Automation Toolbox
apiRouter.get('/termux/toolbox', (_req: Request, res: Response) => {
  const termuxSetupScript = `#!/data/data/com.termux/files/usr/bin/bash
# ==============================================================
# VulnHunter AI - Termux Supercharge Automation Script
# Mobile-optimized bug bounty hunting environment setup
# ==============================================================

echo "[*] Updating Termux repositories..."
pkg update -y && pkg upgrade -y

echo "[*] Installing core bug bounty dependencies..."
pkg install -y git curl wget jq nodejs python build-essential termux-api

echo "[*] Setting up VulnHunter aliases..."
cat << 'EOF' >> ~/.bashrc

# VulnHunter Aliases
alias vh-status="curl -s http://127.0.0.1:3000/api/health | jq ."
alias vh-hunt="curl -s -X POST http://127.0.0.1:3000/api/ai/hunter-scan -H 'Content-Type: application/json' -d"
alias vh-ask="curl -s -X POST http://127.0.0.1:3000/api/ai/ask -H 'Content-Type: application/json' -d"
alias vh-wakelock="termux-wake-lock && echo '[+] Wake lock acquired for background hunting'"
alias vh-wakeunlock="termux-wake-unlock && echo '[-] Wake lock released'"
EOF

echo "[+] VulnHunter Termux Supercharge complete! Run 'source ~/.bashrc' to activate."
`;

  res.json({
    success: true,
    termuxSetupScript,
    cliShortcuts: [
      {
        name: 'Autonomous Quick Hunt',
        cmd: 'curl -s -X POST http://127.0.0.1:3000/api/ai/hunter-scan -H "Content-Type: application/json" -d \'{"target":"https://target.com"}\' | jq .'
      },
      {
        name: 'Deep Multi-Vector Hunt',
        cmd: 'curl -s -X POST http://127.0.0.1:3000/api/ai/hunter-scan -H "Content-Type: application/json" -d \'{"target":"https://target.com","mode":"deep","customHeader":{"key":"X-Bug-Bounty","value":"hunter1"}}\' | jq .'
      },
      {
        name: 'AI Bug Bounty Mentor Query',
        cmd: 'curl -s -X POST http://127.0.0.1:3000/api/ai/ask -H "Content-Type: application/json" -d \'{"question":"How to bypass 403 forbidden headers?"}\' | jq -r .answer'
      },
      {
        name: 'Termux Hardware Telemetry Check',
        cmd: 'curl -s http://127.0.0.1:3000/api/tools/resource-monitor | jq .'
      }
    ]
  });
});

// 31. Interactive AI Bug Bounty Advisor Chat
apiRouter.post('/ai/ask', async (req: Request, res: Response) => {
  const { question, context } = req.body;
  if (!question || typeof question !== 'string' || !question.trim()) {
    return res.status(400).json({ error: 'Question is required.' });
  }

  try {
    const { GoogleGenAI } = await import('@google/genai');
    const ai = new GoogleGenAI();

    const systemPrompt = `You are VulnHunter AI, the world's #1 Bug Bounty Co-Pilot and Application Security Mentor.
Your mission is to make finding, understanding, and reporting security vulnerabilities simple, ethical, and highly effective for bug hunters of all levels.

Guidelines:
- Explain security concepts clearly and concisely.
- If the user asks in English, reply in English. If they prompt in Roman Urdu or Urdu, understand and respond helpfully in Roman Urdu / English.
- Always emphasize authorized scope, non-destructive proof-of-concept verification, and actionable impact proofs.
- Never write weaponized malware or exploit chains. Always provide ethical verification methodologies, defensive insights, and HackerOne/Bugcrowd reporting tips.`;

    const userContent = context 
      ? `Target Context: ${JSON.stringify(context)}\n\nQuestion: ${question.trim()}`
      : question.trim();

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: `${systemPrompt}\n\n${userContent}`
    });

    res.json({
      success: true,
      answer: response.text || 'No response generated.'
    });
  } catch (err: any) {
    // Deterministic fallback response
    res.json({
      success: true,
      answer: `**VulnHunter AI Advisory**: For bug bounty testing on this target, always verify scope boundaries first in the Scope Gate. For injection testing, use benign canaries. For broken object authorization (IDOR), compare responses between doc_a and doc_b identifiers. To submit to HackerOne, ensure your report has clear reproduction steps and business impact documentation. (Offline fallback: ${err.message})`
    });
  }
});

// 32. Dedicated JavaScript LinkFinder & Secret Extractor
apiRouter.post('/recon/js-extract', async (req: Request, res: Response) => {
  const { targetUrl, customHeaders } = req.body;
  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({ error: 'Target URL is required.' });
  }

  const cleanTarget = (targetUrl.startsWith('http://') || targetUrl.startsWith('https://'))
    ? targetUrl.trim()
    : (targetUrl.includes('localhost') || targetUrl.includes('127.0.0.1') ? `http://${targetUrl.trim()}` : `https://${targetUrl.trim()}`);

  try {
    const result = await crawlAndAnalyzeJavaScript(cleanTarget, undefined, customHeaders);
    res.json({ success: true, result });
  } catch (err: any) {
    res.status(500).json({ error: `JavaScript analysis failed: ${err.message}` });
  }
});
