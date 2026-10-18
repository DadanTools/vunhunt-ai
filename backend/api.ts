/**
 * VulnHunter AI - Express Backend API Routes
 * Modular router handling scope enforcement, scanners, findings, proxy, and audit logs.
 */

import { Router, Request, Response } from 'express';
import crypto from 'node:crypto';
import { db } from './db.js';
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
  safeHttpRequest 
} from './scanner_engine.js';
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
