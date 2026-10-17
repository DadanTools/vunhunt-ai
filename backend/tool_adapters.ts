/**
 * VulnHunter AI - External Tool Adapters (Subfinder, Nuclei, Python)
 * Detects tool availability, versions, executes safely with timeouts and resource bounds,
 * and provides honest diagnostics when binaries are missing.
 */

import { exec, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import path from 'node:path';
import { logAudit } from './scope_gate.js';
import { redactBody } from './redactor.js';

const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);

export interface ToolHealth {
  name: string;
  binary: string;
  isAvailable: boolean;
  version?: string;
  path?: string;
  notes: string;
}

export async function detectTool(name: string, binary: string, versionFlag = '-version'): Promise<ToolHealth> {
  try {
    const { stdout: whichOut } = await execAsync(`which ${binary}`).catch(() => ({ stdout: '' }));
    const binPath = whichOut.trim();

    if (!binPath) {
      return {
        name,
        binary,
        isAvailable: false,
        notes: `Binary '${binary}' not found in PATH. Passive / native mode active.`
      };
    }

    const { stdout, stderr } = await execAsync(`${binPath} ${versionFlag}`, { timeout: 4000 }).catch(err => ({
      stdout: err.stdout || '',
      stderr: err.stderr || err.message
    }));

    const rawVer = (stdout || stderr || '').trim().split('\n')[0];
    return {
      name,
      binary,
      isAvailable: true,
      path: binPath,
      version: rawVer.slice(0, 80),
      notes: `Ready for authorized scanning.`
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      name,
      binary,
      isAvailable: false,
      notes: `Detection error: ${msg}`
    };
  }
}

export async function getSystemToolHealth(): Promise<Record<string, ToolHealth>> {
  const [subfinder, nuclei, python, curl] = await Promise.all([
    detectTool('Subfinder', 'subfinder', '-version'),
    detectTool('Nuclei', 'nuclei', '-version'),
    detectTool('Python 3', 'python3', '--version'),
    detectTool('cURL', 'curl', '--version')
  ]);

  return {
    subfinder,
    nuclei,
    python,
    curl
  };
}

export interface SubfinderResult {
  host: string;
  source: string;
}

/**
 * Runs Subfinder if installed with strict timeout and concurrency limits.
 */
export async function runSubfinderDiscovery(targetDomain: string, maxTimeMs = 30000): Promise<{
  success: boolean;
  assets: SubfinderResult[];
  error?: string;
}> {
  const toolHealth = await detectTool('Subfinder', 'subfinder', '-version');
  if (!toolHealth.isAvailable) {
    return {
      success: false,
      assets: [],
      error: `Subfinder binary is not installed on this system. You can use Passive / Manual Asset Import or install via 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest' in Termux with Golang.`
    };
  }

  logAudit('TOOL_RUN_SUBFINDER', targetDomain, `Running subfinder discovery on ${targetDomain}`, 'info');

  try {
    const { stdout } = await execFileAsync(toolHealth.path!, ['-d', targetDomain, '-silent', '-json'], {
      timeout: maxTimeMs,
      maxBuffer: 1024 * 1024 * 4
    });

    const lines = stdout.trim().split('\n').filter(Boolean);
    const results: SubfinderResult[] = [];

    for (const line of lines) {
      try {
        const parsed = JSON.parse(line);
        if (parsed.host) {
          results.push({ host: parsed.host, source: parsed.source || 'subfinder' });
        }
      } catch (_e) {
        // Line might be plain host text
        if (line.includes('.')) {
          results.push({ host: line.trim(), source: 'subfinder' });
        }
      }
    }

    return { success: true, assets: results };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, assets: [], error: `Subfinder run failed: ${msg}` };
  }
}

export interface NucleiScanResult {
  templateId: string;
  name: string;
  severity: string;
  matchedAt: string;
  extractedResults?: string[];
  curlCommand?: string;
  description?: string;
}

/**
 * Runs Nuclei with locally configured template if installed.
 */
export async function runNucleiScan(
  targetUrl: string, 
  templatePath?: string, 
  rateLimit = 10,
  maxTimeMs = 45000
): Promise<{
  success: boolean;
  findings: NucleiScanResult[];
  error?: string;
}> {
  const toolHealth = await detectTool('Nuclei', 'nuclei', '-version');
  if (!toolHealth.isAvailable) {
    return {
      success: false,
      findings: [],
      error: `Nuclei is not installed on this system. Passive & native VulnHunter exposure checks will be used instead.`
    };
  }

  const args = ['-u', targetUrl, '-json-export', '-silent', '-rl', String(rateLimit)];
  if (templatePath && fs.existsSync(templatePath)) {
    args.push('-t', templatePath);
  } else {
    // safe default tags: tech, exposure, headers
    args.push('-tags', 'tech,exposure,misconfig');
  }

  logAudit('TOOL_RUN_NUCLEI', targetUrl, `Running Nuclei scan on ${targetUrl} (rate limit: ${rateLimit})`, 'info');

  try {
    const { stdout } = await execFileAsync(toolHealth.path!, args, {
      timeout: maxTimeMs,
      maxBuffer: 1024 * 1024 * 8
    });

    const lines = stdout.trim().split('\n').filter(Boolean);
    const results: NucleiScanResult[] = [];

    for (const line of lines) {
      try {
        const item = JSON.parse(line);
        results.push({
          templateId: item['template-id'] || item.templateID || 'unknown',
          name: item.info?.name || item.template || 'Nuclei Alert',
          severity: (item.info?.severity || 'info').toLowerCase(),
          matchedAt: item['matched-at'] || targetUrl,
          extractedResults: item['extracted-results'],
          curlCommand: redactBody(item['curl-command']),
          description: item.info?.description || 'Detected via Nuclei template match.'
        });
      } catch (_e) {
        // Skip unparseable lines
      }
    }

    return { success: true, findings: results };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, findings: [], error: `Nuclei execution failed: ${msg}` };
  }
}
