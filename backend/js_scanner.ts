/**
 * VulnHunter AI - Advanced JavaScript & Hidden Endpoint Hunter
 * LinkFinder & Secret Extraction Engine for Bug Bounty Hunting
 */

import { safeHttpRequest, persistFinding, FindingRecord } from './scanner_engine.js';
import { validateScope, logAudit } from './scope_gate.js';
import crypto from 'node:crypto';

export interface DiscoveredEndpoint {
  endpoint: string;
  foundInScript: string;
  category: 'admin' | 'internal' | 'auth' | 'graphql' | 'api' | 'public';
  severity: 'critical' | 'high' | 'medium' | 'low';
  contextSnippet: string;
}

export interface DiscoveredSecret {
  type: string;
  title: string;
  secret: string;
  foundInScript: string;
  severity: 'critical' | 'high' | 'medium';
  priority: 'P1' | 'P2' | 'P3';
  evidence: string;
}

export interface DomXssSink {
  sink: string;
  foundInScript: string;
  snippet: string;
}

export interface SourceMapRef {
  scriptUrl: string;
  mapUrl: string;
  isAccessible: boolean;
  statusCode?: number;
}

export interface JsAnalysisResult {
  targetUrl: string;
  totalScriptsAnalyzed: number;
  scripts: Array<{
    url: string;
    sizeBytes: number;
    hasSourceMap: boolean;
    sourceMapUrl?: string;
  }>;
  hiddenEndpoints: DiscoveredEndpoint[];
  discoveredSecrets: DiscoveredSecret[];
  domXssSinks: DomXssSink[];
  sourceMaps: SourceMapRef[];
  timestamp: string;
}

/**
 * Secret patterns tailored for Bug Bounty Discovery
 */
const SECRET_PATTERNS: Array<{
  type: string;
  title: string;
  regex: RegExp;
  severity: 'critical' | 'high' | 'medium';
  priority: 'P1' | 'P2' | 'P3';
}> = [
  {
    type: 'google_api_key',
    title: 'Exposed Google Cloud / Maps API Key',
    regex: /AIza[0-9A-Za-z_-]{35}/g,
    severity: 'medium',
    priority: 'P3'
  },
  {
    type: 'aws_access_key',
    title: 'Exposed AWS Access Key ID',
    regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
    severity: 'critical',
    priority: 'P1'
  },
  {
    type: 'jwt_token',
    title: 'Hardcoded JSON Web Token (JWT)',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    severity: 'high',
    priority: 'P2'
  },
  {
    type: 'firebase_db',
    title: 'Exposed Firebase Realtime Database URL',
    regex: /https:\/\/[a-z0-9-]+\.firebaseio\.com/gi,
    severity: 'medium',
    priority: 'P3'
  },
  {
    type: 'aws_s3_bucket',
    title: 'Exposed Cloud Storage (S3 / GCS) Bucket',
    regex: /(?:[a-z0-9.-]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com|storage\.googleapis\.com\/[a-z0-9.-]+)/gi,
    severity: 'medium',
    priority: 'P3'
  },
  {
    type: 'generic_api_secret',
    title: 'Hardcoded API Secret / Key Assignment',
    regex: /(?:api_secret|client_secret|clientSecret|secretKey|secret_key|authToken|auth_token)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{16,80})['"]/gi,
    severity: 'high',
    priority: 'P2'
  },
  {
    type: 'private_key',
    title: 'Hardcoded Private Key Header',
    regex: /-----BEGIN (?:RSA )?PRIVATE KEY-----/g,
    severity: 'critical',
    priority: 'P1'
  }
];

/**
 * Common DOM XSS Sinks in Client-Side JavaScript
 */
const DOM_XSS_SINKS: Array<{ sink: string; regex: RegExp }> = [
  { sink: 'innerHTML / outerHTML', regex: /\.(innerHTML|outerHTML)\s*=\s*[^;\n]+/gi },
  { sink: 'document.write', regex: /document\.write(?:ln)?\s*\([^;\n]+\)/gi },
  { sink: 'eval execution', regex: /(?:^|[^a-zA-Z0-9_])eval\s*\([^;\n]+\)/gi },
  { sink: 'location assignment', regex: /(?:window\.)?location\.(?:href|assign|replace)\s*=\s*[^;\n]+/gi }
];

/**
 * Main JavaScript Scraping & Link/Secret Extraction Engine
 */
export async function crawlAndAnalyzeJavaScript(
  targetUrl: string,
  scanId?: string,
  customHeaders?: Record<string, string>
): Promise<JsAnalysisResult> {
  const scopeCheck = await validateScope(targetUrl);
  if (!scopeCheck.authorized) {
    throw new Error(`Scope Check Failed: ${scopeCheck.reason}`);
  }

  const baseHeaders = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) VulnHunter-JS-Analyzer/2.0',
    ...(customHeaders || {})
  };

  logAudit('JS_ANALYSIS_START', targetUrl, `Initiating JS link & secret extraction for ${targetUrl}`, 'info');

  const scriptsToAnalyze: Array<{ url: string; content?: string }> = [];
  const targetParsed = new URL(targetUrl);

  // 1. Fetch Root Page HTML
  let rootHtml = '';
  try {
    const rootRes = await safeHttpRequest(targetUrl, {
      method: 'GET',
      headers: baseHeaders,
      maxBytes: 128 * 1024
    });
    rootHtml = rootRes.body;
  } catch (err: any) {
    throw new Error(`Failed to fetch root HTML for script discovery: ${err.message}`);
  }

  // 2. Discover External Script URLs from HTML
  const scriptTagRegex = /<script\b[^>]*?\bsrc=['"]([^'"]+?)['"][^>]*?>/gi;
  let match: RegExpExecArray | null;

  while ((match = scriptTagRegex.exec(rootHtml)) !== null) {
    const rawSrc = match[1];
    if (!rawSrc || rawSrc.startsWith('data:')) continue;

    try {
      const fullUrl = new URL(rawSrc, targetUrl).toString();
      if (!scriptsToAnalyze.some(s => s.url === fullUrl)) {
        scriptsToAnalyze.push({ url: fullUrl });
      }
    } catch {}
  }

  // Also check common JavaScript build paths if no scripts found
  if (scriptsToAnalyze.length === 0) {
    const commonPaths = ['/main.js', '/app.js', '/bundle.js', '/assets/index.js'];
    for (const cp of commonPaths) {
      scriptsToAnalyze.push({ url: new URL(cp, targetUrl).toString() });
    }
  }

  const result: JsAnalysisResult = {
    targetUrl,
    totalScriptsAnalyzed: 0,
    scripts: [],
    hiddenEndpoints: [],
    discoveredSecrets: [],
    domXssSinks: [],
    sourceMaps: [],
    timestamp: new Date().toLocaleTimeString()
  };

  const seenEndpoints = new Set<string>();
  const seenSecrets = new Set<string>();

  // 3. Download and Analyze Each Script (Up to 8 scripts to ensure low Termux RAM)
  const scriptsSlice = scriptsToAnalyze.slice(0, 8);

  for (const item of scriptsSlice) {
    try {
      const sRes = await safeHttpRequest(item.url, {
        method: 'GET',
        headers: baseHeaders,
        maxBytes: 256 * 1024 // 256KB cap per script
      });

      if (sRes.statusCode !== 200 || !sRes.body) continue;

      const jsContent = sRes.body;
      result.totalScriptsAnalyzed++;

      // Check for SourceMap declaration
      const smMatch = jsContent.match(/\/\/#\s*sourceMappingURL=([^\s]+)/i);
      let hasSourceMap = false;
      let sourceMapUrl: string | undefined;

      if (smMatch && smMatch[1]) {
        hasSourceMap = true;
        try {
          sourceMapUrl = new URL(smMatch[1], item.url).toString();
        } catch {
          sourceMapUrl = `${item.url}.map`;
        }
      }

      result.scripts.push({
        url: item.url,
        sizeBytes: jsContent.length,
        hasSourceMap,
        sourceMapUrl
      });

      // If Source Map is referenced, verify if publicly accessible
      if (sourceMapUrl) {
        try {
          const mapRes = await safeHttpRequest(sourceMapUrl, { method: 'HEAD', headers: baseHeaders });
          const isAccessible = mapRes.statusCode === 200;
          result.sourceMaps.push({
            scriptUrl: item.url,
            mapUrl: sourceMapUrl,
            isAccessible,
            statusCode: mapRes.statusCode
          });

          if (isAccessible && scanId) {
            persistFinding({
              scan_id: scanId,
              title: 'Exposed Frontend JavaScript Source Map (.map)',
              category: 'sensitive_exposure',
              severity: 'medium',
              confidence: 'certain',
              affected_asset: targetParsed.host,
              endpoint: sourceMapUrl,
              evidence_json: JSON.stringify({ script: item.url, sourceMapUrl }),
              reproduction_steps: `curl -s -I "${sourceMapUrl}"`,
              impact: 'P3 Medium Bounty: Full original unminified client-side source code and developer comments are publicly downloadable.',
              remediation: 'Remove .map files from production deployments or restrict access via web server directives.',
              verification_status: 'verified-in-authorized-lab',
              source_tool: 'js_analyzer',
              fingerprint: crypto.createHash('sha256').update(`${targetParsed.host}:map:${sourceMapUrl}`).digest('hex')
            });
          }
        } catch {}
      }

      // --- A. Extract Hidden Links & Endpoints (LinkFinder Algorithm) ---
      // Pattern 1: Explicit quoted paths starting with /
      const pathQuotedRegex = /['"`](\/(?:api|v[0-9]|rest|graphql|admin|internal|auth|v1|v2|v3|users|login|register|dashboard|account|upload|download|export|import|webhook|token|secret|debug|metrics|actuator)[a-zA-Z0-9_\-\.\/\?=&]*)['"`]/gi;
      let pMatch: RegExpExecArray | null;

      while ((pMatch = pathQuotedRegex.exec(jsContent)) !== null) {
        const rawEndpoint = pMatch[1];
        if (!rawEndpoint || seenEndpoints.has(rawEndpoint) || rawEndpoint.length < 3) continue;
        seenEndpoints.add(rawEndpoint);

        // Determine category & severity
        let category: DiscoveredEndpoint['category'] = 'api';
        let severity: DiscoveredEndpoint['severity'] = 'low';

        if (rawEndpoint.includes('/admin') || rawEndpoint.includes('/internal') || rawEndpoint.includes('/debug') || rawEndpoint.includes('/actuator')) {
          category = 'admin';
          severity = 'critical';
        } else if (rawEndpoint.includes('/auth') || rawEndpoint.includes('/token') || rawEndpoint.includes('/login') || rawEndpoint.includes('/users')) {
          category = 'auth';
          severity = 'high';
        } else if (rawEndpoint.includes('/graphql') || rawEndpoint.includes('/gql')) {
          category = 'graphql';
          severity = 'medium';
        }

        const snippetStart = Math.max(0, pMatch.index - 30);
        const snippetEnd = Math.min(jsContent.length, pMatch.index + rawEndpoint.length + 30);
        const contextSnippet = jsContent.slice(snippetStart, snippetEnd).replace(/\s+/g, ' ');

        result.hiddenEndpoints.push({
          endpoint: rawEndpoint,
          foundInScript: item.url,
          category,
          severity,
          contextSnippet
        });

        // If high or critical endpoint discovered and in scan context, persist candidate finding
        if ((severity === 'critical' || severity === 'high') && scanId) {
          persistFinding({
            scan_id: scanId,
            title: `Hidden ${category.toUpperCase()} Endpoint Discovered in JavaScript: ${rawEndpoint}`,
            category: 'information_disclosure',
            severity,
            confidence: 'firm',
            affected_asset: targetParsed.host,
            endpoint: rawEndpoint,
            evidence_json: JSON.stringify({ script: item.url, endpoint: rawEndpoint, snippet: contextSnippet }),
            reproduction_steps: `curl -s "${new URL(rawEndpoint, targetUrl).toString()}"`,
            impact: `${severity === 'critical' ? 'P1/P2' : 'P2/P3'} Bounty: Sensitive hidden endpoint exposed in compiled client bundle, expanding attack surface.`,
            remediation: 'Ensure backend routing enforces robust authentication and authorization checks irrespective of client bundling.',
            verification_status: 'needs-review',
            source_tool: 'js_analyzer',
            fingerprint: crypto.createHash('sha256').update(`${targetParsed.host}:endpoint:${rawEndpoint}`).digest('hex')
          });
        }
      }

      // --- B. Extract Exposed Secrets & API Keys ---
      for (const pattern of SECRET_PATTERNS) {
        let sMatch: RegExpExecArray | null;
        pattern.regex.lastIndex = 0;

        while ((sMatch = pattern.regex.exec(jsContent)) !== null) {
          const secretFound = sMatch[1] || sMatch[0];
          if (!secretFound || seenSecrets.has(secretFound)) continue;
          seenSecrets.add(secretFound);

          const snipStart = Math.max(0, sMatch.index - 35);
          const snipEnd = Math.min(jsContent.length, sMatch.index + secretFound.length + 35);
          const evidence = jsContent.slice(snipStart, snipEnd).replace(/\s+/g, ' ');

          result.discoveredSecrets.push({
            type: pattern.type,
            title: pattern.title,
            secret: secretFound.length > 30 ? `${secretFound.slice(0, 15)}...${secretFound.slice(-6)}` : secretFound,
            foundInScript: item.url,
            severity: pattern.severity,
            priority: pattern.priority,
            evidence
          });

          if (scanId) {
            persistFinding({
              scan_id: scanId,
              title: pattern.title,
              category: 'credential_leak',
              severity: pattern.severity,
              confidence: 'firm',
              affected_asset: targetParsed.host,
              endpoint: item.url,
              evidence_json: JSON.stringify({ type: pattern.type, evidence }),
              reproduction_steps: `curl -s "${item.url}" | grep -C 2 "${secretFound.slice(0, 10)}"`,
              impact: `${pattern.priority} Bounty: Hardcoded credentials or cloud tokens in frontend JavaScript files allow unauthorized platform access.`,
              remediation: 'Rotate leaked credentials immediately and proxy third-party API interactions through a protected backend.',
              verification_status: 'verified-in-authorized-lab',
              source_tool: 'js_analyzer',
              fingerprint: crypto.createHash('sha256').update(`${targetParsed.host}:secret:${secretFound}`).digest('hex')
            });
          }
        }
      }

      // --- C. Extract DOM XSS Sinks ---
      for (const sinkDef of DOM_XSS_SINKS) {
        sinkDef.regex.lastIndex = 0;
        let sinkMatch: RegExpExecArray | null;
        if ((sinkMatch = sinkDef.regex.exec(jsContent)) !== null) {
          result.domXssSinks.push({
            sink: sinkDef.sink,
            foundInScript: item.url,
            snippet: sinkMatch[0].slice(0, 80)
          });
        }
      }

    } catch (_err) {
      // Continue to next script
    }
  }

  logAudit(
    'JS_ANALYSIS_COMPLETE',
    targetUrl,
    `Analyzed ${result.totalScriptsAnalyzed} JS files. Discovered ${result.hiddenEndpoints.length} endpoints and ${result.discoveredSecrets.length} secrets.`,
    'info'
  );

  return result;
}
