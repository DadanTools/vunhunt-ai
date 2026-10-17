/**
 * VulnHunter AI - Burp-Style Local HTTP Proxy & Repeater Engine
 * Records HTTP traffic, enforces scope, logs to SQLite, and provides an interactive request repeater.
 */

import http from 'node:http';
import { db } from './db.js';
import { validateScope, logAudit } from './scope_gate.js';
import { safeHttpRequest, HttpRequestOptions } from './scanner_engine.js';
import { redactHeaders, redactBody } from './redactor.js';

let proxyServer: http.Server | null = null;
let proxyPort = 8081;
let isProxyRunning = false;

export interface ProxyLogEntry {
  id: string;
  method: string;
  url: string;
  host: string;
  path: string;
  request_headers: string;
  request_body?: string;
  status_code?: number;
  response_headers?: string;
  response_body?: string;
  duration_ms?: number;
  is_in_scope: number;
  created_at: string;
}

export function startLocalProxy(port = 8081): Promise<{ success: boolean; port: number; message: string }> {
  if (isProxyRunning) {
    return Promise.resolve({ success: true, port: proxyPort, message: `Proxy already listening on 127.0.0.1:${proxyPort}` });
  }

  proxyPort = port;

  return new Promise((resolve) => {
    proxyServer = http.createServer(async (clientReq, clientRes) => {
      const startTime = Date.now();
      const rawUrl = clientReq.url || '/';
      let targetUrl: string;

      try {
        if (rawUrl.startsWith('http://') || rawUrl.startsWith('https://')) {
          targetUrl = rawUrl;
        } else {
          targetUrl = `http://${clientReq.headers.host || 'localhost'}${rawUrl}`;
        }
      } catch (_e) {
        clientRes.writeHead(400, { 'Content-Type': 'text/plain' });
        clientRes.end('Bad Request: Malformed URL');
        return;
      }

      // Collect request body
      let reqBody = '';
      clientReq.on('data', chunk => {
        if (reqBody.length < 32768) reqBody += chunk.toString('utf-8');
      });

      clientReq.on('end', async () => {
        // Enforce server-side scope gate
        const scopeResult = await validateScope(targetUrl);
        const logId = 'prx-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6);
        const parsed = new URL(targetUrl);

        if (!scopeResult.authorized) {
          logAudit('PROXY_SCOPE_BLOCKED', targetUrl, `Proxy blocked outbound request: ${scopeResult.reason}`, 'warning');
          
          db.prepare(`
            INSERT INTO proxy_logs (id, method, url, host, path, request_headers, request_body, status_code, response_headers, response_body, duration_ms, is_in_scope, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).run(
            logId, clientReq.method || 'GET', targetUrl, parsed.host, parsed.pathname,
            JSON.stringify(redactHeaders(clientReq.headers as any)),
            redactBody(reqBody), 403, JSON.stringify({ 'x-vulnhunter-gate': 'blocked' }),
            `Blocked by VulnHunter AI Scope Gate: ${scopeResult.reason}`, 0, 0, new Date().toISOString()
          );

          clientRes.writeHead(403, { 'Content-Type': 'application/json' });
          clientRes.end(JSON.stringify({
            error: 'Target outside authorized scope',
            reason: scopeResult.reason,
            safety_gate: 'VulnHunter AI Scope Enforcement'
          }));
          return;
        }

        // Forward authorized request
        try {
          const forwardHeaders: Record<string, string> = {};
          for (const [k, v] of Object.entries(clientReq.headers)) {
            if (k.toLowerCase() !== 'host' && v) {
              forwardHeaders[k] = Array.isArray(v) ? v.join(', ') : v;
            }
          }

          const response = await safeHttpRequest(targetUrl, {
            method: clientReq.method,
            headers: forwardHeaders,
            body: reqBody || undefined,
            timeoutMs: 10000
          });

          // Log transaction
          db.prepare(`
            INSERT INTO proxy_logs (id, method, url, host, path, request_headers, request_body, status_code, response_headers, response_body, duration_ms, is_in_scope, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `).run(
            logId, clientReq.method || 'GET', targetUrl, parsed.host, parsed.pathname,
            JSON.stringify(redactHeaders(clientReq.headers as any)),
            redactBody(reqBody),
            response.statusCode,
            JSON.stringify(redactHeaders(response.headers as any)),
            redactBody(response.body),
            response.durationMs,
            1,
            new Date().toISOString()
          );

          // Pipe back to client
          clientRes.writeHead(response.statusCode, response.headers as any);
          clientRes.end(response.body);
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
          clientRes.end(`VulnHunter Proxy Gateway Error: ${msg}`);
        }
      });
    });

    proxyServer.listen(proxyPort, '127.0.0.1', () => {
      isProxyRunning = true;
      logAudit('PROXY_START', `127.0.0.1:${proxyPort}`, `Local HTTP proxy listening on port ${proxyPort}`, 'info');
      resolve({
        success: true,
        port: proxyPort,
        message: `Local HTTP Proxy active on 127.0.0.1:${proxyPort}`
      });
    });

    proxyServer.on('error', (err) => {
      isProxyRunning = false;
      resolve({
        success: false,
        port: proxyPort,
        message: `Failed to bind proxy on port ${proxyPort}: ${err.message}`
      });
    });
  });
}

export function stopLocalProxy(): Promise<void> {
  return new Promise((resolve) => {
    if (proxyServer) {
      proxyServer.close(() => {
        isProxyRunning = false;
        proxyServer = null;
        logAudit('PROXY_STOP', `127.0.0.1:${proxyPort}`, 'Local HTTP proxy stopped', 'info');
        resolve();
      });
    } else {
      isProxyRunning = false;
      resolve();
    }
  });
}

export function getProxyStatus() {
  return {
    isRunning: isProxyRunning,
    port: proxyPort,
    host: '127.0.0.1',
    note: 'HTTP proxy binds strictly to 127.0.0.1. HTTPS proxying requires user-installed root CA on Android; see settings documentation.'
  };
}

/**
 * Repeater Engine: Executes an arbitrary request to an authorized target.
 */
export async function executeRepeaterRequest(
  method: string,
  urlStr: string,
  headers: Record<string, string>,
  body?: string
) {
  const scopeResult = await validateScope(urlStr);
  if (!scopeResult.authorized) {
    throw new Error(`Scope Gate Violation: ${scopeResult.reason}`);
  }

  logAudit('REPEATER_SEND', urlStr, `Replaying ${method} request via Repeater to authorized target`, 'info');

  const response = await safeHttpRequest(urlStr, {
    method,
    headers,
    body,
    timeoutMs: 12000
  });

  // Log to proxy history as a repeater entry
  const parsed = new URL(urlStr);
  const logId = 'rep-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6);

  db.prepare(`
    INSERT INTO proxy_logs (id, method, url, host, path, request_headers, request_body, status_code, response_headers, response_body, duration_ms, is_in_scope, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    logId, method, urlStr, parsed.host, parsed.pathname,
    JSON.stringify(redactHeaders(headers)),
    redactBody(body),
    response.statusCode,
    JSON.stringify(redactHeaders(response.headers as any)),
    redactBody(response.body),
    response.durationMs,
    1,
    new Date().toISOString()
  );

  return {
    statusCode: response.statusCode,
    statusMessage: response.statusMessage,
    headers: response.headers,
    body: response.body,
    durationMs: response.durationMs
  };
}
