/**
 * VulnHunter AI - Scope and Safety Gate
 * Strictly validates targets server-side before any active scan, HTTP probe,
 * proxy replay or template execution.
 */

import dns from 'node:dns/promises';
import { db } from './db.js';

export interface ScopeRule {
  id: string;
  target: string;
  target_type: 'domain' | 'host' | 'ip' | 'cidr' | 'lab';
  is_active: number;
  allow_private_ip: number;
  notes?: string;
}

// Global Emergency Stop Flag
let emergencyStopActivated = false;

export function activateEmergencyStop(): void {
  emergencyStopActivated = true;
  // Mark all currently running scans as cancelled
  db.prepare(`
    UPDATE scans 
    SET status = 'cancelled', error_message = 'EMERGENCY STOP TRIGGERED BY USER' 
    WHERE status IN ('running', 'queued')
  `).run();

  logAudit('EMERGENCY_STOP', 'ALL_TARGETS', 'Global Emergency Stop engaged. All active scanner jobs aborted immediately.', 'critical');
}

export function deactivateEmergencyStop(): void {
  emergencyStopActivated = false;
  logAudit('EMERGENCY_STOP_CLEARED', 'ALL_TARGETS', 'Global Emergency Stop cleared. System returned to normal operations.', 'info');
}

export function isEmergencyStopActive(): boolean {
  return emergencyStopActivated;
}

export function logAudit(action: string, target: string, details: string, severity: 'info' | 'warning' | 'critical' = 'info'): void {
  const id = 'audit-' + Date.now() + '-' + Math.random().toString(36).substring(2, 7);
  const now = new Date().toISOString();
  try {
    db.prepare(`
      INSERT INTO audit_logs (id, timestamp, action, target, actor, details, severity)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, now, action, target, 'local_user', details, severity);
  } catch (err) {
    console.error('Failed to write audit log:', err);
  }
}

/**
 * Checks if an IP is in a forbidden private/internal range (mitigating SSRF to cloud metadata or unauthorized LANs).
 */
export function isInternalOrPrivateIp(ip: string): boolean {
  // Cloud metadata endpoint
  if (ip === '169.254.169.254') return true;

  // IPv4 checks
  const parts = ip.split('.').map(Number);
  if (parts.length === 4 && parts.every(p => !isNaN(p) && p >= 0 && p <= 255)) {
    // 127.0.0.0/8 Loopback
    if (parts[0] === 127) return true;
    // 10.0.0.0/8 Private
    if (parts[0] === 10) return true;
    // 172.16.0.0/12 Private
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 192.168.0.0/16 Private
    if (parts[0] === 192 && parts[1] === 168) return true;
    // 169.254.0.0/16 Link-local
    if (parts[0] === 169 && parts[1] === 254) return true;
    // 0.0.0.0/8
    if (parts[0] === 0) return true;
  }

  // IPv6 loopback / unique local
  if (ip === '::1' || ip.startsWith('fc00:') || ip.startsWith('fe80:')) {
    return true;
  }

  return false;
}

export interface ScopeCheckResult {
  authorized: boolean;
  reason: string;
  normalizedUrl?: string;
  matchedRule?: ScopeRule;
}

/**
 * Server-side Scope Gate validation.
 * Revalidates host, port, protocol, and resolves IP to prevent SSRF against unauthorized internal networks.
 */
export async function validateScope(rawTarget: string, allowLabLocalhost = true): Promise<ScopeCheckResult> {
  if (emergencyStopActivated) {
    return { authorized: false, reason: 'Emergency Stop is currently active. All outgoing security testing is blocked.' };
  }

  if (!rawTarget || typeof rawTarget !== 'string') {
    return { authorized: false, reason: 'Target cannot be empty.' };
  }

  let parsed: URL;
  try {
    const formatted = rawTarget.startsWith('http://') || rawTarget.startsWith('https://') 
      ? rawTarget 
      : `http://${rawTarget}`;
    parsed = new URL(formatted);
  } catch (_e) {
    return { authorized: false, reason: `Invalid target URL or host syntax: "${rawTarget}"` };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { authorized: false, reason: `Forbidden protocol "${parsed.protocol}". Only HTTP and HTTPS are permitted.` };
  }

  const hostname = parsed.hostname.toLowerCase();
  const port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);

  // Check unsafe or system ports
  const unsafePorts = [22, 25, 53, 3306, 5432, 6379, 27017, 9200];
  if (unsafePorts.includes(port)) {
    return { authorized: false, reason: `Access to infrastructure port ${port} is blocked by safety gate.` };
  }

  // Fetch all active scope rules from DB
  const rules = db.prepare('SELECT * FROM scopes WHERE is_active = 1').all() as unknown as ScopeRule[];

  if (rules.length === 0) {
    return { authorized: false, reason: 'No authorized scopes configured in Scope Gate. You must explicitly add target to scope.' };
  }

  let matchedRule: ScopeRule | null = null;

  for (const rule of rules) {
    const ruleTarget = rule.target.trim().toLowerCase();
    
    // Check exact host (e.g. localhost:3000, 127.0.0.1:3000, or example.com)
    if (parsed.host === ruleTarget || hostname === ruleTarget) {
      matchedRule = rule;
      break;
    }

    // Check domain wildcard/suffix (e.g. *.example.com or .example.com)
    if (ruleTarget.startsWith('*.')) {
      const baseDomain = ruleTarget.slice(2);
      if (hostname === baseDomain || hostname.endsWith(`.${baseDomain}`)) {
        matchedRule = rule;
        break;
      }
    } else if (ruleTarget.startsWith('.')) {
      const baseDomain = ruleTarget.slice(1);
      if (hostname === baseDomain || hostname.endsWith(`.${baseDomain}`)) {
        matchedRule = rule;
        break;
      }
    }
  }

  if (!matchedRule) {
    return {
      authorized: false,
      reason: `Target "${hostname}" is outside all configured authorized scopes. Authorization required.`
    };
  }

  // DNS Re-validation and IP SSRF checks
  try {
    const isLocalhostHost = hostname === 'localhost' || hostname === '127.0.0.1';
    
    if (isLocalhostHost) {
      if (!matchedRule.allow_private_ip && !allowLabLocalhost) {
        return { authorized: false, reason: 'Localhost/loopback target requires explicit allow_private_ip scope authorization.' };
      }
    } else {
      // Resolve host to IP to prevent DNS rebinding
      const addresses = await dns.resolve4(hostname).catch(() => []);
      if (addresses.length > 0) {
        for (const resolvedIp of addresses) {
          if (isInternalOrPrivateIp(resolvedIp) && !matchedRule.allow_private_ip) {
            return {
              authorized: false,
              reason: `Host "${hostname}" resolved to private/cloud-metadata IP ${resolvedIp}, which is not authorized.`
            };
          }
        }
      }
    }
  } catch (_e) {
    // DNS resolution failure
  }

  return {
    authorized: true,
    reason: `Target matches authorized scope "${matchedRule.target}".`,
    normalizedUrl: parsed.origin + (parsed.pathname === '/' ? '' : parsed.pathname),
    matchedRule
  };
}
