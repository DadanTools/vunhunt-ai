import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';

const DB_DIR = path.resolve(process.cwd(), 'data');
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

const DB_PATH = path.join(DB_DIR, 'vulnhunter.sqlite');
export const db = new DatabaseSync(DB_PATH);

// Enable WAL mode for high concurrency
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

export function initDatabase() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS scopes (
      id TEXT PRIMARY KEY,
      target TEXT NOT NULL UNIQUE,
      target_type TEXT NOT NULL, -- 'domain', 'host', 'ip', 'cidr', 'lab'
      is_active INTEGER NOT NULL DEFAULT 1,
      allow_private_ip INTEGER NOT NULL DEFAULT 0,
      notes TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS assets (
      id TEXT PRIMARY KEY,
      host TEXT NOT NULL,
      ip TEXT,
      port INTEGER DEFAULT 80,
      protocol TEXT DEFAULT 'http',
      url TEXT,
      status_code INTEGER,
      title TEXT,
      technologies TEXT, -- JSON array
      provenance TEXT NOT NULL, -- 'subfinder', 'manual_import', 'crawler', 'test_lab'
      scan_job_id TEXT,
      is_authorized INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      target TEXT NOT NULL,
      scan_type TEXT NOT NULL, -- 'exposure', 'templates', 'injection', 'idor', 'full'
      status TEXT NOT NULL, -- 'queued', 'running', 'completed', 'cancelled', 'failed'
      progress INTEGER NOT NULL DEFAULT 0,
      total_tasks INTEGER NOT NULL DEFAULT 0,
      completed_tasks INTEGER NOT NULL DEFAULT 0,
      error_message TEXT,
      started_at TEXT NOT NULL,
      completed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS findings (
      id TEXT PRIMARY KEY,
      scan_id TEXT,
      title TEXT NOT NULL,
      category TEXT NOT NULL, -- 'information_disclosure', 'security_headers', 'injection', 'auth_idor', 'cve', 'cors'
      severity TEXT NOT NULL, -- 'critical', 'high', 'medium', 'low', 'info'
      confidence TEXT NOT NULL, -- 'certain', 'firm', 'tentative'
      affected_asset TEXT NOT NULL,
      endpoint TEXT NOT NULL,
      evidence_json TEXT NOT NULL, -- sanitized evidence
      reproduction_steps TEXT NOT NULL,
      impact TEXT NOT NULL,
      remediation TEXT NOT NULL,
      verification_status TEXT NOT NULL DEFAULT 'candidate', -- 'candidate', 'needs-review', 'verified-in-authorized-lab', 'false-positive'
      source_tool TEXT NOT NULL, -- 'exposure_scanner', 'injection_engine', 'nuclei', 'idor_comparer'
      fingerprint TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS proxy_logs (
      id TEXT PRIMARY KEY,
      method TEXT NOT NULL,
      url TEXT NOT NULL,
      host TEXT NOT NULL,
      path TEXT NOT NULL,
      request_headers TEXT NOT NULL,
      request_body TEXT,
      status_code INTEGER,
      response_headers TEXT,
      response_body TEXT,
      duration_ms INTEGER,
      is_in_scope INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      action TEXT NOT NULL,
      target TEXT,
      actor TEXT NOT NULL DEFAULT 'local_user',
      details TEXT NOT NULL,
      severity TEXT NOT NULL DEFAULT 'info'
    );

    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS cve_intelligence (
      id TEXT PRIMARY KEY,
      query TEXT NOT NULL,
      cve_id TEXT,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      cvss_score REAL,
      affected_software TEXT,
      cwe TEXT,
      description TEXT NOT NULL,
      remediation TEXT NOT NULL,
      sources TEXT NOT NULL,
      source_engine TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  // Initialize default settings and sample local test lab scope if empty
  const scopeCountRow = db.prepare('SELECT COUNT(*) as count FROM scopes').get() as { count: number };
  if (scopeCountRow.count === 0) {
    const now = new Date().toISOString();
    // Default safe local authorization targets
    db.prepare(`
      INSERT INTO scopes (id, target, target_type, is_active, allow_private_ip, notes, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('scope-local-lab', 'localhost:3000', 'host', 1, 1, 'Default authorized local VulnHunter security test fixture', now);

    db.prepare(`
      INSERT INTO scopes (id, target, target_type, is_active, allow_private_ip, notes, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('scope-127', '127.0.0.1:3000', 'host', 1, 1, 'Local loopback authorized test fixture', now);

    // Initial audit log
    db.prepare(`
      INSERT INTO audit_logs (id, timestamp, action, target, actor, details, severity)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run('audit-init', now, 'INITIALIZE_SYSTEM', 'localhost:3000', 'system', 'VulnHunter AI database and default local security lab scope initialized', 'info');
  }

  // Ensure default passive mode setting
  const passiveSetting = db.prepare('SELECT value FROM settings WHERE key = ?').get('passive_mode_only') as { value: string } | undefined;
  if (!passiveSetting) {
    db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run('passive_mode_only', 'false');
  }

  const rateLimitSetting = db.prepare('SELECT value FROM settings WHERE key = ?').get('max_req_per_sec') as { value: string } | undefined;
  if (!rateLimitSetting) {
    db.prepare('INSERT INTO settings (key, value) VALUES (?, ?)').run('max_req_per_sec', '5');
  }
}
