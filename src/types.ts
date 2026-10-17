export interface ScopeRule {
  id: string;
  target: string;
  target_type: 'domain' | 'host' | 'ip' | 'cidr' | 'lab';
  is_active: number;
  allow_private_ip: number;
  notes?: string;
  created_at: string;
}

export interface Asset {
  id: string;
  host: string;
  ip?: string;
  port: number;
  protocol: string;
  url?: string;
  status_code?: number;
  title?: string;
  technologies?: string;
  provenance: string;
  scan_job_id?: string;
  is_authorized: number;
  created_at: string;
  updated_at: string;
}

export interface ScanJob {
  id: string;
  target: string;
  scan_type: string;
  status: 'queued' | 'running' | 'completed' | 'cancelled' | 'failed';
  progress: number;
  total_tasks: number;
  completed_tasks: number;
  error_message?: string;
  started_at: string;
  completed_at?: string;
}

export interface Finding {
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
  created_at: string;
  updated_at: string;
}

export interface ProxyLog {
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

export interface AuditLog {
  id: string;
  timestamp: string;
  action: string;
  target?: string;
  actor: string;
  details: string;
  severity: 'info' | 'warning' | 'critical';
}

export interface ToolHealth {
  name: string;
  binary: string;
  isAvailable: boolean;
  version?: string;
  path?: string;
  notes: string;
}
