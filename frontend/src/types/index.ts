export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Asset {
  id: string;
  name: string;
  target: string;
  asset_type: 'domain' | 'ip' | 'url' | 'cidr';
  authorized: boolean;
  authorized_by?: string;
  authorized_at?: string;
  notes?: string;
  created_at: string;
  updated_at: string;
}

export interface Vulnerability {
  id: string;
  scan_id: string;
  asset_id: string;
  title: string;
  category: string;
  attack_type: string;
  vector: string;
  severity: Severity;
  confidence: number;
  cve?: string;
  cwe?: string;
  owasp?: string;
  cvss_score?: number;
  description?: string;
  evidence_json: string;
  remediation?: string;
  verified: boolean;
  status: 'open' | 'remediated' | 'false_positive';
  created_at: string;
}

export interface Scan {
  id: string;
  name: string;
  asset_id: string;
  scan_mode: 'passive' | 'active' | 'custom';
  status: 'pending' | 'running' | 'paused' | 'completed' | 'cancelled' | 'failed';
  progress: number;
  started_at?: string;
  completed_at?: string;
  error_message?: string;
  config_json: string;
  created_at: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  target?: string;
  details_json: string;
  status: 'SUCCESS' | 'DENIED' | 'FAILED';
}

export interface DashboardStats {
  total_assets: number;
  authorized_assets: number;
  active_scans: number;
  total_vulnerabilities: number;
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
  verified_vulns: number;
}

export type ModuleId =
  | 'dashboard'
  | 'asset-discovery'
  | 'reconnaissance'
  | 'web-security'
  | 'api-security'
  | 'injection-testing'
  | 'cloud-security'
  | 'container-security'
  | 'kubernetes-security'
  | 'auth-testing'
  | 'ai-security'
  | 'vulnerability-management'
  | 'reports'
  | 'plugin-manager'
  | 'settings'
  | 'audit-logs';

export type ModuleStatus = 'verified' | 'experimental' | 'pending';

export interface ModuleItem {
  id: ModuleId;
  name: string;
  category: 'core' | 'scanners' | 'infrastructure' | 'governance';
  status: ModuleStatus;
  description: string;
}
