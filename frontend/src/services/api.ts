import { Asset, AuditLog, AuditSession, DashboardStats, Scan, Scope, ScopeExclusion, Vulnerability } from '../types';

const isTauri = typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

async function tauriInvoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (isTauri) {
    const { invoke } = await import('@tauri-apps/api/core');
    return invoke<T>(cmd, args);
  }
  throw new Error('Not running inside Tauri desktop environment');
}

// Local mock storage keys
const MOCK_STORAGE_KEY_ASSETS = 'sec_master_mock_assets';
const MOCK_STORAGE_KEY_VULNS = 'sec_master_mock_vulns';
const MOCK_STORAGE_KEY_SCANS = 'sec_master_mock_scans';
const MOCK_STORAGE_KEY_AUDIT = 'sec_master_mock_audit';
const MOCK_STORAGE_KEY_EXCLUSIONS = 'sec_master_mock_exclusions';
const MOCK_STORAGE_KEY_SESSIONS = 'sec_master_mock_sessions';

function getMockAssets(): Asset[] {
  const data = localStorage.getItem(MOCK_STORAGE_KEY_ASSETS);
  if (data) return JSON.parse(data);
  const initial: Asset[] = [
    {
      id: 'ast-1',
      name: 'Corporate Portal',
      target: 'https://staging.corp-portal.local',
      asset_type: 'url',
      authorized: true,
      authorized_by: 'Lead Auditor (SEC-01)',
      authorized_at: new Date().toISOString(),
      notes: 'Primary staging web application environment.',
      created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
      updated_at: new Date().toISOString(),
    },
    {
      id: 'ast-2',
      name: 'Auth API Gateway',
      target: 'api.auth-internal.local',
      asset_type: 'domain',
      authorized: false,
      notes: 'Pending Scope Authorization confirmation from SecOps.',
      created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
      updated_at: new Date().toISOString(),
    },
    {
      id: 'ast-3',
      name: 'Internal Kubernetes Ingress',
      target: '10.244.0.1/24',
      asset_type: 'cidr',
      authorized: false,
      notes: 'Excluded from active fuzzing until maintenance window.',
      created_at: new Date(Date.now() - 86400000).toISOString(),
      updated_at: new Date().toISOString(),
    },
  ];
  localStorage.setItem(MOCK_STORAGE_KEY_ASSETS, JSON.stringify(initial));
  return initial;
}

function getMockExclusions(): ScopeExclusion[] {
  const data = localStorage.getItem(MOCK_STORAGE_KEY_EXCLUSIONS);
  if (data) return JSON.parse(data);
  const initial: ScopeExclusion[] = [
    {
      id: 'exc-1',
      asset_id: 'ast-1',
      pattern: '/admin/delete',
      exclusion_type: 'path',
      reason: 'Prevents destructive administrative state changes',
      created_at: new Date().toISOString(),
    },
    {
      id: 'exc-2',
      asset_id: 'ast-1',
      pattern: '/auth/logout',
      exclusion_type: 'path',
      reason: 'Avoids prematurely terminating scanner session tokens',
      created_at: new Date().toISOString(),
    },
  ];
  localStorage.setItem(MOCK_STORAGE_KEY_EXCLUSIONS, JSON.stringify(initial));
  return initial;
}

function getMockSessions(): AuditSession[] {
  const data = localStorage.getItem(MOCK_STORAGE_KEY_SESSIONS);
  if (data) return JSON.parse(data);
  const initial: AuditSession[] = [
    {
      id: 'sess-1',
      name: 'Auditoría Trimestral Q4 - Staging',
      asset_id: 'ast-1',
      auditor_name: 'Lead Auditor (SEC-01)',
      status: 'active',
      start_time: new Date(Date.now() - 3600000 * 5).toISOString(),
      findings_count: 3,
      created_at: new Date(Date.now() - 3600000 * 5).toISOString(),
    },
  ];
  localStorage.setItem(MOCK_STORAGE_KEY_SESSIONS, JSON.stringify(initial));
  return initial;
}

function getMockVulnerabilities(): Vulnerability[] {
  const data = localStorage.getItem(MOCK_STORAGE_KEY_VULNS);
  if (data) return JSON.parse(data);
  const initial: Vulnerability[] = [
    {
      id: 'vuln-1',
      scan_id: 'scn-1',
      asset_id: 'ast-1',
      title: 'Reflected Cross-Site Scripting (XSS) in Search Parameter',
      category: 'Web Security',
      attack_type: 'xss',
      vector: 'query',
      severity: 'high',
      confidence: 95,
      cve: 'CVE-2023-28432',
      cwe: 'CWE-79',
      owasp: 'A03:2021 - Injection',
      cvss_score: 8.2,
      description: 'The parameter "q" at /search reflects unsanitized HTML/JS payloads directly into the DOM document body.',
      evidence_json: JSON.stringify({
        url: 'https://staging.corp-portal.local/search?q=%3Cscript%3Econfirm(document.domain)%3C%2Fscript%3E',
        injected_token: 'confirm(document.domain)',
        verified_execution: true,
        http_status: 200,
        baseline_length_delta: '+42 bytes'
      }),
      remediation: 'Implement contextual HTML entity encoding and define a strict Content-Security-Policy (CSP) omitting unsafe-inline.',
      verified: true,
      status: 'open',
      created_at: new Date(Date.now() - 3600000 * 4).toISOString(),
    },
    {
      id: 'vuln-2',
      scan_id: 'scn-1',
      asset_id: 'ast-1',
      title: 'Open Redirect via Target Destination Callback',
      category: 'Web Security',
      attack_type: 'openredirect',
      vector: 'query',
      severity: 'medium',
      confidence: 100,
      cwe: 'CWE-601',
      owasp: 'A01:2021 - Broken Access Control',
      cvss_score: 6.1,
      description: 'The redirection endpoint accepts arbitrary untrusted external URLs in the "next" parameter, leading to phishing or token theft.',
      evidence_json: JSON.stringify({
        endpoint: '/auth/login?next=https://attacker-domain.org',
        response_header_location: 'https://attacker-domain.org',
        http_status: 302
      }),
      remediation: 'Validate destination URLs against an allowlist of relative paths or trusted company domains.',
      verified: true,
      status: 'open',
      created_at: new Date(Date.now() - 3600000 * 3).toISOString(),
    },
    {
      id: 'vuln-3',
      scan_id: 'scn-1',
      asset_id: 'ast-1',
      title: 'Missing HTTP Strict Transport Security (HSTS)',
      category: 'Web Security',
      attack_type: 'headers',
      vector: 'header',
      severity: 'low',
      confidence: 100,
      cwe: 'CWE-319',
      owasp: 'A05:2021 - Security Misconfiguration',
      cvss_score: 3.7,
      description: 'The server does not enforce encrypted transport via Strict-Transport-Security header.',
      evidence_json: JSON.stringify({
        missing_header: 'Strict-Transport-Security',
        protocol: 'HTTP/1.1'
      }),
      remediation: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" to all server responses.',
      verified: true,
      status: 'open',
      created_at: new Date(Date.now() - 3600000 * 2).toISOString(),
    }
  ];
  localStorage.setItem(MOCK_STORAGE_KEY_VULNS, JSON.stringify(initial));
  return initial;
}

export const api = {
  async getDashboardStats(): Promise<DashboardStats> {
    try {
      return await tauriInvoke<DashboardStats>('get_dashboard_stats');
    } catch {
      const assets = getMockAssets();
      const vulns = getMockVulnerabilities();
      const sessions = getMockSessions();
      const exclusions = getMockExclusions();
      return {
        total_assets: assets.length,
        authorized_assets: assets.filter(a => a.authorized).length,
        active_scans: 1,
        total_vulnerabilities: vulns.length,
        critical_vulns: vulns.filter(v => v.severity === 'critical').length,
        high_vulns: vulns.filter(v => v.severity === 'high').length,
        medium_vulns: vulns.filter(v => v.severity === 'medium').length,
        low_vulns: vulns.filter(v => v.severity === 'low').length,
        verified_vulns: vulns.filter(v => v.verified).length,
        active_sessions: sessions.filter(s => s.status === 'active').length,
        total_exclusions: exclusions.length,
      };
    }
  },

  async getAssets(): Promise<Asset[]> {
    try {
      return await tauriInvoke<Asset[]>('get_assets');
    } catch {
      return getMockAssets();
    }
  },

  async createAsset(name: string, target: string, assetType: 'domain' | 'ip' | 'url' | 'cidr', notes?: string): Promise<Asset> {
    try {
      return await tauriInvoke<Asset>('create_asset', {
        req: { name, target, asset_type: assetType, notes }
      });
    } catch {
      const assets = getMockAssets();
      const newAsset: Asset = {
        id: `ast-${Date.now()}`,
        name,
        target,
        asset_type: assetType,
        authorized: false,
        notes,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      assets.unshift(newAsset);
      localStorage.setItem(MOCK_STORAGE_KEY_ASSETS, JSON.stringify(assets));
      return newAsset;
    }
  },

  async deleteAsset(id: string): Promise<void> {
    try {
      await tauriInvoke('delete_asset', { id });
    } catch {
      const assets = getMockAssets().filter(a => a.id !== id);
      localStorage.setItem(MOCK_STORAGE_KEY_ASSETS, JSON.stringify(assets));
    }
  },

  async authorizeAsset(id: string, authorized: boolean, authorizedBy: string): Promise<void> {
    try {
      await tauriInvoke('authorize_asset', {
        req: { id, authorized, authorized_by: authorizedBy }
      });
    } catch {
      const assets = getMockAssets();
      const asset = assets.find(a => a.id === id);
      if (asset) {
        asset.authorized = authorized;
        asset.authorized_by = authorized ? authorizedBy : undefined;
        asset.authorized_at = authorized ? new Date().toISOString() : undefined;
        asset.updated_at = new Date().toISOString();
        localStorage.setItem(MOCK_STORAGE_KEY_ASSETS, JSON.stringify(assets));
      }
    }
  },

  async getScope(assetId: string): Promise<Scope | null> {
    try {
      return await tauriInvoke<Scope | null>('get_scope', { assetId });
    } catch {
      const assets = getMockAssets();
      const asset = assets.find(a => a.id === assetId);
      return {
        id: `scp-${assetId}`,
        asset_id: assetId,
        allowed_paths: '["/"]',
        excluded_paths: '["/logout", "/admin/delete"]',
        max_rate: 20,
        passive_only: !asset?.authorized,
        created_at: new Date().toISOString(),
      };
    }
  },

  async updateScope(scope: Scope): Promise<void> {
    try {
      await tauriInvoke('update_scope', { scope });
    } catch {
      console.log('Mock: Scope updated', scope);
    }
  },

  async listExclusions(assetId: string): Promise<ScopeExclusion[]> {
    try {
      return await tauriInvoke<ScopeExclusion[]>('list_exclusions', { assetId });
    } catch {
      return getMockExclusions().filter(e => e.asset_id === assetId);
    }
  },

  async addExclusion(assetId: string, pattern: string, exclusionType: 'path' | 'subdomain' | 'ip_range' | 'param', reason: string): Promise<ScopeExclusion> {
    try {
      return await tauriInvoke<ScopeExclusion>('add_exclusion', {
        req: { asset_id: assetId, pattern, exclusion_type: exclusionType, reason }
      });
    } catch {
      const list = getMockExclusions();
      const newExc: ScopeExclusion = {
        id: `exc-${Date.now()}`,
        asset_id: assetId,
        pattern,
        exclusion_type: exclusionType,
        reason,
        created_at: new Date().toISOString(),
      };
      list.unshift(newExc);
      localStorage.setItem(MOCK_STORAGE_KEY_EXCLUSIONS, JSON.stringify(list));
      return newExc;
    }
  },

  async deleteExclusion(id: string): Promise<void> {
    try {
      await tauriInvoke('delete_exclusion', { id });
    } catch {
      const list = getMockExclusions().filter(e => e.id !== id);
      localStorage.setItem(MOCK_STORAGE_KEY_EXCLUSIONS, JSON.stringify(list));
    }
  },

  async listAuditSessions(assetId?: string): Promise<AuditSession[]> {
    try {
      return await tauriInvoke<AuditSession[]>('list_audit_sessions', { assetId: assetId || null });
    } catch {
      const list = getMockSessions();
      if (assetId) {
        return list.filter(s => s.asset_id === assetId);
      }
      return list;
    }
  },

  async createAuditSession(name: string, assetId: string, auditorName: string): Promise<AuditSession> {
    try {
      return await tauriInvoke<AuditSession>('create_audit_session', {
        req: { name, asset_id: assetId, auditor_name: auditorName }
      });
    } catch {
      const list = getMockSessions();
      const newSess: AuditSession = {
        id: `sess-${Date.now()}`,
        name,
        asset_id: assetId,
        auditor_name: auditorName,
        status: 'active',
        start_time: new Date().toISOString(),
        findings_count: 0,
        created_at: new Date().toISOString(),
      };
      list.unshift(newSess);
      localStorage.setItem(MOCK_STORAGE_KEY_SESSIONS, JSON.stringify(list));
      return newSess;
    }
  },

  async closeAuditSession(id: string, summary?: string): Promise<void> {
    try {
      await tauriInvoke('close_audit_session', { id, summary: summary || null });
    } catch {
      const list = getMockSessions();
      const s = list.find(x => x.id === id);
      if (s) {
        s.status = 'completed';
        s.end_time = new Date().toISOString();
        s.summary = summary;
        localStorage.setItem(MOCK_STORAGE_KEY_SESSIONS, JSON.stringify(list));
      }
    }
  },

  async getVulnerabilities(): Promise<Vulnerability[]> {
    try {
      return await tauriInvoke<Vulnerability[]>('get_vulnerabilities');
    } catch {
      return getMockVulnerabilities();
    }
  },

  async getAuditLogs(): Promise<AuditLog[]> {
    try {
      return await tauriInvoke<AuditLog[]>('get_audit_logs');
    } catch {
      const data = localStorage.getItem(MOCK_STORAGE_KEY_AUDIT);
      if (data) return JSON.parse(data);
      const initial: AuditLog[] = [
        {
          id: 'log-1',
          timestamp: new Date().toISOString(),
          actor: 'Operator',
          action: 'AUTHORIZE_SCOPE',
          target: 'https://staging.corp-portal.local',
          details_json: JSON.stringify({ authorized: true, rationale: 'Scheduled external pentest' }),
          status: 'SUCCESS'
        },
        {
          id: 'log-2',
          timestamp: new Date(Date.now() - 3600000).toISOString(),
          actor: 'Operator',
          action: 'LAUNCH_SCAN',
          target: 'https://staging.corp-portal.local',
          details_json: JSON.stringify({ module: 'Web Security (Differential Validation)' }),
          status: 'SUCCESS'
        }
      ];
      localStorage.setItem(MOCK_STORAGE_KEY_AUDIT, JSON.stringify(initial));
      return initial;
    }
  },

  async getScans(): Promise<Scan[]> {
    try {
      return await tauriInvoke<Scan[]>('get_scans');
    } catch {
      const data = localStorage.getItem(MOCK_STORAGE_KEY_SCANS);
      if (data) return JSON.parse(data);
      const initial: Scan[] = [
        {
          id: 'scn-1',
          name: 'Portal Differential Baseline Audit',
          asset_id: 'ast-1',
          scan_mode: 'active',
          status: 'completed',
          progress: 100.0,
          started_at: new Date(Date.now() - 3600000 * 2).toISOString(),
          completed_at: new Date(Date.now() - 3600000).toISOString(),
          config_json: JSON.stringify({ vectors: ['xss', 'sqli', 'openredirect'] }),
          created_at: new Date(Date.now() - 3600000 * 2).toISOString(),
        }
      ];
      localStorage.setItem(MOCK_STORAGE_KEY_SCANS, JSON.stringify(initial));
      return initial;
    }
  },

  async createScan(
    name: string,
    assetId: string,
    scanMode: string,
    vectors?: string[],
    rateLimit?: number
  ): Promise<Scan> {
    try {
      return await tauriInvoke<Scan>('create_scan', {
        req: {
          name,
          asset_id: assetId,
          scan_mode: scanMode,
          vectors,
          rate_limit: rateLimit,
        },
      });
    } catch (err) {
      console.warn('Falling back to local simulated scan in browser preview mode:', err);
      const scans = await this.getScans();
      const newScan: Scan = {
        id: `scn-${Date.now()}`,
        name,
        asset_id: assetId,
        scan_mode: scanMode as 'passive' | 'active',
        status: 'running',
        progress: 0.0,
        started_at: new Date().toISOString(),
        config_json: JSON.stringify({ vectors, rateLimit }),
        created_at: new Date().toISOString(),
      };
      scans.unshift(newScan);
      localStorage.setItem(MOCK_STORAGE_KEY_SCANS, JSON.stringify(scans));
      return newScan;
    }
  },

  async onScanEvent(callback: (event: any) => void): Promise<() => void> {
    if (isTauri) {
      try {
        const { listen } = await import('@tauri-apps/api/event');
        const unlisten = await listen('scan-event', (e) => {
          callback(e.payload);
        });
        return unlisten;
      } catch (err) {
        console.error('Failed to attach Tauri event listener:', err);
      }
    }
    return () => {};
  },

  async cancelScan(scanId: string): Promise<void> {
    try {
      await tauriInvoke('cancel_scan', { scanId });
    } catch {
      const scans = await this.getScans();
      const s = scans.find(x => x.id === scanId);
      if (s) {
        s.status = 'cancelled';
        s.progress = 100;
        localStorage.setItem(MOCK_STORAGE_KEY_SCANS, JSON.stringify(scans));
      }
    }
  }
};
