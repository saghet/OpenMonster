use rusqlite::{params, Connection, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Asset {
    pub id: String,
    pub name: String,
    pub target: String,
    pub asset_type: String,
    pub authorized: bool,
    pub authorized_by: Option<String>,
    pub authorized_at: Option<String>,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Scope {
    pub id: String,
    pub asset_id: String,
    pub allowed_paths: String,
    pub excluded_paths: String,
    pub max_rate: i64,
    pub passive_only: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScopeExclusion {
    pub id: String,
    pub asset_id: String,
    pub pattern: String,
    pub exclusion_type: String,
    pub reason: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditSession {
    pub id: String,
    pub name: String,
    pub asset_id: String,
    pub auditor_name: String,
    pub status: String,
    pub start_time: String,
    pub end_time: Option<String>,
    pub summary: Option<String>,
    pub findings_count: i64,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vulnerability {
    pub id: String,
    pub scan_id: String,
    pub asset_id: String,
    pub title: String,
    pub category: String,
    pub attack_type: String,
    pub vector: String,
    pub severity: String,
    pub confidence: i64,
    pub cve: Option<String>,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub cvss_score: Option<f64>,
    pub description: Option<String>,
    pub evidence_json: String,
    pub remediation: Option<String>,
    pub verified: bool,
    pub status: String,
    pub created_at: String,
    pub fingerprint: Option<String>,
    pub false_positive_reason: Option<String>,
    pub remediation_notes: Option<String>,
    pub resolved_at: Option<String>,
    pub occurrences: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VulnerabilityHistory {
    pub id: String,
    pub vulnerability_id: String,
    pub previous_status: String,
    pub new_status: String,
    pub actor: String,
    pub notes: Option<String>,
    pub changed_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RemediationDiff {
    pub new_findings: Vec<Vulnerability>,
    pub resolved_findings: Vec<Vulnerability>,
    pub persistent_findings: Vec<Vulnerability>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReconScan {
    pub id: String,
    pub asset_id: String,
    pub status: String,
    pub mode: String,
    pub target_domain: String,
    pub subdomains_count: i64,
    pub dns_records_count: i64,
    pub technologies_count: i64,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub error_message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReconSubdomain {
    pub id: String,
    pub recon_scan_id: String,
    pub asset_id: String,
    pub subdomain: String,
    pub ip_addresses: String,
    pub source: String,
    pub confidence: i64,
    pub is_live: bool,
    pub http_status: Option<i64>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReconDnsRecord {
    pub id: String,
    pub recon_scan_id: String,
    pub asset_id: String,
    pub domain: String,
    pub record_type: String,
    pub record_value: String,
    pub ttl: Option<i64>,
    pub is_takeover_risk: bool,
    pub takeover_reason: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReconTechnology {
    pub id: String,
    pub recon_scan_id: String,
    pub asset_id: String,
    pub target_url: String,
    pub name: String,
    pub category: String,
    pub version: Option<String>,
    pub confidence: String,
    pub matched_indicators_json: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReconHttpFingerprint {
    pub id: String,
    pub recon_scan_id: String,
    pub asset_id: String,
    pub target_url: String,
    pub status_code: i64,
    pub server_header: Option<String>,
    pub title: Option<String>,
    pub content_type: Option<String>,
    pub tls_version: Option<String>,
    pub tls_cipher: Option<String>,
    pub tls_cert_subject: Option<String>,
    pub tls_cert_issuer: Option<String>,
    pub tls_cert_days_left: Option<i64>,
    pub security_headers_json: String,
    pub cookies_json: String,
    pub raw_headers_json: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ReconSummary {
    pub subdomains: Vec<ReconSubdomain>,
    pub dns_records: Vec<ReconDnsRecord>,
    pub technologies: Vec<ReconTechnology>,
    pub http_fingerprints: Vec<ReconHttpFingerprint>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Scan {
    pub id: String,
    pub name: String,
    pub asset_id: String,
    pub scan_mode: String,
    pub status: String,
    pub progress: f64,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub error_message: Option<String>,
    pub config_json: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuditLog {
    pub id: String,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub target: Option<String>,
    pub details_json: String,
    pub status: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DashboardStats {
    pub total_assets: i64,
    pub authorized_assets: i64,
    pub active_scans: i64,
    pub total_vulnerabilities: i64,
    pub critical_vulns: i64,
    pub high_vulns: i64,
    pub medium_vulns: i64,
    pub low_vulns: i64,
    pub verified_vulns: i64,
    pub active_sessions: i64,
    pub total_exclusions: i64,
}

pub struct DatabaseManager {
    conn: Mutex<Connection>,
}

impl DatabaseManager {
    pub fn new(db_path: PathBuf) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        let manager = Self {
            conn: Mutex::new(conn),
        };
        manager.run_migrations()?;
        Ok(manager)
    }

    pub fn new_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let manager = Self {
            conn: Mutex::new(conn),
        };
        manager.run_migrations()?;
        Ok(manager)
    }

    fn run_migrations(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let m1 = include_str!("../../database/migrations/001_initial_schema.sql");
        conn.execute_batch(m1)?;
        let m2 = include_str!("../../database/migrations/002_phase2_scope_enhancements.sql");
        conn.execute_batch(m2)?;
        let m3 = include_str!("../../database/migrations/003_vulnerability_dedup_and_remediation.sql");
        conn.execute_batch(m3)?;
        let m4 = include_str!("../../database/migrations/004_reconnaissance_engine.sql");
        conn.execute_batch(m4)?;
        Ok(())
    }

    pub fn get_dashboard_stats(&self) -> Result<DashboardStats> {
        let conn = self.conn.lock().unwrap();

        let total_assets: i64 = conn
            .query_row("SELECT COUNT(*) FROM assets", [], |r| r.get(0))
            .unwrap_or(0);

        let authorized_assets: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM assets WHERE authorized = 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let active_scans: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM scans WHERE status = 'running'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let total_vulnerabilities: i64 = conn
            .query_row("SELECT COUNT(*) FROM vulnerabilities", [], |r| r.get(0))
            .unwrap_or(0);

        let critical_vulns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'critical'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let high_vulns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'high'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let medium_vulns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'medium'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let low_vulns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'low'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let verified_vulns: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM vulnerabilities WHERE verified = 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let active_sessions: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM audit_sessions WHERE status = 'active'",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let total_exclusions: i64 = conn
            .query_row("SELECT COUNT(*) FROM scope_exclusions", [], |r| r.get(0))
            .unwrap_or(0);

        Ok(DashboardStats {
            total_assets,
            authorized_assets,
            active_scans,
            total_vulnerabilities,
            critical_vulns,
            high_vulns,
            medium_vulns,
            low_vulns,
            verified_vulns,
            active_sessions,
            total_exclusions,
        })
    }

    pub fn list_assets(&self) -> Result<Vec<Asset>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, target, asset_type, authorized, authorized_by, authorized_at, notes, created_at, updated_at FROM assets ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            let auth_int: i64 = row.get(4)?;
            Ok(Asset {
                id: row.get(0)?,
                name: row.get(1)?,
                target: row.get(2)?,
                asset_type: row.get(3)?,
                authorized: auth_int == 1,
                authorized_by: row.get(5)?,
                authorized_at: row.get(6)?,
                notes: row.get(7)?,
                created_at: row.get(8)?,
                updated_at: row.get(9)?,
            })
        })?;

        let mut assets = Vec::new();
        for r in rows {
            assets.push(r?);
        }
        Ok(assets)
    }

    pub fn insert_asset(&self, asset: &Asset) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO assets (id, name, target, asset_type, authorized, authorized_by, authorized_at, notes, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                asset.id,
                asset.name,
                asset.target,
                asset.asset_type,
                if asset.authorized { 1 } else { 0 },
                asset.authorized_by,
                asset.authorized_at,
                asset.notes,
                asset.created_at,
                asset.updated_at
            ],
        )?;

        // Automatically create associated default scope record in passive mode
        let scope_id = format!("scp-{}", asset.id);
        conn.execute(
            "INSERT OR IGNORE INTO scopes (id, asset_id, allowed_paths, excluded_paths, max_rate, passive_only, created_at) VALUES (?1, ?2, '[\"/\"]', '[\"/logout\", \"/admin/delete\"]', 20, 1, ?3)",
            params![scope_id, asset.id, asset.created_at],
        )?;

        Ok(())
    }

    pub fn delete_asset(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM assets WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn update_asset_authorization(
        &self,
        id: &str,
        authorized: bool,
        authorized_by: Option<String>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE assets SET authorized = ?1, authorized_by = ?2, authorized_at = ?3, updated_at = ?4 WHERE id = ?5",
            params![
                if authorized { 1 } else { 0 },
                authorized_by,
                if authorized { Some(now.clone()) } else { None },
                now,
                id
            ],
        )?;

        // Also update scope passive_only flag
        conn.execute(
            "UPDATE scopes SET passive_only = ?1 WHERE asset_id = ?2",
            params![if authorized { 0 } else { 1 }, id],
        )?;

        Ok(())
    }

    pub fn get_scope(&self, asset_id: &str) -> Result<Option<Scope>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, asset_id, allowed_paths, excluded_paths, max_rate, passive_only, created_at FROM scopes WHERE asset_id = ?1",
        )?;

        let mut rows = stmt.query(params![asset_id])?;
        if let Some(row) = rows.next()? {
            let passive_int: i64 = row.get(5)?;
            Ok(Some(Scope {
                id: row.get(0)?,
                asset_id: row.get(1)?,
                allowed_paths: row.get(2)?,
                excluded_paths: row.get(3)?,
                max_rate: row.get(4)?,
                passive_only: passive_int == 1,
                created_at: row.get(6)?,
            }))
        } else {
            Ok(None)
        }
    }

    pub fn update_scope(&self, scope: &Scope) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO scopes (id, asset_id, allowed_paths, excluded_paths, max_rate, passive_only, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7) ON CONFLICT(id) DO UPDATE SET allowed_paths = ?3, excluded_paths = ?4, max_rate = ?5, passive_only = ?6",
            params![
                scope.id,
                scope.asset_id,
                scope.allowed_paths,
                scope.excluded_paths,
                scope.max_rate,
                if scope.passive_only { 1 } else { 0 },
                scope.created_at
            ],
        )?;
        Ok(())
    }

    pub fn list_exclusions(&self, asset_id: &str) -> Result<Vec<ScopeExclusion>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, asset_id, pattern, exclusion_type, reason, created_at FROM scope_exclusions WHERE asset_id = ?1 ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map(params![asset_id], |row| {
            Ok(ScopeExclusion {
                id: row.get(0)?,
                asset_id: row.get(1)?,
                pattern: row.get(2)?,
                exclusion_type: row.get(3)?,
                reason: row.get(4)?,
                created_at: row.get(5)?,
            })
        })?;

        let mut exclusions = Vec::new();
        for r in rows {
            exclusions.push(r?);
        }
        Ok(exclusions)
    }

    pub fn insert_exclusion(&self, exc: &ScopeExclusion) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO scope_exclusions (id, asset_id, pattern, exclusion_type, reason, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                exc.id,
                exc.asset_id,
                exc.pattern,
                exc.exclusion_type,
                exc.reason,
                exc.created_at
            ],
        )?;
        Ok(())
    }

    pub fn delete_exclusion(&self, id: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM scope_exclusions WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn check_path_in_scope(&self, asset_id: &str, path: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let exclusions: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT pattern FROM scope_exclusions WHERE asset_id = ?1 AND exclusion_type = 'path'",
            )?;
            let rows = stmt.query_map(params![asset_id], |r| r.get(0))?;
            rows.filter_map(|r| r.ok()).collect()
        };

        for pattern in exclusions {
            if path.contains(&pattern) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn list_audit_sessions(&self, asset_id: Option<&str>) -> Result<Vec<AuditSession>> {
        let conn = self.conn.lock().unwrap();
        let mut sessions = Vec::new();

        if let Some(aid) = asset_id {
            let mut stmt = conn.prepare(
                "SELECT id, name, asset_id, auditor_name, status, start_time, end_time, summary, findings_count, created_at FROM audit_sessions WHERE asset_id = ?1 ORDER BY created_at DESC",
            )?;
            let rows = stmt.query_map(params![aid], |row| {
                Ok(AuditSession {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    asset_id: row.get(2)?,
                    auditor_name: row.get(3)?,
                    status: row.get(4)?,
                    start_time: row.get(5)?,
                    end_time: row.get(6)?,
                    summary: row.get(7)?,
                    findings_count: row.get(8)?,
                    created_at: row.get(9)?,
                })
            })?;
            for r in rows {
                sessions.push(r?);
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT id, name, asset_id, auditor_name, status, start_time, end_time, summary, findings_count, created_at FROM audit_sessions ORDER BY created_at DESC",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok(AuditSession {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    asset_id: row.get(2)?,
                    auditor_name: row.get(3)?,
                    status: row.get(4)?,
                    start_time: row.get(5)?,
                    end_time: row.get(6)?,
                    summary: row.get(7)?,
                    findings_count: row.get(8)?,
                    created_at: row.get(9)?,
                })
            })?;
            for r in rows {
                sessions.push(r?);
            }
        }

        Ok(sessions)
    }

    pub fn insert_audit_session(&self, session: &AuditSession) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_sessions (id, name, asset_id, auditor_name, status, start_time, end_time, summary, findings_count, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                session.id,
                session.name,
                session.asset_id,
                session.auditor_name,
                session.status,
                session.start_time,
                session.end_time,
                session.summary,
                session.findings_count,
                session.created_at
            ],
        )?;
        Ok(())
    }

    pub fn close_audit_session(&self, id: &str, summary: Option<&str>) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE audit_sessions SET status = 'completed', end_time = ?1, summary = COALESCE(?2, summary) WHERE id = ?3",
            params![now, summary, id],
        )?;
        Ok(())
    }

    pub fn list_vulnerabilities(&self) -> Result<Vec<Vulnerability>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, scan_id, asset_id, title, category, attack_type, vector, severity, confidence, cve, cwe, owasp, cvss_score, description, evidence_json, remediation, verified, status, created_at, fingerprint, false_positive_reason, remediation_notes, resolved_at, occurrences FROM vulnerabilities ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            let verif_int: i64 = row.get(16)?;
            Ok(Vulnerability {
                id: row.get(0)?,
                scan_id: row.get(1)?,
                asset_id: row.get(2)?,
                title: row.get(3)?,
                category: row.get(4)?,
                attack_type: row.get(5)?,
                vector: row.get(6)?,
                severity: row.get(7)?,
                confidence: row.get(8)?,
                cve: row.get(9)?,
                cwe: row.get(10)?,
                owasp: row.get(11)?,
                cvss_score: row.get(12)?,
                description: row.get(13)?,
                evidence_json: row.get(14)?,
                remediation: row.get(15)?,
                verified: verif_int == 1,
                status: row.get(17)?,
                created_at: row.get(18)?,
                fingerprint: row.get(19)?,
                false_positive_reason: row.get(20)?,
                remediation_notes: row.get(21)?,
                resolved_at: row.get(22)?,
                occurrences: row.get(23)?,
            })
        })?;

        let mut vulns = Vec::new();
        for r in rows {
            vulns.push(r?);
        }
        Ok(vulns)
    }

    pub fn insert_vulnerability_with_dedup(&self, v: &Vulnerability) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let fp = v.fingerprint.clone().unwrap_or_else(|| {
            format!("{}:{}:{}:{}", v.asset_id, v.attack_type, v.vector, v.title)
        });

        // Check if matching vulnerability already exists for this asset
        let existing: Option<(String, i64)> = conn
            .query_row(
                "SELECT id, occurrences FROM vulnerabilities WHERE asset_id = ?1 AND fingerprint = ?2",
                params![v.asset_id, fp],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();

        if let Some((existing_id, occ)) = existing {
            // Update existing entry: increment occurrences count and update evidence without polluting duplicates
            conn.execute(
                "UPDATE vulnerabilities SET occurrences = ?1, confidence = MAX(confidence, ?2), evidence_json = ?3 WHERE id = ?4",
                params![occ + 1, v.confidence, v.evidence_json, existing_id],
            )?;
        } else {
            conn.execute(
                "INSERT INTO vulnerabilities (id, scan_id, asset_id, title, category, attack_type, vector, severity, confidence, cve, cwe, owasp, cvss_score, description, evidence_json, remediation, verified, status, created_at, fingerprint, false_positive_reason, remediation_notes, resolved_at, occurrences) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24)",
                params![
                    v.id,
                    v.scan_id,
                    v.asset_id,
                    v.title,
                    v.category,
                    v.attack_type,
                    v.vector,
                    v.severity,
                    v.confidence,
                    v.cve,
                    v.cwe,
                    v.owasp,
                    v.cvss_score,
                    v.description,
                    v.evidence_json,
                    v.remediation,
                    if v.verified { 1 } else { 0 },
                    v.status,
                    v.created_at,
                    fp,
                    v.false_positive_reason,
                    v.remediation_notes,
                    v.resolved_at,
                    v.occurrences
                ],
            )?;
        }

        Ok(())
    }

    pub fn update_vulnerability_status(
        &self,
        id: &str,
        new_status: &str,
        notes: Option<&str>,
        actor: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let prev_status: String = conn.query_row(
            "SELECT status FROM vulnerabilities WHERE id = ?1",
            params![id],
            |r| r.get(0),
        )?;

        let now = chrono::Utc::now().to_rfc3339();
        let resolved_at = if new_status == "remediated" {
            Some(now.clone())
        } else {
            None
        };

        let fp_reason = if new_status == "false_positive" {
            notes.map(|n| n.to_string())
        } else {
            None
        };

        conn.execute(
            "UPDATE vulnerabilities SET status = ?1, remediation_notes = ?2, resolved_at = ?3, false_positive_reason = COALESCE(?4, false_positive_reason) WHERE id = ?5",
            params![new_status, notes, resolved_at, fp_reason, id],
        )?;

        // Record in vulnerability history
        let hist_id = uuid::Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO vulnerability_history (id, vulnerability_id, previous_status, new_status, actor, notes, changed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![hist_id, id, prev_status, new_status, actor, notes, now],
        )?;

        Ok(())
    }

    pub fn get_remediation_diff(&self, asset_id: &str) -> Result<RemediationDiff> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, scan_id, asset_id, title, category, attack_type, vector, severity, confidence, cve, cwe, owasp, cvss_score, description, evidence_json, remediation, verified, status, created_at, fingerprint, false_positive_reason, remediation_notes, resolved_at, occurrences FROM vulnerabilities WHERE asset_id = ?1",
        )?;

        let rows = stmt.query_map(params![asset_id], |row| {
            let verif_int: i64 = row.get(16)?;
            Ok(Vulnerability {
                id: row.get(0)?,
                scan_id: row.get(1)?,
                asset_id: row.get(2)?,
                title: row.get(3)?,
                category: row.get(4)?,
                attack_type: row.get(5)?,
                vector: row.get(6)?,
                severity: row.get(7)?,
                confidence: row.get(8)?,
                cve: row.get(9)?,
                cwe: row.get(10)?,
                owasp: row.get(11)?,
                cvss_score: row.get(12)?,
                description: row.get(13)?,
                evidence_json: row.get(14)?,
                remediation: row.get(15)?,
                verified: verif_int == 1,
                status: row.get(17)?,
                created_at: row.get(18)?,
                fingerprint: row.get(19)?,
                false_positive_reason: row.get(20)?,
                remediation_notes: row.get(21)?,
                resolved_at: row.get(22)?,
                occurrences: row.get(23)?,
            })
        })?;

        let mut new_findings = Vec::new();
        let mut resolved_findings = Vec::new();
        let mut persistent_findings = Vec::new();

        for r in rows {
            let v = r?;
            if v.status == "remediated" {
                resolved_findings.push(v);
            } else if v.occurrences > 1 && v.status == "open" {
                persistent_findings.push(v);
            } else if v.status == "open" {
                new_findings.push(v);
            }
        }

        Ok(RemediationDiff {
            new_findings,
            resolved_findings,
            persistent_findings,
        })
    }

    pub fn insert_vulnerability(&self, v: &Vulnerability) -> Result<()> {
        self.insert_vulnerability_with_dedup(v)
    }

    pub fn list_audit_logs(&self) -> Result<Vec<AuditLog>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, actor, action, target, details_json, status FROM audit_logs ORDER BY timestamp DESC LIMIT 200",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(AuditLog {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                actor: row.get(2)?,
                action: row.get(3)?,
                target: row.get(4)?,
                details_json: row.get(5)?,
                status: row.get(6)?,
            })
        })?;

        let mut logs = Vec::new();
        for r in rows {
            logs.push(r?);
        }
        Ok(logs)
    }

    pub fn insert_audit_log(&self, log: &AuditLog) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO audit_logs (id, timestamp, actor, action, target, details_json, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                log.id,
                log.timestamp,
                log.actor,
                log.action,
                log.target,
                log.details_json,
                log.status
            ],
        )?;
        Ok(())
    }

    pub fn list_scans(&self) -> Result<Vec<Scan>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, asset_id, scan_mode, status, progress, started_at, completed_at, error_message, config_json, created_at FROM scans ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(Scan {
                id: row.get(0)?,
                name: row.get(1)?,
                asset_id: row.get(2)?,
                scan_mode: row.get(3)?,
                status: row.get(4)?,
                progress: row.get(5)?,
                started_at: row.get(6)?,
                completed_at: row.get(7)?,
                error_message: row.get(8)?,
                config_json: row.get(9)?,
                created_at: row.get(10)?,
            })
        })?;

        let mut scans = Vec::new();
        for r in rows {
            scans.push(r?);
        }
        Ok(scans)
    }

    pub fn insert_scan(&self, s: &Scan) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO scans (id, name, asset_id, scan_mode, status, progress, started_at, completed_at, error_message, config_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                s.id,
                s.name,
                s.asset_id,
                s.scan_mode,
                s.status,
                s.progress,
                s.started_at,
                s.completed_at,
                s.error_message,
                s.config_json,
                s.created_at
            ],
        )?;
        Ok(())
    }

    pub fn update_scan_status(&self, scan_id: &str, status: &str, progress: f64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let completed_at = if status == "completed" || status == "cancelled" || status == "failed" {
            Some(chrono::Utc::now().to_rfc3339())
        } else {
            None
        };
        conn.execute(
            "UPDATE scans SET status = ?1, progress = ?2, completed_at = COALESCE(?3, completed_at) WHERE id = ?4",
            params![status, progress, completed_at, scan_id],
        )?;
        Ok(())
    }

    // === RECONNAISSANCE ENGINE PERSISTENCE ===

    pub fn insert_recon_scan(&self, s: &ReconScan) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO recon_scans (id, asset_id, status, mode, target_domain, subdomains_count, dns_records_count, technologies_count, started_at, completed_at, error_message) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                s.id,
                s.asset_id,
                s.status,
                s.mode,
                s.target_domain,
                s.subdomains_count,
                s.dns_records_count,
                s.technologies_count,
                s.started_at,
                s.completed_at,
                s.error_message
            ],
        )?;
        Ok(())
    }

    pub fn update_recon_scan_status(
        &self,
        id: &str,
        status: &str,
        subdomains: i64,
        dns: i64,
        tech: i64,
        error: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let completed_at = if status == "completed" || status == "cancelled" || status == "failed" {
            Some(chrono::Utc::now().to_rfc3339())
        } else {
            None
        };
        conn.execute(
            "UPDATE recon_scans SET status = ?1, subdomains_count = ?2, dns_records_count = ?3, technologies_count = ?4, error_message = ?5, completed_at = COALESCE(?6, completed_at) WHERE id = ?7",
            params![status, subdomains, dns, tech, error, completed_at, id],
        )?;
        Ok(())
    }

    pub fn list_recon_scans(&self, asset_id: Option<&str>) -> Result<Vec<ReconScan>> {
        let conn = self.conn.lock().unwrap();
        let mut scans = Vec::new();

        if let Some(aid) = asset_id {
            let mut stmt = conn.prepare("SELECT id, asset_id, status, mode, target_domain, subdomains_count, dns_records_count, technologies_count, started_at, completed_at, error_message FROM recon_scans WHERE asset_id = ?1 ORDER BY started_at DESC")?;
            let rows = stmt.query_map(params![aid], |row| {
                Ok(ReconScan {
                    id: row.get(0)?,
                    asset_id: row.get(1)?,
                    status: row.get(2)?,
                    mode: row.get(3)?,
                    target_domain: row.get(4)?,
                    subdomains_count: row.get(5)?,
                    dns_records_count: row.get(6)?,
                    technologies_count: row.get(7)?,
                    started_at: row.get(8)?,
                    completed_at: row.get(9)?,
                    error_message: row.get(10)?,
                })
            })?;
            for r in rows {
                scans.push(r?);
            }
        } else {
            let mut stmt = conn.prepare("SELECT id, asset_id, status, mode, target_domain, subdomains_count, dns_records_count, technologies_count, started_at, completed_at, error_message FROM recon_scans ORDER BY started_at DESC")?;
            let rows = stmt.query_map([], |row| {
                Ok(ReconScan {
                    id: row.get(0)?,
                    asset_id: row.get(1)?,
                    status: row.get(2)?,
                    mode: row.get(3)?,
                    target_domain: row.get(4)?,
                    subdomains_count: row.get(5)?,
                    dns_records_count: row.get(6)?,
                    technologies_count: row.get(7)?,
                    started_at: row.get(8)?,
                    completed_at: row.get(9)?,
                    error_message: row.get(10)?,
                })
            })?;
            for r in rows {
                scans.push(r?);
            }
        }

        Ok(scans)
    }

    pub fn insert_recon_subdomain(&self, s: &ReconSubdomain) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO recon_subdomains (id, recon_scan_id, asset_id, subdomain, ip_addresses, source, confidence, is_live, http_status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                s.id,
                s.recon_scan_id,
                s.asset_id,
                s.subdomain,
                s.ip_addresses,
                s.source,
                s.confidence,
                if s.is_live { 1 } else { 0 },
                s.http_status,
                s.created_at
            ],
        )?;
        Ok(())
    }

    pub fn insert_recon_dns_record(&self, r: &ReconDnsRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO recon_dns_records (id, recon_scan_id, asset_id, domain, record_type, record_value, ttl, is_takeover_risk, takeover_reason, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                r.id,
                r.recon_scan_id,
                r.asset_id,
                r.domain,
                r.record_type,
                r.record_value,
                r.ttl,
                if r.is_takeover_risk { 1 } else { 0 },
                r.takeover_reason,
                r.created_at
            ],
        )?;
        Ok(())
    }

    pub fn insert_recon_technology(&self, t: &ReconTechnology) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO recon_technologies (id, recon_scan_id, asset_id, target_url, name, category, version, confidence, matched_indicators_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                t.id,
                t.recon_scan_id,
                t.asset_id,
                t.target_url,
                t.name,
                t.category,
                t.version,
                t.confidence,
                t.matched_indicators_json,
                t.created_at
            ],
        )?;
        Ok(())
    }

    pub fn insert_recon_http_fingerprint(&self, f: &ReconHttpFingerprint) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO recon_http_fingerprints (id, recon_scan_id, asset_id, target_url, status_code, server_header, title, content_type, tls_version, tls_cipher, tls_cert_subject, tls_cert_issuer, tls_cert_days_left, security_headers_json, cookies_json, raw_headers_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                f.id,
                f.recon_scan_id,
                f.asset_id,
                f.target_url,
                f.status_code,
                f.server_header,
                f.title,
                f.content_type,
                f.tls_version,
                f.tls_cipher,
                f.tls_cert_subject,
                f.tls_cert_issuer,
                f.tls_cert_days_left,
                f.security_headers_json,
                f.cookies_json,
                f.raw_headers_json,
                f.created_at
            ],
        )?;
        Ok(())
    }

    pub fn get_recon_summary(&self, asset_id: &str) -> Result<ReconSummary> {
        let conn = self.conn.lock().unwrap();

        // 1. Subdomains
        let mut sub_stmt = conn.prepare("SELECT id, recon_scan_id, asset_id, subdomain, ip_addresses, source, confidence, is_live, http_status, created_at FROM recon_subdomains WHERE asset_id = ?1 ORDER BY is_live DESC, subdomain ASC")?;
        let sub_rows = sub_stmt.query_map(params![asset_id], |row| {
            let is_live_int: i64 = row.get(7)?;
            Ok(ReconSubdomain {
                id: row.get(0)?,
                recon_scan_id: row.get(1)?,
                asset_id: row.get(2)?,
                subdomain: row.get(3)?,
                ip_addresses: row.get(4)?,
                source: row.get(5)?,
                confidence: row.get(6)?,
                is_live: is_live_int == 1,
                http_status: row.get(7)?,
                created_at: row.get(9)?,
            })
        })?;
        let mut subdomains = Vec::new();
        for r in sub_rows {
            subdomains.push(r?);
        }

        // 2. DNS Records
        let mut dns_stmt = conn.prepare("SELECT id, recon_scan_id, asset_id, domain, record_type, record_value, ttl, is_takeover_risk, takeover_reason, created_at FROM recon_dns_records WHERE asset_id = ?1 ORDER BY domain ASC, record_type ASC")?;
        let dns_rows = dns_stmt.query_map(params![asset_id], |row| {
            let risk_int: i64 = row.get(7)?;
            Ok(ReconDnsRecord {
                id: row.get(0)?,
                recon_scan_id: row.get(1)?,
                asset_id: row.get(2)?,
                domain: row.get(3)?,
                record_type: row.get(4)?,
                record_value: row.get(5)?,
                ttl: row.get(6)?,
                is_takeover_risk: risk_int == 1,
                takeover_reason: row.get(8)?,
                created_at: row.get(9)?,
            })
        })?;
        let mut dns_records = Vec::new();
        for r in dns_rows {
            dns_records.push(r?);
        }

        // 3. Technologies
        let mut tech_stmt = conn.prepare("SELECT id, recon_scan_id, asset_id, target_url, name, category, version, confidence, matched_indicators_json, created_at FROM recon_technologies WHERE asset_id = ?1 ORDER BY name ASC")?;
        let tech_rows = tech_stmt.query_map(params![asset_id], |row| {
            Ok(ReconTechnology {
                id: row.get(0)?,
                recon_scan_id: row.get(1)?,
                asset_id: row.get(2)?,
                target_url: row.get(3)?,
                name: row.get(4)?,
                category: row.get(5)?,
                version: row.get(6)?,
                confidence: row.get(7)?,
                matched_indicators_json: row.get(8)?,
                created_at: row.get(9)?,
            })
        })?;
        let mut technologies = Vec::new();
        for r in tech_rows {
            technologies.push(r?);
        }

        // 4. HTTP Fingerprints
        let mut fp_stmt = conn.prepare("SELECT id, recon_scan_id, asset_id, target_url, status_code, server_header, title, content_type, tls_version, tls_cipher, tls_cert_subject, tls_cert_issuer, tls_cert_days_left, security_headers_json, cookies_json, raw_headers_json, created_at FROM recon_http_fingerprints WHERE asset_id = ?1 ORDER BY target_url ASC")?;
        let fp_rows = fp_stmt.query_map(params![asset_id], |row| {
            Ok(ReconHttpFingerprint {
                id: row.get(0)?,
                recon_scan_id: row.get(1)?,
                asset_id: row.get(2)?,
                target_url: row.get(3)?,
                status_code: row.get(4)?,
                server_header: row.get(5)?,
                title: row.get(6)?,
                content_type: row.get(7)?,
                tls_version: row.get(8)?,
                tls_cipher: row.get(9)?,
                tls_cert_subject: row.get(10)?,
                tls_cert_issuer: row.get(11)?,
                tls_cert_days_left: row.get(12)?,
                security_headers_json: row.get(13)?,
                cookies_json: row.get(14)?,
                raw_headers_json: row.get(15)?,
                created_at: row.get(16)?,
            })
        })?;
        let mut http_fingerprints = Vec::new();
        for r in fp_rows {
            http_fingerprints.push(r?);
        }

        Ok(ReconSummary {
            subdomains,
            dns_records,
            technologies,
            http_fingerprints,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_db_migrations() {
        let db = DatabaseManager::new_in_memory().expect("Should initialize in-memory DB");
        let stats = db.get_dashboard_stats().expect("Should get stats");
        assert_eq!(stats.total_assets, 0);
        assert_eq!(stats.authorized_assets, 0);
        assert_eq!(stats.active_sessions, 0);
        assert_eq!(stats.total_exclusions, 0);
    }

    #[test]
    fn test_asset_lifecycle_and_scope() {
        let db = DatabaseManager::new_in_memory().expect("Should initialize in-memory DB");
        let asset = Asset {
            id: "test-asset-1".to_string(),
            name: "Test Target".to_string(),
            target: "https://test.local".to_string(),
            asset_type: "url".to_string(),
            authorized: false,
            authorized_by: None,
            authorized_at: None,
            notes: Some("Initial registration".to_string()),
            created_at: "2026-11-01T00:00:00Z".to_string(),
            updated_at: "2026-11-01T00:00:00Z".to_string(),
        };

        db.insert_asset(&asset).expect("Should insert asset");
        let assets = db.list_assets().expect("Should list assets");
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].authorized, false);

        // Check automatically created scope
        let scope = db.get_scope("test-asset-1").expect("Should query scope");
        assert!(scope.is_some());
        assert_eq!(scope.unwrap().passive_only, true);

        // Sign authorization
        db.update_asset_authorization("test-asset-1", true, Some("Auditor X".to_string()))
            .expect("Should update authorization");
        let updated = db.list_assets().expect("Should list assets");
        assert_eq!(updated[0].authorized, true);
        assert_eq!(updated[0].authorized_by, Some("Auditor X".to_string()));

        let scope_updated = db.get_scope("test-asset-1").expect("Should query scope");
        assert_eq!(scope_updated.unwrap().passive_only, false);
    }

    #[test]
    fn test_scope_exclusions_and_compliance() {
        let db = DatabaseManager::new_in_memory().expect("Should initialize in-memory DB");
        let asset = Asset {
            id: "ast-exc-1".to_string(),
            name: "Portal".to_string(),
            target: "https://portal.local".to_string(),
            asset_type: "url".to_string(),
            authorized: true,
            authorized_by: Some("Lead".to_string()),
            authorized_at: None,
            notes: None,
            created_at: "2026-11-01T00:00:00Z".to_string(),
            updated_at: "2026-11-01T00:00:00Z".to_string(),
        };
        db.insert_asset(&asset).unwrap();

        let exc = ScopeExclusion {
            id: "exc-1".to_string(),
            asset_id: "ast-exc-1".to_string(),
            pattern: "/admin/billing".to_string(),
            exclusion_type: "path".to_string(),
            reason: "Critical production billing endpoint".to_string(),
            created_at: "2026-11-01T00:00:00Z".to_string(),
        };
        db.insert_exclusion(&exc).expect("Should insert exclusion");

        let in_scope = db.check_path_in_scope("ast-exc-1", "/public/catalog").unwrap();
        assert_eq!(in_scope, true);

        let excluded = db.check_path_in_scope("ast-exc-1", "/admin/billing/checkout").unwrap();
        assert_eq!(excluded, false);
    }

    #[test]
    fn test_audit_sessions_lifecycle() {
        let db = DatabaseManager::new_in_memory().expect("Should initialize in-memory DB");
        let asset = Asset {
            id: "ast-sess-1".to_string(),
            name: "Internal API".to_string(),
            target: "https://api.internal.local".to_string(),
            asset_type: "url".to_string(),
            authorized: true,
            authorized_by: Some("Lead".to_string()),
            authorized_at: None,
            notes: None,
            created_at: "2026-11-01T00:00:00Z".to_string(),
            updated_at: "2026-11-01T00:00:00Z".to_string(),
        };
        db.insert_asset(&asset).unwrap();

        let session = AuditSession {
            id: "sess-1".to_string(),
            name: "Q4 External Assessment".to_string(),
            asset_id: "ast-sess-1".to_string(),
            auditor_name: "Auditor Jane".to_string(),
            status: "active".to_string(),
            start_time: "2026-11-01T08:00:00Z".to_string(),
            end_time: None,
            summary: None,
            findings_count: 0,
            created_at: "2026-11-01T08:00:00Z".to_string(),
        };
        db.insert_audit_session(&session).unwrap();

        let active_sessions = db.list_audit_sessions(None).unwrap();
        assert_eq!(active_sessions.len(), 1);
        assert_eq!(active_sessions[0].status, "active");

        db.close_audit_session("sess-1", Some("Assessment completed cleanly with 0 crashes.")).unwrap();
        let closed = db.list_audit_sessions(None).unwrap();
        assert_eq!(closed[0].status, "completed");
        assert!(closed[0].end_time.is_some());
    }

    #[test]
    fn test_vulnerability_deduplication() {
        let db = DatabaseManager::new_in_memory().expect("Should initialize in-memory DB");
        let asset = Asset {
            id: "ast-dedup-1".to_string(),
            name: "App".to_string(),
            target: "https://app.local".to_string(),
            asset_type: "url".to_string(),
            authorized: true,
            authorized_by: None,
            authorized_at: None,
            notes: None,
            created_at: "2026-11-01T00:00:00Z".to_string(),
            updated_at: "2026-11-01T00:00:00Z".to_string(),
        };
        db.insert_asset(&asset).unwrap();

        let scan = Scan {
            id: "scan-dedup-1".to_string(),
            name: "Dedup Test Scan".to_string(),
            asset_id: "ast-dedup-1".to_string(),
            scan_mode: "active".to_string(),
            status: "completed".to_string(),
            progress: 100.0,
            started_at: None,
            completed_at: None,
            error_message: None,
            config_json: "{}".to_string(),
            created_at: "2026-11-01T00:00:00Z".to_string(),
        };
        db.insert_scan(&scan).unwrap();

        let v1 = Vulnerability {
            id: "v-dedup-1".to_string(),
            scan_id: "scan-dedup-1".to_string(),
            asset_id: "ast-dedup-1".to_string(),
            title: "XSS Search".to_string(),
            category: "Web Security".to_string(),
            attack_type: "xss".to_string(),
            vector: "query:q".to_string(),
            severity: "high".to_string(),
            confidence: 90,
            cve: None,
            cwe: Some("CWE-79".to_string()),
            owasp: Some("A03:2021".to_string()),
            cvss_score: Some(7.5),
            description: None,
            evidence_json: "{\"param\": \"q\"}".to_string(),
            remediation: None,
            verified: true,
            status: "open".to_string(),
            created_at: "2026-11-01T00:00:00Z".to_string(),
            fingerprint: Some("ast-dedup-1:xss:query:q:XSS Search".to_string()),
            false_positive_reason: None,
            remediation_notes: None,
            resolved_at: None,
            occurrences: 1,
        };

        db.insert_vulnerability_with_dedup(&v1).expect("Insert v1");

        // Insert identical vulnerability
        let mut v2 = v1.clone();
        v2.id = "v-dedup-2".to_string();
        v2.confidence = 95;
        db.insert_vulnerability_with_dedup(&v2).expect("Insert v2 should dedup");

        let vulns = db.list_vulnerabilities().expect("List vulns");
        assert_eq!(vulns.len(), 1, "Duplicate should not create new row");
        assert_eq!(vulns[0].occurrences, 2, "Occurrences counter should be incremented");
        assert_eq!(vulns[0].confidence, 95, "Confidence should take maximum");
    }

    #[test]
    fn test_remediation_status_transition_and_history() {
        let db = DatabaseManager::new_in_memory().expect("Should initialize in-memory DB");
        let asset = Asset {
            id: "ast-rem-1".to_string(),
            name: "App".to_string(),
            target: "https://app.local".to_string(),
            asset_type: "url".to_string(),
            authorized: true,
            authorized_by: None,
            authorized_at: None,
            notes: None,
            created_at: "2026-11-01T00:00:00Z".to_string(),
            updated_at: "2026-11-01T00:00:00Z".to_string(),
        };
        db.insert_asset(&asset).unwrap();

        let scan = Scan {
            id: "scan-rem-1".to_string(),
            name: "Remediation Test Scan".to_string(),
            asset_id: "ast-rem-1".to_string(),
            scan_mode: "active".to_string(),
            status: "completed".to_string(),
            progress: 100.0,
            started_at: None,
            completed_at: None,
            error_message: None,
            config_json: "{}".to_string(),
            created_at: "2026-11-01T00:00:00Z".to_string(),
        };
        db.insert_scan(&scan).unwrap();

        let v = Vulnerability {
            id: "v-rem-1".to_string(),
            scan_id: "scan-rem-1".to_string(),
            asset_id: "ast-rem-1".to_string(),
            title: "SSTI Render".to_string(),
            category: "Web Security".to_string(),
            attack_type: "ssti".to_string(),
            vector: "query:tmpl".to_string(),
            severity: "critical".to_string(),
            confidence: 100,
            cve: None,
            cwe: Some("CWE-1336".to_string()),
            owasp: Some("A03:2021".to_string()),
            cvss_score: Some(9.8),
            description: None,
            evidence_json: "{}".to_string(),
            remediation: None,
            verified: true,
            status: "open".to_string(),
            created_at: "2026-11-01T00:00:00Z".to_string(),
            fingerprint: Some("ast-rem-1:ssti:query:tmpl:SSTI Render".to_string()),
            false_positive_reason: None,
            remediation_notes: None,
            resolved_at: None,
            occurrences: 1,
        };
        db.insert_vulnerability_with_dedup(&v).unwrap();

        // Mark remediated
        db.update_vulnerability_status(
            "v-rem-1",
            "remediated",
            Some("Patched in release v2.4 by escaping template strings"),
            "SecLead",
        )
        .expect("Update status");

        let updated = db.list_vulnerabilities().unwrap();
        assert_eq!(updated[0].status, "remediated");
        assert!(updated[0].resolved_at.is_some());
        assert_eq!(
            updated[0].remediation_notes,
            Some("Patched in release v2.4 by escaping template strings".to_string())
        );

        // Check remediation diff
        let diff = db.get_remediation_diff("ast-rem-1").unwrap();
        assert_eq!(diff.resolved_findings.len(), 1);
        assert_eq!(diff.new_findings.len(), 0);
    }

    #[test]
    fn test_reconnaissance_lifecycle() {
        let db = DatabaseManager::new_in_memory().expect("In-memory DB");

        // Insert asset
        let asset = Asset {
            id: "ast-recon-1".to_string(),
            name: "Corp Staging".to_string(),
            target: "https://staging.corp.internal".to_string(),
            asset_type: "url".to_string(),
            authorized: true,
            authorized_by: Some("LeadSec".to_string()),
            authorized_at: Some("2026-11-01T00:00:00Z".to_string()),
            notes: None,
            created_at: "2026-11-01T00:00:00Z".to_string(),
            updated_at: "2026-11-01T00:00:00Z".to_string(),
        };
        db.insert_asset(&asset).unwrap();

        // Insert ReconScan
        let rscan = ReconScan {
            id: "rscan-1".to_string(),
            asset_id: "ast-recon-1".to_string(),
            status: "running".to_string(),
            mode: "all".to_string(),
            target_domain: "staging.corp.internal".to_string(),
            subdomains_count: 0,
            dns_records_count: 0,
            technologies_count: 0,
            started_at: "2026-11-01T00:00:00Z".to_string(),
            completed_at: None,
            error_message: None,
        };
        db.insert_recon_scan(&rscan).unwrap();

        // Insert Subdomain
        let sub = ReconSubdomain {
            id: "sub-1".to_string(),
            recon_scan_id: "rscan-1".to_string(),
            asset_id: "ast-recon-1".to_string(),
            subdomain: "api.staging.corp.internal".to_string(),
            ip_addresses: "[\"10.0.0.15\"]".to_string(),
            source: "crt.sh".to_string(),
            confidence: 90,
            is_live: true,
            http_status: Some(200),
            created_at: "2026-11-01T00:00:00Z".to_string(),
        };
        db.insert_recon_subdomain(&sub).unwrap();

        // Insert DNS record
        let dns = ReconDnsRecord {
            id: "dns-1".to_string(),
            recon_scan_id: "rscan-1".to_string(),
            asset_id: "ast-recon-1".to_string(),
            domain: "staging.corp.internal".to_string(),
            record_type: "CNAME".to_string(),
            record_value: "cname.s3-website.amazonaws.com".to_string(),
            ttl: Some(300),
            is_takeover_risk: true,
            takeover_reason: Some("Dangling S3 bucket bucket-404".to_string()),
            created_at: "2026-11-01T00:00:00Z".to_string(),
        };
        db.insert_recon_dns_record(&dns).unwrap();

        // Insert Technology
        let tech = ReconTechnology {
            id: "tech-1".to_string(),
            recon_scan_id: "rscan-1".to_string(),
            asset_id: "ast-recon-1".to_string(),
            target_url: "https://staging.corp.internal".to_string(),
            name: "Nginx".to_string(),
            category: "Web Server".to_string(),
            version: Some("1.24.0".to_string()),
            confidence: "Confirmed".to_string(),
            matched_indicators_json: "[\"Server: nginx/1.24.0\"]".to_string(),
            created_at: "2026-11-01T00:00:00Z".to_string(),
        };
        db.insert_recon_technology(&tech).unwrap();

        // Update Scan to completed
        db.update_recon_scan_status("rscan-1", "completed", 1, 1, 1, None).unwrap();

        let scans = db.list_recon_scans(Some("ast-recon-1")).unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].status, "completed");
        assert_eq!(scans[0].subdomains_count, 1);

        // Get Summary
        let summary = db.get_recon_summary("ast-recon-1").unwrap();
        assert_eq!(summary.subdomains.len(), 1);
        assert_eq!(summary.subdomains[0].subdomain, "api.staging.corp.internal");
        assert_eq!(summary.dns_records.len(), 1);
        assert!(summary.dns_records[0].is_takeover_risk);
        assert_eq!(summary.technologies.len(), 1);
        assert_eq!(summary.technologies[0].name, "Nginx");
    }
}
