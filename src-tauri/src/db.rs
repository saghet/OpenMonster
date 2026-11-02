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
        let migration_sql = include_str!("../../database/migrations/001_initial_schema.sql");
        conn.execute_batch(migration_sql)?;
        Ok(())
    }

    pub fn get_dashboard_stats(&self) -> Result<DashboardStats> {
        let conn = self.conn.lock().unwrap();
        
        let total_assets: i64 = conn.query_row(
            "SELECT COUNT(*) FROM assets",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        let authorized_assets: i64 = conn.query_row(
            "SELECT COUNT(*) FROM assets WHERE authorized = 1",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        let active_scans: i64 = conn.query_row(
            "SELECT COUNT(*) FROM scans WHERE status = 'running'",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        let total_vulnerabilities: i64 = conn.query_row(
            "SELECT COUNT(*) FROM vulnerabilities",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        let critical_vulns: i64 = conn.query_row(
            "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'critical'",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        let high_vulns: i64 = conn.query_row(
            "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'high'",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        let medium_vulns: i64 = conn.query_row(
            "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'medium'",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        let low_vulns: i64 = conn.query_row(
            "SELECT COUNT(*) FROM vulnerabilities WHERE severity = 'low'",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

        let verified_vulns: i64 = conn.query_row(
            "SELECT COUNT(*) FROM vulnerabilities WHERE verified = 1",
            [],
            |r| r.get(0),
        ).unwrap_or(0);

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
        })
    }

    pub fn list_assets(&self) -> Result<Vec<Asset>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, name, target, asset_type, authorized, authorized_by, authorized_at, notes, created_at, updated_at FROM assets ORDER BY created_at DESC"
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
        Ok(())
    }

    pub fn update_asset_authorization(&self, id: &str, authorized: bool, authorized_by: Option<String>) -> Result<()> {
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
        Ok(())
    }

    pub fn list_vulnerabilities(&self) -> Result<Vec<Vulnerability>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, scan_id, asset_id, title, category, attack_type, vector, severity, confidence, cve, cwe, owasp, cvss_score, description, evidence_json, remediation, verified, status, created_at FROM vulnerabilities ORDER BY created_at DESC"
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
            })
        })?;

        let mut vulns = Vec::new();
        for r in rows {
            vulns.push(r?);
        }
        Ok(vulns)
    }

    pub fn insert_vulnerability(&self, v: &Vulnerability) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO vulnerabilities (id, scan_id, asset_id, title, category, attack_type, vector, severity, confidence, cve, cwe, owasp, cvss_score, description, evidence_json, remediation, verified, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
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
                v.created_at
            ],
        )?;
        Ok(())
    }

    pub fn list_audit_logs(&self) -> Result<Vec<AuditLog>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, actor, action, target, details_json, status FROM audit_logs ORDER BY timestamp DESC LIMIT 100"
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
            "SELECT id, name, asset_id, scan_mode, status, progress, started_at, completed_at, error_message, config_json, created_at FROM scans ORDER BY created_at DESC"
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

        // Sign authorization
        db.update_asset_authorization("test-asset-1", true, Some("Auditor X".to_string()))
            .expect("Should update authorization");
        let updated = db.list_assets().expect("Should list assets");
        assert_eq!(updated[0].authorized, true);
        assert_eq!(updated[0].authorized_by, Some("Auditor X".to_string()));
    }

    #[test]
    fn test_vulnerability_and_audit_logging() {
        let db = DatabaseManager::new_in_memory().expect("Should initialize in-memory DB");
        let asset = Asset {
            id: "asset-vuln-1".to_string(),
            name: "Target".to_string(),
            target: "https://vuln.local".to_string(),
            asset_type: "url".to_string(),
            authorized: true,
            authorized_by: Some("Auditor".to_string()),
            authorized_at: None,
            notes: None,
            created_at: "2026-11-01T00:00:00Z".to_string(),
            updated_at: "2026-11-01T00:00:00Z".to_string(),
        };
        db.insert_asset(&asset).unwrap();

        let scan = Scan {
            id: "scan-1".to_string(),
            name: "Initial Scan".to_string(),
            asset_id: "asset-vuln-1".to_string(),
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

        let vuln = Vulnerability {
            id: "v-1".to_string(),
            scan_id: "scan-1".to_string(),
            asset_id: "asset-vuln-1".to_string(),
            title: "Differential XSS".to_string(),
            category: "Web Security".to_string(),
            attack_type: "xss".to_string(),
            vector: "query".to_string(),
            severity: "high".to_string(),
            confidence: 90,
            cve: None,
            cwe: Some("CWE-79".to_string()),
            owasp: Some("A03:2021".to_string()),
            cvss_score: Some(7.5),
            description: Some("Contextual unescaped reflection".to_string()),
            evidence_json: "{}".to_string(),
            remediation: Some("Encode output".to_string()),
            verified: true,
            status: "open".to_string(),
            created_at: "2026-11-01T00:00:00Z".to_string(),
        };
        db.insert_vulnerability(&vuln).unwrap();

        let vulns = db.list_vulnerabilities().unwrap();
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].title, "Differential XSS");
        assert_eq!(vulns[0].verified, true);
    }
}
