use crate::db::{
    Asset, AuditLog, AuditSession, DashboardStats, DatabaseManager, Scan, Scope, ScopeExclusion,
    Vulnerability,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, State};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use uuid::Uuid;

pub struct AppState {
    pub db: Arc<DatabaseManager>,
    pub running_processes: Arc<Mutex<HashMap<String, u32>>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateAssetRequest {
    pub name: String,
    pub target: String,
    pub asset_type: String,
    pub notes: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizeAssetRequest {
    pub id: String,
    pub authorized: bool,
    pub authorized_by: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateScanRequest {
    pub name: String,
    pub asset_id: String,
    pub scan_mode: String,
    pub vectors: Option<Vec<String>>,
    pub rate_limit: Option<i64>,
    pub config_json: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddExclusionRequest {
    pub asset_id: String,
    pub pattern: String,
    pub exclusion_type: String,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub name: String,
    pub asset_id: String,
    pub auditor_name: String,
}

#[tauri::command]
pub async fn get_dashboard_stats(state: State<'_, AppState>) -> Result<DashboardStats, String> {
    state.db.get_dashboard_stats().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_assets(state: State<'_, AppState>) -> Result<Vec<Asset>, String> {
    state.db.list_assets().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn create_asset(
    req: CreateAssetRequest,
    state: State<'_, AppState>,
) -> Result<Asset, String> {
    let now = chrono::Utc::now().to_rfc3339();
    let asset = Asset {
        id: Uuid::new_v4().to_string(),
        name: req.name,
        target: req.target.clone(),
        asset_type: req.asset_type,
        authorized: false,
        authorized_by: None,
        authorized_at: None,
        notes: req.notes,
        created_at: now.clone(),
        updated_at: now.clone(),
    };

    state.db.insert_asset(&asset).map_err(|e| e.to_string())?;

    let log = AuditLog {
        id: Uuid::new_v4().to_string(),
        timestamp: now,
        actor: "Operator".to_string(),
        action: "CREATE_ASSET".to_string(),
        target: Some(req.target),
        details_json: format!("{{\"asset_id\": \"{}\"}}", asset.id),
        status: "SUCCESS".to_string(),
    };
    let _ = state.db.insert_audit_log(&log);

    Ok(asset)
}

#[tauri::command]
pub async fn delete_asset(id: String, state: State<'_, AppState>) -> Result<(), String> {
    state.db.delete_asset(&id).map_err(|e| e.to_string())?;

    let log = AuditLog {
        id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        actor: "Operator".to_string(),
        action: "DELETE_ASSET".to_string(),
        target: Some(id),
        details_json: "{}".to_string(),
        status: "SUCCESS".to_string(),
    };
    let _ = state.db.insert_audit_log(&log);

    Ok(())
}

#[tauri::command]
pub async fn authorize_asset(
    req: AuthorizeAssetRequest,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .db
        .update_asset_authorization(&req.id, req.authorized, Some(req.authorized_by.clone()))
        .map_err(|e| e.to_string())?;

    let log = AuditLog {
        id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        actor: req.authorized_by,
        action: if req.authorized {
            "AUTHORIZE_SCOPE".to_string()
        } else {
            "REVOKE_SCOPE".to_string()
        },
        target: Some(req.id),
        details_json: "{}".to_string(),
        status: "SUCCESS".to_string(),
    };
    let _ = state.db.insert_audit_log(&log);

    Ok(())
}

#[tauri::command]
pub async fn get_scope(asset_id: String, state: State<'_, AppState>) -> Result<Option<Scope>, String> {
    state.db.get_scope(&asset_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn update_scope(scope: Scope, state: State<'_, AppState>) -> Result<(), String> {
    state.db.update_scope(&scope).map_err(|e| e.to_string())?;

    let log = AuditLog {
        id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        actor: "Operator".to_string(),
        action: "UPDATE_SCOPE_POLICIES".to_string(),
        target: Some(scope.asset_id),
        details_json: format!("{{\"rate_limit\": {}, \"passive\": {}}}", scope.max_rate, scope.passive_only),
        status: "SUCCESS".to_string(),
    };
    let _ = state.db.insert_audit_log(&log);

    Ok(())
}

#[tauri::command]
pub async fn list_exclusions(asset_id: String, state: State<'_, AppState>) -> Result<Vec<ScopeExclusion>, String> {
    state.db.list_exclusions(&asset_id).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn add_exclusion(req: AddExclusionRequest, state: State<'_, AppState>) -> Result<ScopeExclusion, String> {
    let now = chrono::Utc::now().to_rfc3339();
    let exc = ScopeExclusion {
        id: Uuid::new_v4().to_string(),
        asset_id: req.asset_id.clone(),
        pattern: req.pattern.clone(),
        exclusion_type: req.exclusion_type,
        reason: req.reason,
        created_at: now.clone(),
    };

    state.db.insert_exclusion(&exc).map_err(|e| e.to_string())?;

    let log = AuditLog {
        id: Uuid::new_v4().to_string(),
        timestamp: now,
        actor: "Operator".to_string(),
        action: "ADD_SCOPE_EXCLUSION".to_string(),
        target: Some(req.asset_id),
        details_json: format!("{{\"pattern\": \"{}\"}}", req.pattern),
        status: "SUCCESS".to_string(),
    };
    let _ = state.db.insert_audit_log(&log);

    Ok(exc)
}

#[tauri::command]
pub async fn delete_exclusion(id: String, state: State<'_, AppState>) -> Result<(), String> {
    state.db.delete_exclusion(&id).map_err(|e| e.to_string())?;

    let log = AuditLog {
        id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        actor: "Operator".to_string(),
        action: "REMOVE_SCOPE_EXCLUSION".to_string(),
        target: Some(id),
        details_json: "{}".to_string(),
        status: "SUCCESS".to_string(),
    };
    let _ = state.db.insert_audit_log(&log);

    Ok(())
}

#[tauri::command]
pub async fn list_audit_sessions(asset_id: Option<String>, state: State<'_, AppState>) -> Result<Vec<AuditSession>, String> {
    state.db.list_audit_sessions(asset_id.as_deref()).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn create_audit_session(req: CreateSessionRequest, state: State<'_, AppState>) -> Result<AuditSession, String> {
    let now = chrono::Utc::now().to_rfc3339();
    let session = AuditSession {
        id: Uuid::new_v4().to_string(),
        name: req.name,
        asset_id: req.asset_id.clone(),
        auditor_name: req.auditor_name,
        status: "active".to_string(),
        start_time: now.clone(),
        end_time: None,
        summary: None,
        findings_count: 0,
        created_at: now.clone(),
    };

    state.db.insert_audit_session(&session).map_err(|e| e.to_string())?;

    let log = AuditLog {
        id: Uuid::new_v4().to_string(),
        timestamp: now,
        actor: session.auditor_name.clone(),
        action: "START_AUDIT_SESSION".to_string(),
        target: Some(req.asset_id),
        details_json: format!("{{\"session_id\": \"{}\"}}", session.id),
        status: "SUCCESS".to_string(),
    };
    let _ = state.db.insert_audit_log(&log);

    Ok(session)
}

#[tauri::command]
pub async fn close_audit_session(id: String, summary: Option<String>, state: State<'_, AppState>) -> Result<(), String> {
    state.db.close_audit_session(&id, summary.as_deref()).map_err(|e| e.to_string())?;

    let log = AuditLog {
        id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        actor: "Operator".to_string(),
        action: "CLOSE_AUDIT_SESSION".to_string(),
        target: Some(id),
        details_json: "{}".to_string(),
        status: "SUCCESS".to_string(),
    };
    let _ = state.db.insert_audit_log(&log);

    Ok(())
}

#[tauri::command]
pub async fn get_vulnerabilities(state: State<'_, AppState>) -> Result<Vec<Vulnerability>, String> {
    state.db.list_vulnerabilities().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_audit_logs(state: State<'_, AppState>) -> Result<Vec<AuditLog>, String> {
    state.db.list_audit_logs().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_scans(state: State<'_, AppState>) -> Result<Vec<Scan>, String> {
    state.db.list_scans().map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn create_scan(
    req: CreateScanRequest,
    app_handle: AppHandle,
    state: State<'_, AppState>,
) -> Result<Scan, String> {
    let assets = state.db.list_assets().map_err(|e| e.to_string())?;
    let target_asset = assets.iter().find(|a| a.id == req.asset_id).cloned();

    let asset = match target_asset {
        Some(a) => {
            if req.scan_mode == "active" && !a.authorized {
                return Err("Scope authorization required: Target asset is not explicitly authorized for active testing.".to_string());
            }
            a
        }
        None => return Err("Asset not found.".to_string()),
    };

    let now = chrono::Utc::now().to_rfc3339();
    let scan = Scan {
        id: Uuid::new_v4().to_string(),
        name: req.name,
        asset_id: req.asset_id.clone(),
        scan_mode: req.scan_mode.clone(),
        status: "running".to_string(),
        progress: 0.0,
        started_at: Some(now.clone()),
        completed_at: None,
        error_message: None,
        config_json: req.config_json.unwrap_or_else(|| "{}".to_string()),
        created_at: now.clone(),
    };

    state.db.insert_scan(&scan).map_err(|e| e.to_string())?;

    let log = AuditLog {
        id: Uuid::new_v4().to_string(),
        timestamp: now.clone(),
        actor: "Operator".to_string(),
        action: "START_SCAN".to_string(),
        target: Some(scan.asset_id.clone()),
        details_json: format!("{{\"scan_id\": \"{}\", \"mode\": \"{}\"}}", scan.id, scan.scan_mode),
        status: "SUCCESS".to_string(),
    };
    let _ = state.db.insert_audit_log(&log);

    // Prepare Python subprocess execution
    let vectors_arg = req
        .vectors
        .map(|v| v.join(","))
        .unwrap_or_else(|| "headers,xss,sqli,ssti,openredirect".to_string());
    let rate_limit_arg = req.rate_limit.unwrap_or(20).to_string();

    let mut cmd = Command::new("python3");
    cmd.arg("engine/runner.py")
        .arg("--target")
        .arg(&asset.target)
        .arg("--scan-id")
        .arg(&scan.id)
        .arg("--asset-id")
        .arg(&scan.asset_id)
        .arg("--vectors")
        .arg(&vectors_arg)
        .arg("--rate-limit")
        .arg(&rate_limit_arg)
        .arg("--allowed-targets")
        .arg(&asset.target);

    if scan.scan_mode == "passive" {
        cmd.arg("--passive-only");
    }

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    match cmd.spawn() {
        Ok(mut child) => {
            let pid = child.id().unwrap_or(0);
            if pid > 0 {
                let mut map = state.running_processes.lock().unwrap();
                map.insert(scan.id.clone(), pid);
            }

            let stdout = child.stdout.take();
            let db_clone = state.db.clone();
            let proc_map_clone = state.running_processes.clone();
            let scan_id_clone = scan.id.clone();
            let asset_id_clone = scan.asset_id.clone();
            let app_clone = app_handle.clone();

            tokio::spawn(async move {
                if let Some(out) = stdout {
                    let mut reader = BufReader::new(out).lines();
                    while let Ok(Some(line)) = reader.next_line().await {
                        if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                            let event_type = event.get("type").and_then(|t| t.as_str()).unwrap_or("");

                            // Emit raw event to frontend
                            let _ = app_clone.emit("scan-event", &event);

                            match event_type {
                                "progress" => {
                                    if let Some(percent) = event.pointer("/data/percent").and_then(|p| p.as_f64()) {
                                        let _ = db_clone.update_scan_status(&scan_id_clone, "running", percent);
                                    }
                                }
                                "finding" => {
                                    if let Some(finding_data) = event.get("data") {
                                        let title = finding_data.get("title").and_then(|t| t.as_str()).unwrap_or("Untitled Finding");
                                        let category = finding_data.get("category").and_then(|t| t.as_str()).unwrap_or("Web Security");
                                        let attack_type = finding_data.get("attack_type").and_then(|t| t.as_str()).unwrap_or("general");
                                        let vector = finding_data.get("vector").and_then(|t| t.as_str()).unwrap_or("query");
                                        let severity = finding_data.get("severity").and_then(|t| t.as_str()).unwrap_or("medium");
                                        let confidence = finding_data.get("confidence").and_then(|t| t.as_i64()).unwrap_or(80);
                                        let cve = finding_data.get("cve").and_then(|t| t.as_str()).map(|s| s.to_string());
                                        let cwe = finding_data.get("cwe").and_then(|t| t.as_str()).map(|s| s.to_string());
                                        let owasp = finding_data.get("owasp").and_then(|t| t.as_str()).map(|s| s.to_string());
                                        let cvss_score = finding_data.get("cvss_score").and_then(|t| t.as_f64());
                                        let description = finding_data.get("description").and_then(|t| t.as_str()).map(|s| s.to_string());
                                        let evidence_json = finding_data.get("evidence").map(|e| e.to_string()).unwrap_or_else(|| "{}".to_string());
                                        let remediation = finding_data.get("remediation").and_then(|t| t.as_str()).map(|s| s.to_string());
                                        let verified = finding_data.get("verified").and_then(|t| t.as_bool()).unwrap_or(false);

                                        let vuln = Vulnerability {
                                            id: Uuid::new_v4().to_string(),
                                            scan_id: scan_id_clone.clone(),
                                            asset_id: asset_id_clone.clone(),
                                            title: title.to_string(),
                                            category: category.to_string(),
                                            attack_type: attack_type.to_string(),
                                            vector: vector.to_string(),
                                            severity: severity.to_string(),
                                            confidence,
                                            cve,
                                            cwe,
                                            owasp,
                                            cvss_score,
                                            description,
                                            evidence_json,
                                            remediation,
                                            verified,
                                            status: "open".to_string(),
                                            created_at: chrono::Utc::now().to_rfc3339(),
                                        };
                                        let _ = db_clone.insert_vulnerability(&vuln);
                                    }
                                }
                                "completed" => {
                                    let _ = db_clone.update_scan_status(&scan_id_clone, "completed", 100.0);
                                }
                                "error" => {
                                    let _ = db_clone.update_scan_status(&scan_id_clone, "failed", 100.0);
                                }
                                _ => {}
                            }
                        }
                    }
                }

                // Process exited: clean up process map
                let _ = child.wait().await;
                let mut map = proc_map_clone.lock().unwrap();
                map.remove(&scan_id_clone);
            });
        }
        Err(e) => {
            let _ = state.db.update_scan_status(&scan.id, "failed", 0.0);
            return Err(format!("Failed to launch scanner process: {}", e));
        }
    }

    Ok(scan)
}

#[tauri::command]
pub async fn cancel_scan(scan_id: String, state: State<'_, AppState>) -> Result<(), String> {
    // Look up child PID and kill via SIGTERM
    let pid_opt = {
        let mut map = state.running_processes.lock().unwrap();
        map.remove(&scan_id)
    };

    if let Some(pid) = pid_opt {
        let _ = std::process::Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .output();
    }

    state
        .db
        .update_scan_status(&scan_id, "cancelled", 100.0)
        .map_err(|e| e.to_string())?;

    let log = AuditLog {
        id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        actor: "Operator".to_string(),
        action: "CANCEL_SCAN".to_string(),
        target: Some(scan_id),
        details_json: "{}".to_string(),
        status: "SUCCESS".to_string(),
    };
    let _ = state.db.insert_audit_log(&log);

    Ok(())
}
