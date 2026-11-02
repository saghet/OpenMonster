use crate::db::{
    Asset, AuditLog, AuditSession, DashboardStats, DatabaseManager, ReconDnsRecord,
    ReconHttpFingerprint, ReconScan, ReconSubdomain, ReconSummary, ReconTechnology, Scan, Scope,
    ScopeExclusion, Vulnerability,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateVulnStatusRequest {
    pub id: String,
    pub status: String,
    pub notes: Option<String>,
    pub actor: String,
}

#[tauri::command]
pub async fn update_vulnerability_status(
    req: UpdateVulnStatusRequest,
    state: State<'_, AppState>,
) -> Result<(), String> {
    state
        .db
        .update_vulnerability_status(&req.id, &req.status, req.notes.as_deref(), &req.actor)
        .map_err(|e| e.to_string())?;

    let log = AuditLog {
        id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        actor: req.actor,
        action: format!("UPDATE_VULN_STATUS_{}", req.status.to_uppercase()),
        target: Some(req.id),
        details_json: format!("{{\"notes\": \"{}\"}}", req.notes.unwrap_or_default()),
        status: "SUCCESS".to_string(),
    };
    let _ = state.db.insert_audit_log(&log);

    Ok(())
}

#[tauri::command]
pub async fn get_remediation_diff(
    asset_id: String,
    state: State<'_, AppState>,
) -> Result<crate::db::RemediationDiff, String> {
    state.db.get_remediation_diff(&asset_id).map_err(|e| e.to_string())
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
                                            fingerprint: Some(format!("{}:{}:{}:{}", asset_id_clone, attack_type, vector, title)),
                                            false_positive_reason: None,
                                            remediation_notes: None,
                                            resolved_at: None,
                                            occurrences: 1,
                                        };
                                        let _ = db_clone.insert_vulnerability_with_dedup(&vuln);
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

fn get_cli_path() -> std::path::PathBuf {
    let p1 = std::path::PathBuf::from("engine/cli.py");
    if p1.exists() {
        return p1;
    }
    let p2 = std::path::PathBuf::from("../engine/cli.py");
    if p2.exists() {
        return p2;
    }
    p1
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PluginItem {
    pub plugin_id: String,
    pub name: String,
    pub version: String,
    pub author: String,
    pub license: String,
    pub category: String,
    pub description: String,
    pub entrypoint: String,
    pub permissions: Vec<String>,
    pub dependencies: Vec<String>,
    pub risk_level: String,
    pub cwe: Option<String>,
    pub owasp: Option<String>,
    pub integrity_hash: Option<String>,
    pub enabled: bool,
}

#[tauri::command]
pub async fn list_plugins() -> Result<Vec<PluginItem>, String> {
    let cli = get_cli_path();
    let output = Command::new("python3")
        .arg(&cli)
        .arg("plugins")
        .arg("list")
        .output()
        .await
        .map_err(|e| format!("Failed to execute plugin discovery: {}", e))?;

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Plugin discovery error: {}", err_msg));
    }

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let plugins: Vec<PluginItem> = serde_json::from_str(&stdout_str)
        .map_err(|e| format!("Failed to parse plugin json: {} (Output: {})", e, stdout_str))?;

    Ok(plugins)
}

#[tauri::command]
pub async fn toggle_plugin(plugin_id: String, enabled: bool) -> Result<bool, String> {
    let cli = get_cli_path();
    let enable_str = if enabled { "true" } else { "false" };
    let output = Command::new("python3")
        .arg(&cli)
        .arg("plugins")
        .arg("toggle")
        .arg(&plugin_id)
        .arg(enable_str)
        .output()
        .await
        .map_err(|e| format!("Failed to toggle plugin: {}", e))?;

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Plugin toggle error: {}", err_msg));
    }

    Ok(enabled)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OllamaStatusResponse {
    pub available: bool,
    pub models: Vec<String>,
    pub error_message: Option<String>,
}

#[tauri::command]
pub async fn check_ollama_status() -> Result<OllamaStatusResponse, String> {
    let cli = get_cli_path();
    let output = Command::new("python3")
        .arg(&cli)
        .arg("ollama")
        .arg("status")
        .output()
        .await
        .map_err(|e| format!("Failed to query Ollama daemon: {}", e))?;

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let status: OllamaStatusResponse = serde_json::from_str(&stdout_str)
        .map_err(|e| format!("Failed to parse Ollama status: {} (Raw: {})", e, stdout_str))?;

    Ok(status)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExplainVulnRequest {
    pub title: String,
    pub category: String,
    pub severity: String,
    pub cwe: Option<String>,
    pub description: Option<String>,
    pub evidence: Option<String>,
    pub model: Option<String>,
}

#[tauri::command]
pub async fn explain_vulnerability_ai(req: ExplainVulnRequest) -> Result<serde_json::Value, String> {
    let cli = get_cli_path();
    let mut cmd = Command::new("python3");
    cmd.arg(&cli)
        .arg("ollama")
        .arg("explain")
        .arg("--title")
        .arg(&req.title)
        .arg("--category")
        .arg(&req.category)
        .arg("--severity")
        .arg(&req.severity)
        .arg("--cwe")
        .arg(req.cwe.as_deref().unwrap_or(""))
        .arg("--description")
        .arg(req.description.as_deref().unwrap_or(""))
        .arg("--evidence")
        .arg(req.evidence.as_deref().unwrap_or("{}"));

    if let Some(m) = req.model {
        if !m.is_empty() {
            cmd.arg("--model").arg(m);
        }
    }

    let output = cmd
        .output()
        .await
        .map_err(|e| format!("Failed to query AI assistant: {}", e))?;

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let res: serde_json::Value = serde_json::from_str(&stdout_str)
        .map_err(|e| format!("Failed to parse AI response: {} (Raw: {})", e, stdout_str))?;

    Ok(res)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PrioritizeRequest {
    pub findings_json: String,
    pub model: Option<String>,
}

#[tauri::command]
pub async fn prioritize_vulnerabilities_ai(req: PrioritizeRequest) -> Result<serde_json::Value, String> {
    let cli = get_cli_path();
    let mut cmd = Command::new("python3");
    cmd.arg(&cli)
        .arg("ollama")
        .arg("prioritize")
        .arg("--findings")
        .arg(&req.findings_json);

    if let Some(m) = req.model {
        if !m.is_empty() {
            cmd.arg("--model").arg(m);
        }
    }

    let output = cmd
        .output()
        .await
        .map_err(|e| format!("Failed to query AI prioritization: {}", e))?;

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let res: serde_json::Value = serde_json::from_str(&stdout_str)
        .map_err(|e| format!("Failed to parse AI prioritization: {} (Raw: {})", e, stdout_str))?;

    Ok(res)
}

#[tauri::command]
pub async fn get_system_diagnostics() -> Result<serde_json::Value, String> {
    let cli = get_cli_path();
    let output = Command::new("python3")
        .arg(&cli)
        .arg("diagnose")
        .output()
        .await
        .map_err(|e| format!("Failed to execute local diagnostics: {}", e))?;

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    let res: serde_json::Value = serde_json::from_str(&stdout_str)
        .map_err(|e| format!("Failed to parse diagnostics JSON: {} (Raw: {})", e, stdout_str))?;

    Ok(res)
}

fn get_recon_orchestrator_path() -> std::path::PathBuf {
    let p1 = std::path::PathBuf::from("engine/recon/orchestrator.py");
    if p1.exists() {
        return p1;
    }
    let p2 = std::path::PathBuf::from("../engine/recon/orchestrator.py");
    if p2.exists() {
        return p2;
    }
    p1
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateReconScanRequest {
    pub asset_id: String,
    pub mode: String,
    pub rate_limit: Option<i64>,
}

#[tauri::command]
pub async fn create_recon_scan(
    req: CreateReconScanRequest,
    app_handle: AppHandle,
    state: State<'_, AppState>,
) -> Result<ReconScan, String> {
    let assets = state.db.list_assets().map_err(|e| e.to_string())?;
    let target_asset = assets.iter().find(|a| a.id == req.asset_id).cloned();

    let asset = match target_asset {
        Some(a) => {
            if req.mode != "passive" && !a.authorized {
                return Err("Scope authorization required: Target asset is not explicitly authorized for active reconnaissance testing.".to_string());
            }
            a
        }
        None => return Err("Asset not found.".to_string()),
    };

    let now = chrono::Utc::now().to_rfc3339();
    let scan = ReconScan {
        id: Uuid::new_v4().to_string(),
        asset_id: req.asset_id.clone(),
        status: "running".to_string(),
        mode: req.mode.clone(),
        target_domain: asset.target.clone(),
        subdomains_count: 0,
        dns_records_count: 0,
        technologies_count: 0,
        started_at: now.clone(),
        completed_at: None,
        error_message: None,
    };

    state.db.insert_recon_scan(&scan).map_err(|e| e.to_string())?;

    let log = AuditLog {
        id: Uuid::new_v4().to_string(),
        timestamp: now.clone(),
        actor: "Operator".to_string(),
        action: "START_RECON_SCAN".to_string(),
        target: Some(scan.asset_id.clone()),
        details_json: format!("{{\"recon_scan_id\": \"{}\", \"mode\": \"{}\"}}", scan.id, scan.mode),
        status: "SUCCESS".to_string(),
    };
    let _ = state.db.insert_audit_log(&log);

    let orch_path = get_recon_orchestrator_path();
    let rate_limit_arg = req.rate_limit.unwrap_or(10).to_string();

    let mut cmd = Command::new("python3");
    cmd.arg(&orch_path)
        .arg("--target")
        .arg(&asset.target)
        .arg("--asset-id")
        .arg(&scan.asset_id)
        .arg("--recon-scan-id")
        .arg(&scan.id)
        .arg("--mode")
        .arg(&scan.mode)
        .arg("--rate-limit")
        .arg(&rate_limit_arg)
        .arg("--allowed-targets")
        .arg(&asset.target);

    if scan.mode == "passive" {
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
                let mut sub_count = 0;
                let mut dns_count = 0;
                let mut tech_count = 0;

                if let Some(out) = stdout {
                    let mut reader = BufReader::new(out).lines();
                    while let Ok(Some(line)) = reader.next_line().await {
                        if let Ok(event) = serde_json::from_str::<serde_json::Value>(&line) {
                            let event_type = event.get("type").and_then(|t| t.as_str()).unwrap_or("");

                            let _ = app_clone.emit("recon-event", &event);

                            match event_type {
                                "recon_subdomain" => {
                                    if let Some(d) = event.get("data") {
                                        sub_count += 1;
                                        let sub = ReconSubdomain {
                                            id: Uuid::new_v4().to_string(),
                                            recon_scan_id: scan_id_clone.clone(),
                                            asset_id: asset_id_clone.clone(),
                                            subdomain: d.get("subdomain").and_then(|s| s.as_str()).unwrap_or("").to_string(),
                                            ip_addresses: serde_json::to_string(&d.get("ip_addresses").unwrap_or(&serde_json::json!([]))).unwrap_or_else(|_| "[]".to_string()),
                                            source: d.get("source").and_then(|s| s.as_str()).unwrap_or("crt.sh").to_string(),
                                            confidence: d.get("confidence").and_then(|c| c.as_i64()).unwrap_or(80),
                                            is_live: d.get("is_live").and_then(|l| l.as_bool()).unwrap_or(false),
                                            http_status: d.get("http_status").and_then(|s| s.as_i64()),
                                            created_at: chrono::Utc::now().to_rfc3339(),
                                        };
                                        let _ = db_clone.insert_recon_subdomain(&sub);
                                    }
                                }
                                "recon_dns" => {
                                    if let Some(d) = event.get("data") {
                                        dns_count += 1;
                                        let rec = ReconDnsRecord {
                                            id: Uuid::new_v4().to_string(),
                                            recon_scan_id: scan_id_clone.clone(),
                                            asset_id: asset_id_clone.clone(),
                                            domain: d.get("domain").and_then(|s| s.as_str()).unwrap_or("").to_string(),
                                            record_type: d.get("record_type").and_then(|s| s.as_str()).unwrap_or("A").to_string(),
                                            record_value: d.get("record_value").and_then(|s| s.as_str()).unwrap_or("").to_string(),
                                            ttl: d.get("ttl").and_then(|t| t.as_i64()),
                                            is_takeover_risk: d.get("is_takeover_risk").and_then(|r| r.as_bool()).unwrap_or(false),
                                            takeover_reason: d.get("takeover_reason").and_then(|r| r.as_str()).map(|s| s.to_string()),
                                            created_at: chrono::Utc::now().to_rfc3339(),
                                        };
                                        let _ = db_clone.insert_recon_dns_record(&rec);
                                    }
                                }
                                "recon_tech" => {
                                    if let Some(d) = event.get("data") {
                                        tech_count += 1;
                                        let tech = ReconTechnology {
                                            id: Uuid::new_v4().to_string(),
                                            recon_scan_id: scan_id_clone.clone(),
                                            asset_id: asset_id_clone.clone(),
                                            target_url: d.get("target_url").and_then(|s| s.as_str()).unwrap_or("").to_string(),
                                            name: d.get("name").and_then(|s| s.as_str()).unwrap_or("").to_string(),
                                            category: d.get("category").and_then(|s| s.as_str()).unwrap_or("Web Server").to_string(),
                                            version: d.get("version").and_then(|s| s.as_str()).map(|s| s.to_string()),
                                            confidence: d.get("confidence").and_then(|s| s.as_str()).unwrap_or("Confirmed").to_string(),
                                            matched_indicators_json: serde_json::to_string(&d.get("matched_indicators").unwrap_or(&serde_json::json!([]))).unwrap_or_else(|_| "[]".to_string()),
                                            created_at: chrono::Utc::now().to_rfc3339(),
                                        };
                                        let _ = db_clone.insert_recon_technology(&tech);
                                    }
                                }
                                "recon_http" => {
                                    if let Some(d) = event.get("data") {
                                        let fp = ReconHttpFingerprint {
                                            id: Uuid::new_v4().to_string(),
                                            recon_scan_id: scan_id_clone.clone(),
                                            asset_id: asset_id_clone.clone(),
                                            target_url: d.get("target_url").and_then(|s| s.as_str()).unwrap_or("").to_string(),
                                            status_code: d.get("status_code").and_then(|s| s.as_i64()).unwrap_or(200),
                                            server_header: d.get("server_header").and_then(|s| s.as_str()).map(|s| s.to_string()),
                                            title: d.get("title").and_then(|s| s.as_str()).map(|s| s.to_string()),
                                            content_type: d.get("content_type").and_then(|s| s.as_str()).map(|s| s.to_string()),
                                            tls_version: d.get("tls_version").and_then(|s| s.as_str()).map(|s| s.to_string()),
                                            tls_cipher: d.get("tls_cipher").and_then(|s| s.as_str()).map(|s| s.to_string()),
                                            tls_cert_subject: d.get("tls_cert_subject").and_then(|s| s.as_str()).map(|s| s.to_string()),
                                            tls_cert_issuer: d.get("tls_cert_issuer").and_then(|s| s.as_str()).map(|s| s.to_string()),
                                            tls_cert_days_left: d.get("tls_cert_days_left").and_then(|s| s.as_i64()),
                                            security_headers_json: serde_json::to_string(&d.get("security_headers").unwrap_or(&serde_json::json!({}))).unwrap_or_else(|_| "{}".to_string()),
                                            cookies_json: serde_json::to_string(&d.get("cookies").unwrap_or(&serde_json::json!([]))).unwrap_or_else(|_| "[]".to_string()),
                                            raw_headers_json: serde_json::to_string(&d.get("raw_headers").unwrap_or(&serde_json::json!({}))).unwrap_or_else(|_| "{}".to_string()),
                                            created_at: chrono::Utc::now().to_rfc3339(),
                                        };
                                        let _ = db_clone.insert_recon_http_fingerprint(&fp);
                                    }
                                }
                                "finding" => {
                                    if let Some(d) = event.get("data") {
                                        let vuln = Vulnerability {
                                            id: Uuid::new_v4().to_string(),
                                            scan_id: scan_id_clone.clone(),
                                            asset_id: asset_id_clone.clone(),
                                            title: d.get("title").and_then(|s| s.as_str()).unwrap_or("Unknown Security Finding").to_string(),
                                            category: d.get("category").and_then(|s| s.as_str()).unwrap_or("Web Security").to_string(),
                                            attack_type: d.get("attack_type").and_then(|s| s.as_str()).unwrap_or("recon").to_string(),
                                            vector: d.get("vector").and_then(|s| s.as_str()).unwrap_or("endpoint").to_string(),
                                            severity: d.get("severity").and_then(|s| s.as_str()).unwrap_or("low").to_string(),
                                            confidence: d.get("confidence").and_then(|c| c.as_i64()).unwrap_or(80),
                                            cve: d.get("cve").and_then(|s| s.as_str()).map(|s| s.to_string()),
                                            cwe: d.get("cwe").and_then(|s| s.as_str()).map(|s| s.to_string()),
                                            owasp: d.get("owasp").and_then(|s| s.as_str()).map(|s| s.to_string()),
                                            cvss_score: d.get("cvss_score").and_then(|c| c.as_f64()),
                                            description: d.get("description").and_then(|s| s.as_str()).map(|s| s.to_string()),
                                            evidence_json: serde_json::to_string(&d.get("evidence").unwrap_or(&serde_json::json!({}))).unwrap_or_else(|_| "{}".to_string()),
                                            remediation: d.get("remediation").and_then(|s| s.as_str()).map(|s| s.to_string()),
                                            verified: d.get("verified").and_then(|v| v.as_bool()).unwrap_or(true),
                                            status: "open".to_string(),
                                            created_at: chrono::Utc::now().to_rfc3339(),
                                            fingerprint: None,
                                            false_positive_reason: None,
                                            remediation_notes: None,
                                            resolved_at: None,
                                            occurrences: 1,
                                        };
                                        let _ = db_clone.insert_vulnerability_with_dedup(&vuln);
                                    }
                                }
                                "completed" => {
                                    let _ = db_clone.update_recon_scan_status(&scan_id_clone, "completed", sub_count, dns_count, tech_count, None);
                                    let log = AuditLog {
                                        id: Uuid::new_v4().to_string(),
                                        timestamp: chrono::Utc::now().to_rfc3339(),
                                        actor: "Operator".to_string(),
                                        action: "RECON_SCAN_COMPLETED".to_string(),
                                        target: Some(asset_id_clone.clone()),
                                        details_json: serde_json::json!({
                                            "subdomains_count": sub_count,
                                            "dns_records_count": dns_count,
                                            "technologies_count": tech_count,
                                        }).to_string(),
                                        status: "SUCCESS".to_string(),
                                    };
                                    let _ = db_clone.insert_audit_log(&log);
                                }
                                "error" => {
                                    let err_msg = event.pointer("/data/message").and_then(|m| m.as_str()).unwrap_or("Unknown error");
                                    let _ = db_clone.update_recon_scan_status(&scan_id_clone, "failed", sub_count, dns_count, tech_count, Some(err_msg));
                                }
                                _ => {}
                            }
                        }
                    }
                }

                let _ = child.wait().await;
                let mut map = proc_map_clone.lock().unwrap();
                map.remove(&scan_id_clone);
            });
        }
        Err(e) => {
            let _ = state.db.update_recon_scan_status(&scan.id, "failed", 0, 0, 0, Some(&e.to_string()));
            return Err(format!("Failed to launch reconnaissance orchestrator: {}", e));
        }
    }

    Ok(scan)
}

#[tauri::command]
pub async fn cancel_recon_scan(scan_id: String, state: State<'_, AppState>) -> Result<(), String> {
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
        .update_recon_scan_status(&scan_id, "cancelled", 0, 0, 0, None)
        .map_err(|e| e.to_string())?;

    let log = AuditLog {
        id: Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        actor: "Operator".to_string(),
        action: "CANCEL_RECON_SCAN".to_string(),
        target: Some(scan_id),
        details_json: "{}".to_string(),
        status: "SUCCESS".to_string(),
    };
    let _ = state.db.insert_audit_log(&log);

    Ok(())
}

#[tauri::command]
pub async fn list_recon_scans(
    asset_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<ReconScan>, String> {
    state.db.list_recon_scans(asset_id.as_deref()).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_recon_summary(
    asset_id: String,
    state: State<'_, AppState>,
) -> Result<ReconSummary, String> {
    state.db.get_recon_summary(&asset_id).map_err(|e| e.to_string())
}
