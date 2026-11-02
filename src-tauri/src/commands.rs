use crate::db::{Asset, AuditLog, DashboardStats, DatabaseManager, Scan, Vulnerability};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;
use uuid::Uuid;

pub struct AppState {
    pub db: Arc<DatabaseManager>,
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
    pub config_json: Option<String>,
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

    // Audit log
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
    state: State<'_, AppState>,
) -> Result<Scan, String> {
    // Scope authorization check
    let assets = state.db.list_assets().map_err(|e| e.to_string())?;
    let target_asset = assets.iter().find(|a| a.id == req.asset_id);

    match target_asset {
        Some(asset) => {
            if req.scan_mode == "active" && !asset.authorized {
                return Err("Authorization required: Target asset is not explicitly authorized for active testing.".to_string());
            }
        }
        None => return Err("Asset not found.".to_string()),
    }

    let now = chrono::Utc::now().to_rfc3339();
    let scan = Scan {
        id: Uuid::new_v4().to_string(),
        name: req.name,
        asset_id: req.asset_id,
        scan_mode: req.scan_mode,
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
        timestamp: now,
        actor: "Operator".to_string(),
        action: "START_SCAN".to_string(),
        target: Some(scan.asset_id.clone()),
        details_json: format!("{{\"scan_id\": \"{}\", \"mode\": \"{}\"}}", scan.id, scan.scan_mode),
        status: "SUCCESS".to_string(),
    };
    let _ = state.db.insert_audit_log(&log);

    Ok(scan)
}

#[tauri::command]
pub async fn cancel_scan(scan_id: String, state: State<'_, AppState>) -> Result<(), String> {
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
