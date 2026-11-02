pub mod commands;
pub mod db;

use commands::AppState;
use db::DatabaseManager;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::Manager;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            let app_dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| PathBuf::from("./data"));
            
            if !app_dir.exists() {
                let _ = fs::create_dir_all(&app_dir);
            }

            let db_path = app_dir.join("sec_master.db");
            let db_manager = DatabaseManager::new(db_path)
                .unwrap_or_else(|_| DatabaseManager::new_in_memory().expect("Failed in-memory DB"));

            app.manage(AppState {
                db: Arc::new(db_manager),
            });

            log::info!("SECMASTER database initialized successfully.");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_dashboard_stats,
            commands::get_assets,
            commands::create_asset,
            commands::authorize_asset,
            commands::get_vulnerabilities,
            commands::get_audit_logs,
            commands::get_scans,
            commands::create_scan,
            commands::cancel_scan
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
