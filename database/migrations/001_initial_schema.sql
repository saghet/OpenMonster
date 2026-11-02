-- Migration 001: Initial Schema for SECMASTER-OpenMonster

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    target TEXT NOT NULL UNIQUE,
    asset_type TEXT NOT NULL CHECK(asset_type IN ('domain', 'ip', 'url', 'cidr')),
    authorized INTEGER NOT NULL DEFAULT 0,
    authorized_by TEXT,
    authorized_at TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scopes (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    allowed_paths TEXT DEFAULT '[]',
    excluded_paths TEXT DEFAULT '[]',
    max_rate INTEGER DEFAULT 20,
    passive_only INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    scan_mode TEXT NOT NULL CHECK(scan_mode IN ('passive', 'active', 'custom')),
    status TEXT NOT NULL CHECK(status IN ('pending', 'running', 'paused', 'completed', 'cancelled', 'failed')),
    progress REAL NOT NULL DEFAULT 0.0,
    started_at TEXT,
    completed_at TEXT,
    error_message TEXT,
    config_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    vector TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence INTEGER NOT NULL CHECK(confidence BETWEEN 0 AND 100),
    cve TEXT,
    cwe TEXT,
    owasp TEXT,
    cvss_score REAL,
    description TEXT,
    evidence_json TEXT NOT NULL DEFAULT '{}',
    remediation TEXT,
    verified INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'remediated', 'false_positive')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    details_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'SUCCESS'
);

CREATE TABLE IF NOT EXISTS plugins (
    id TEXT PRIMARY KEY,
    plugin_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    version TEXT NOT NULL,
    author TEXT,
    category TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    manifest_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target);
CREATE INDEX IF NOT EXISTS idx_scans_asset ON scans(asset_id);
CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (1);
