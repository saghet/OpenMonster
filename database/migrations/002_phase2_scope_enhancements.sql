-- Migration 002: Phase 2 Scope & Audit Session Enhancements

CREATE TABLE IF NOT EXISTS audit_sessions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    auditor_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'completed', 'archived')),
    start_time TEXT NOT NULL DEFAULT (datetime('now')),
    end_time TEXT,
    summary TEXT,
    findings_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scope_exclusions (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    pattern TEXT NOT NULL,
    exclusion_type TEXT NOT NULL CHECK(exclusion_type IN ('path', 'subdomain', 'ip_range', 'param')),
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_asset ON audit_sessions(asset_id);
CREATE INDEX IF NOT EXISTS idx_exclusions_asset ON scope_exclusions(asset_id);

INSERT OR IGNORE INTO schema_migrations (version) VALUES (2);
