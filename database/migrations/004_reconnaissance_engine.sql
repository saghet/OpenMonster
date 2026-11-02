-- Migration 004: Reconnaissance & Intelligence Engine Schema
-- Tracks passive discovery, DNS records, HTTP/TLS fingerprints, and technology correlation

CREATE TABLE IF NOT EXISTS recon_scans (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    mode TEXT NOT NULL DEFAULT 'all' CHECK(mode IN ('all', 'passive', 'dns', 'http', 'tech')),
    target_domain TEXT NOT NULL,
    subdomains_count INTEGER NOT NULL DEFAULT 0,
    dns_records_count INTEGER NOT NULL DEFAULT 0,
    technologies_count INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at TEXT,
    error_message TEXT,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS recon_subdomains (
    id TEXT PRIMARY KEY,
    recon_scan_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    ip_addresses TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 80 CHECK(confidence BETWEEN 0 AND 100),
    is_live INTEGER NOT NULL DEFAULT 0,
    http_status INTEGER,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(recon_scan_id) REFERENCES recon_scans(id) ON DELETE CASCADE,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS recon_dns_records (
    id TEXT PRIMARY KEY,
    recon_scan_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    record_type TEXT NOT NULL,
    record_value TEXT NOT NULL,
    ttl INTEGER,
    is_takeover_risk INTEGER NOT NULL DEFAULT 0,
    takeover_reason TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(recon_scan_id) REFERENCES recon_scans(id) ON DELETE CASCADE,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS recon_technologies (
    id TEXT PRIMARY KEY,
    recon_scan_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    target_url TEXT NOT NULL,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    version TEXT,
    confidence TEXT NOT NULL DEFAULT 'Confirmed' CHECK(confidence IN ('Confirmed', 'Probable', 'Suspected')),
    matched_indicators_json TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(recon_scan_id) REFERENCES recon_scans(id) ON DELETE CASCADE,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS recon_http_fingerprints (
    id TEXT PRIMARY KEY,
    recon_scan_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    target_url TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    server_header TEXT,
    title TEXT,
    content_type TEXT,
    tls_version TEXT,
    tls_cipher TEXT,
    tls_cert_subject TEXT,
    tls_cert_issuer TEXT,
    tls_cert_days_left INTEGER,
    security_headers_json TEXT NOT NULL DEFAULT '{}',
    cookies_json TEXT NOT NULL DEFAULT '[]',
    raw_headers_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY(recon_scan_id) REFERENCES recon_scans(id) ON DELETE CASCADE,
    FOREIGN KEY(asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

-- Indices for fast correlation and historical lookups
CREATE INDEX IF NOT EXISTS idx_recon_subdomains_asset ON recon_subdomains(asset_id);
CREATE INDEX IF NOT EXISTS idx_recon_subdomains_scan ON recon_subdomains(recon_scan_id);
CREATE INDEX IF NOT EXISTS idx_recon_subdomains_name ON recon_subdomains(subdomain);

CREATE INDEX IF NOT EXISTS idx_recon_dns_asset ON recon_dns_records(asset_id);
CREATE INDEX IF NOT EXISTS idx_recon_dns_domain ON recon_dns_records(domain);
CREATE INDEX IF NOT EXISTS idx_recon_dns_type ON recon_dns_records(record_type);

CREATE INDEX IF NOT EXISTS idx_recon_tech_asset ON recon_technologies(asset_id);
CREATE INDEX IF NOT EXISTS idx_recon_tech_name ON recon_technologies(name);

CREATE INDEX IF NOT EXISTS idx_recon_http_asset ON recon_http_fingerprints(asset_id);
