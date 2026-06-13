-- Wafer WAF - Database Initialization
-- Run once on fresh system: psql -U wafer -d wafer -f init.sql

BEGIN;

-- 1. Applications
CREATE TABLE IF NOT EXISTS applications (
    app_id           TEXT PRIMARY KEY,
    domain           TEXT NOT NULL UNIQUE,
    config           JSONB NOT NULL DEFAULT '{}',
    under_attack_mode BOOLEAN NOT NULL DEFAULT false,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Security Rules
CREATE TABLE IF NOT EXISTS security_rules (
    rule_id          SERIAL PRIMARY KEY,
    app_id           TEXT REFERENCES applications(app_id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    scope            TEXT NOT NULL DEFAULT 'app',
    rule_group       TEXT NOT NULL DEFAULT '',
    expression_raw   TEXT NOT NULL,
    expression_ast   JSONB,
    action           TEXT NOT NULL DEFAULT 'block',
    skip_modules     TEXT[] NOT NULL DEFAULT '{}',
    priority         INTEGER NOT NULL DEFAULT 0,
    enabled          BOOLEAN NOT NULL DEFAULT true,
    description      TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_security_rules_scope_app
    ON security_rules(scope, app_id, enabled, priority);

-- 3. IP Access Rules
CREATE TABLE IF NOT EXISTS ip_access_rules (
    id               SERIAL PRIMARY KEY,
    app_id           TEXT NOT NULL REFERENCES applications(app_id) ON DELETE CASCADE,
    ip_range         CIDR NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    action           TEXT NOT NULL DEFAULT 'block',
    enabled          BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_access_rules_app_enabled
    ON ip_access_rules(app_id, enabled);

-- 4. Bot Patterns
CREATE TABLE IF NOT EXISTS bot_patterns (
    id               SERIAL PRIMARY KEY,
    pattern_type     TEXT NOT NULL,
    pattern          TEXT NOT NULL,
    score            INTEGER NOT NULL DEFAULT 0,
    verify_ip        BOOLEAN NOT NULL DEFAULT false,
    enabled          BOOLEAN NOT NULL DEFAULT true,
    description      TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. Bot Whitelist
CREATE TABLE IF NOT EXISTS bot_whitelist (
    id               SERIAL PRIMARY KEY,
    ip_range         TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    enabled          BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 6. Bot IP Ranges
CREATE TABLE IF NOT EXISTS bot_ip_ranges (
    id               SERIAL PRIMARY KEY,
    name             TEXT NOT NULL UNIQUE,
    source_type      TEXT NOT NULL DEFAULT 'manual',
    url              TEXT NOT NULL DEFAULT '',
    ip_ranges        JSONB NOT NULL DEFAULT '[]',
    enabled          BOOLEAN NOT NULL DEFAULT true,
    description      TEXT NOT NULL DEFAULT '',
    last_fetched     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 7. Settings (key-value store for configs)
CREATE TABLE IF NOT EXISTS settings (
    key              TEXT PRIMARY KEY,
    value            JSONB NOT NULL DEFAULT '{}',
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 8. Users
CREATE TABLE IF NOT EXISTS users (
    id               SERIAL PRIMARY KEY,
    username         TEXT NOT NULL UNIQUE,
    password_hash    TEXT NOT NULL,
    email            TEXT NOT NULL UNIQUE,
    role             TEXT NOT NULL DEFAULT 'admin',
    enabled          BOOLEAN NOT NULL DEFAULT true,
    last_login       TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 9. Sessions
CREATE TABLE IF NOT EXISTS sessions (
    token            TEXT PRIMARY KEY,
    user_id          INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at       TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- 10. Certificates
CREATE TABLE IF NOT EXISTS certificates (
    cert_id          SERIAL PRIMARY KEY,
    domain           TEXT NOT NULL,
    app_id           TEXT NOT NULL REFERENCES applications(app_id) ON DELETE CASCADE,
    status           TEXT NOT NULL DEFAULT 'pending',
    issuer           TEXT NOT NULL DEFAULT '',
    issued_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    auto_renew       BOOLEAN NOT NULL DEFAULT true,
    last_renew_at    TIMESTAMPTZ,
    last_renew_status TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_certificates_domain ON certificates(domain);
CREATE INDEX IF NOT EXISTS idx_certificates_app_id ON certificates(app_id);

-- 11. Certificate Logs
CREATE TABLE IF NOT EXISTS certificate_logs (
    log_id           SERIAL PRIMARY KEY,
    cert_id          INTEGER NOT NULL REFERENCES certificates(cert_id) ON DELETE CASCADE,
    domain           TEXT NOT NULL,
    action           TEXT NOT NULL,
    status           TEXT NOT NULL,
    message          TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_certificate_logs_cert_id ON certificate_logs(cert_id);

-- 12. IP Reputation Entries
CREATE TABLE IF NOT EXISTS ip_reputation_entries (
    id               SERIAL PRIMARY KEY,
    entry_type       TEXT NOT NULL,
    value            TEXT NOT NULL,
    score            INTEGER NOT NULL DEFAULT 0,
    category         TEXT NOT NULL DEFAULT '',
    description      TEXT NOT NULL DEFAULT '',
    enabled          BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(entry_type, value)
);

-- Migration: add category column if not exists
ALTER TABLE ip_reputation_entries ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT '';

COMMIT;
