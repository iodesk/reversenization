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
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(pattern_type, pattern)
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

-- Migration: add unique constraints if not exists (fixes deploy-time bloat on re-run)
DO $$ BEGIN
  ALTER TABLE bot_patterns ADD CONSTRAINT bot_patterns_type_pattern_unique UNIQUE (pattern_type, pattern);
EXCEPTION WHEN duplicate_table THEN NULL;
END $$;
DO $$ BEGIN
  ALTER TABLE bot_ip_ranges ADD CONSTRAINT bot_ip_ranges_name_unique UNIQUE (name);
EXCEPTION WHEN duplicate_table THEN NULL;
END $$;

-- ============================================================
-- DEFAULT SETTINGS SEED
-- Insert default configs only if they don't already exist.
-- Values are the single source of truth for fresh installs.
-- ============================================================

-- Rate Limit Config
INSERT INTO settings (key, value, updated_at) VALUES (
  'rate_limit',
  '{
    "basic": {"type":"basic","enabled":true,"duration":30,"count":50,"action":"block","challenge_sec":300},
    "attack": {"type":"attack","enabled":true,"duration":60,"count":40,"action":"block","challenge_sec":300},
    "error": {"type":"error","enabled":false,"duration":60,"count":15,"action":"challenge","challenge_sec":300}
  }',
  NOW()
) ON CONFLICT (key) DO NOTHING;

-- Bot Detection Config
INSERT INTO settings (key, value, updated_at) VALUES (
  'bot_config',
  '{
    "threshold": 20,
    "action": "challenge",
    "challenge_duration": 3700,
    "challenge_wait": 30,
    "rules": {
      "missing_user_agent": 10,
      "short_user_agent": 8,
      "missing_accept": 8,
      "wildcard_accept_browser_ua": 5,
      "missing_accept_language": 8,
      "missing_accept_encoding": 8,
      "missing_sec_fetch": 15,
      "incomplete_sec_fetch": 8,
      "no_browser_indicators": 8,
      "chromium_missing_sec_ch_ua": 15,
      "chromium_missing_sec_fetch": 15,
      "firefox_has_sec_ch_ua": 8,
      "no_gzip_or_br": 3,
      "geo_lang_mismatch": 8,
      "repeat_no_cookie": 10,
      "burst_rate": 8,
      "regular_interval": 6,
      "unknown_browser_bot": 27,
      "headless_browser": 25
    },
    "challenge": {
      "title": "Verifying your connection...",
      "description": "Please wait while we verify your request. This process is automatic.",
      "footer": "Protected by Wafer WAF",
      "custom_html": "",
      "show_ray_id": true
    },
    "trust_levels": {
      "level0_max": 0.40,
      "level1_max": 0.60,
      "level2_max": 0.80,
      "reductions": [0, -5, -10, -15]
    }
  }',
  NOW()
) ON CONFLICT (key) DO NOTHING;

-- WAF Config
INSERT INTO settings (key, value, updated_at) VALUES (
  'waf_config',
  '{
    "paranoia_level": 1,
    "anomaly_threshold": 5,
    "outbound_anomaly_threshold": 4,
    "allowed_methods": ["GET","HEAD","POST","OPTIONS"],
    "disabled_rules": [920274, 942421],
    "custom_rules": ""
  }',
  NOW()
) ON CONFLICT (key) DO NOTHING;

-- Protocol Anomaly Config
INSERT INTO settings (key, value, updated_at) VALUES (
  'protocol_anomaly_config',
  '{
    "rules": {
      "http2_connection_header": 8,
      "content_type_no_body": 5,
      "accept_path_mismatch": 5,
      "sec_fetch_dest_mismatch": 6,
      "upgrade_non_navigate": 4,
      "te_cl_conflict": 10,
      "multiple_host_headers": 10,
      "malformed_challenge_cookie": 8,
      "future_cookie_timestamp": 8,
      "excessive_cookies_no_referer": 5,
      "ja4_old_tls_browser_ua": 15,
      "browser_ua_http10": 15,
      "browser_ua_ja4_empty": 4,
      "bot_ua_browser_ja4": 15,
      "browser_ua_simple_ja4": 15
    }
  }',
  NOW()
) ON CONFLICT (key) DO NOTHING;

-- Scoring Config
INSERT INTO settings (key, value, updated_at) VALUES (
  'scoring_config',
  '{
    "thresholds": {"block": 70, "challenge": 35},
    "weights": {
      "ip_reputation": {"enabled": true, "max_score": 30, "multiplier": 1.0},
      "bot_detection": {"enabled": true, "max_score": 35, "multiplier": 1.0},
      "waf_anomaly": {"enabled": true, "max_score": 40, "multiplier": 1.5},
      "protocol_anomaly": {"enabled": true, "max_score": 35, "multiplier": 1.0}
    },
    "trust": {
      "verified_cookie": -2,
      "trusted_history": -4,
      "stable_session": -2,
      "good_bot": -5
    }
  }',
  NOW()
) ON CONFLICT (key) DO NOTHING;

-- IP Reputation Config
INSERT INTO settings (key, value, updated_at) VALUES (
  'ip_reputation_config',
  '{
    "maxmind_dc_score": 15,
    "maxmind_asn_score": 15,
    "spamhaus_ip_score": 50,
    "spamhaus_asn_score": 50
  }',
  NOW()
) ON CONFLICT (key) DO NOTHING;

-- ============================================================
-- DEFAULT BOT PATTERNS SEED
-- Good bot patterns for verified crawlers
-- ============================================================

INSERT INTO bot_patterns (pattern_type, pattern, score, verify_ip, enabled, description) VALUES
  ('good_bot', 'googlebot', 0, true, true, 'Google crawler'),
  ('good_bot', 'gsa-crawler', 0, true, true, 'Google Search Appliance'),
  ('good_bot', 'msnbot', 0, true, true, 'Microsoft MSN bot'),
  ('good_bot', 'msnbot-media', 0, true, true, 'Microsoft MSN media bot'),
  ('good_bot', 'slurp', 0, true, true, 'Yahoo Slurp crawler'),
  ('good_bot', 'yahoo', 0, true, true, 'Yahoo crawler'),
  ('good_bot', 'Googlebot', 0, true, true, 'Google crawler (case-sensitive)'),
  ('good_bot', 'AdsBot-Google', 0, true, true, 'Google Ads bot'),
  ('good_bot', 'Applebot', 0, true, true, 'Apple crawler'),
  ('good_bot', 'DoCoMo', 0, true, true, 'DoCoMo mobile crawler'),
  ('good_bot', 'Feedfetcher-Google', 0, true, true, 'Google Feed Fetcher'),
  ('good_bot', 'Google-HTTP-Java-Client', 0, true, true, 'Google HTTP Java Client'),
  ('good_bot', 'Googlebot-Image', 0, true, true, 'Google Image crawler'),
  ('good_bot', 'Googlebot-Mobile', 0, true, true, 'Google Mobile crawler'),
  ('good_bot', 'Googlebot-News', 0, true, true, 'Google News crawler'),
  ('good_bot', 'Googlebot-Video', 0, true, true, 'Google Video crawler'),
  ('good_bot', 'Googlebot/Test', 0, true, true, 'Google test crawler'),
  ('good_bot', 'Gravityscan', 0, true, true, 'Gravityscan security scanner'),
  ('good_bot', 'Jakarta Commons', 0, true, true, 'Jakarta Commons HTTP client'),
  ('good_bot', 'Kraken/0.1', 0, true, true, 'Kraken crawler'),
  ('good_bot', 'LinkedInBot', 0, true, true, 'LinkedIn crawler'),
  ('good_bot', 'Mediapartners-Google', 0, true, true, 'Google AdSense crawler'),
  ('good_bot', 'SAMSUNG', 0, true, true, 'Samsung browser bot'),
  ('good_bot', 'Slackbot', 0, true, true, 'Slack link preview bot'),
  ('good_bot', 'Slackbot-LinkExpanding', 0, true, true, 'Slack link expanding bot'),
  ('good_bot', 'TwitterBot', 0, true, true, 'Twitter/X crawler'),
  ('good_bot', 'Wordpress', 0, true, true, 'WordPress pingback/trackback'),
  ('good_bot', 'adidxbot', 0, true, true, 'Microsoft adidx bot'),
  ('good_bot', 'bing', 0, true, true, 'Bing crawler'),
  ('good_bot', 'bingbot', 0, true, true, 'Bing crawler'),
  ('good_bot', 'bingpreview', 0, true, true, 'Bing preview bot'),
  ('good_bot', 'developers.facebook.com', 0, true, true, 'Facebook developer bot'),
  ('good_bot', 'duckduckgo', 0, true, true, 'DuckDuckGo crawler'),
  ('good_bot', 'facebookexternalhit', 0, true, true, 'Facebook link preview bot'),
  ('good_bot', 'facebookplatform', 0, true, true, 'Facebook platform bot')
ON CONFLICT (pattern_type, pattern) DO NOTHING;

-- ============================================================
-- DEFAULT BOT IP RANGES SEED
-- Verified bot provider IP range sources
-- ============================================================

INSERT INTO bot_ip_ranges (name, source_type, url, ip_ranges, enabled, description) VALUES
  ('Bingbot', 'json_url', 'https://www.bing.com/toolbox/bingbot.json', '[]', true, 'Official Microsoft Bing crawler IP ranges'),
  ('Googlebot', 'json_url', 'https://developers.google.com/static/search/apis/ipranges/googlebot.json', '[]', true, 'Official Googlebot IP ranges')
ON CONFLICT (name) DO NOTHING;

COMMIT;
