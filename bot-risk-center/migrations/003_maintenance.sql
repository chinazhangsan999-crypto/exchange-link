ALTER TABLE alert_settings
  ADD COLUMN IF NOT EXISTS upstream_update_alert_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE alert_settings
  ADD COLUMN IF NOT EXISTS upstream_check_interval_hours INTEGER NOT NULL DEFAULT 6;

CREATE TABLE IF NOT EXISTS maintenance_projects (
  project_key TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  repository TEXT NOT NULL,
  integration_mode TEXT NOT NULL,
  installed_version TEXT NOT NULL DEFAULT '',
  latest_version TEXT NOT NULL DEFAULT '',
  latest_release_at TIMESTAMPTZ,
  release_url TEXT NOT NULL DEFAULT '',
  last_checked_at TIMESTAMPTZ,
  follow_status TEXT NOT NULL DEFAULT 'unknown',
  followed_version TEXT NOT NULL DEFAULT '',
  followed_at TIMESTAMPTZ,
  ignored_version TEXT NOT NULL DEFAULT '',
  alerted_version TEXT NOT NULL DEFAULT '',
  last_error TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO maintenance_projects
  (project_key, name, repository, integration_mode, installed_version)
VALUES
  ('crowdsec', 'CrowdSec', 'crowdsecurity/crowdsec', 'direct', 'docker:latest'),
  ('botd', 'BotD', 'fingerprintjs/BotD', 'signal_source', '2.0.0'),
  ('fingerprintjs', 'FingerprintJS', 'fingerprintjs/fingerprintjs', 'reference', ''),
  ('anubis', 'Anubis', 'TecharoHQ/anubis', 'reference', ''),
  ('coraza', 'Coraza WAF', 'corazawaf/coraza', 'reference', ''),
  ('mcaptcha', 'mCaptcha', 'mCaptcha/mCaptcha', 'reference', ''),
  ('openappsec', 'open-appsec', 'openappsec/openappsec', 'reference', ''),
  ('ja4-nginx', 'JA4 NGINX', 'FoxIO-LLC/ja4-nginx-module', 'reference', ''),
  ('caddy-defender', 'caddy-defender', 'JasonLovesDoggo/caddy-defender', 'reference', ''),
  ('creepjs', 'CreepJS', 'abrahamjuliot/creepjs', 'reference', '')
ON CONFLICT (project_key) DO UPDATE SET
  name = EXCLUDED.name,
  repository = EXCLUDED.repository,
  integration_mode = EXCLUDED.integration_mode;

CREATE TABLE IF NOT EXISTS maintenance_tokens (
  id BIGSERIAL PRIMARY KEY,
  token_hash TEXT UNIQUE NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  use_count INTEGER NOT NULL DEFAULT 0,
  max_uses INTEGER NOT NULL DEFAULT 50,
  revoked_at TIMESTAMPTZ,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_maintenance_tokens_active
  ON maintenance_tokens(token_hash, expires_at) WHERE revoked_at IS NULL;
