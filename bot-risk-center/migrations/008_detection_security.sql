CREATE TABLE IF NOT EXISTS admin_credentials (
  id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  credential_version INTEGER NOT NULL DEFAULT 1,
  password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_sessions (
  id BIGSERIAL PRIMARY KEY,
  session_hash TEXT UNIQUE NOT NULL,
  username TEXT NOT NULL,
  csrf_token TEXT NOT NULL,
  source_ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  credential_version INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  revoke_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_active
  ON admin_sessions(expires_at DESC, revoked_at, username);

ALTER TABLE admin_audits ADD COLUMN IF NOT EXISTS source_ip TEXT NOT NULL DEFAULT '';
ALTER TABLE admin_audits ADD COLUMN IF NOT EXISTS user_agent TEXT NOT NULL DEFAULT '';

ALTER TABLE signal_rules ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'enforce';
ALTER TABLE signal_rules ADD COLUMN IF NOT EXISTS revision INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS signal_rule_revisions (
  id BIGSERIAL PRIMARY KEY,
  rule_id BIGINT,
  operation TEXT NOT NULL,
  snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_signal_rule_revisions_rule
  ON signal_rule_revisions(rule_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_challenge_audits_created
  ON challenge_audits(created_at DESC, site_key, succeeded);

INSERT INTO policies (name,version,configuration,active)
SELECT '基础策略','baseline-1','{"thresholds":{"observe":25,"silentChallenge":50,"strongChallenge":75,"deny":90}}'::jsonb,
       NOT EXISTS (SELECT 1 FROM policies WHERE active=TRUE)
ON CONFLICT (version) DO NOTHING;

INSERT INTO maintenance_projects
  (project_key, name, repository, integration_mode, installed_version)
VALUES
  ('safeline', 'SafeLine', 'chaitin/SafeLine', 'reference', ''),
  ('bunkerweb', 'BunkerWeb', 'bunkerity/bunkerweb', 'reference', '')
ON CONFLICT (project_key) DO UPDATE SET
  name = EXCLUDED.name,
  repository = EXCLUDED.repository,
  integration_mode = EXCLUDED.integration_mode;
