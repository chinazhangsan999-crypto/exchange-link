CREATE TABLE IF NOT EXISTS analysis_tokens (
  id BIGSERIAL PRIMARY KEY,
  token_hash TEXT UNIQUE NOT NULL,
  scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
  site_keys JSONB NOT NULL DEFAULT '[]'::jsonb,
  expires_at TIMESTAMPTZ NOT NULL,
  use_count INTEGER NOT NULL DEFAULT 0,
  max_uses INTEGER NOT NULL DEFAULT 20,
  revoked_at TIMESTAMPTZ,
  created_by TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_analysis_tokens_active
  ON analysis_tokens(token_hash, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS google_drive_settings (
  id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  folder_id TEXT NOT NULL DEFAULT '',
  file_prefix TEXT NOT NULL DEFAULT 'risk-center',
  backup_range TEXT NOT NULL DEFAULT '7d',
  min_score INTEGER NOT NULL DEFAULT 25,
  site_keys JSONB NOT NULL DEFAULT '[]'::jsonb,
  backup_hour_bjt INTEGER NOT NULL DEFAULT 3,
  credentials_ciphertext TEXT,
  credentials_iv TEXT,
  credentials_tag TEXT,
  service_account_email TEXT NOT NULL DEFAULT '',
  last_backup_at TIMESTAMPTZ,
  last_file_id TEXT NOT NULL DEFAULT '',
  last_error TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO google_drive_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS google_drive_backup_runs (
  id BIGSERIAL PRIMARY KEY,
  trigger_type TEXT NOT NULL,
  success BOOLEAN NOT NULL,
  file_id TEXT NOT NULL DEFAULT '',
  file_name TEXT NOT NULL DEFAULT '',
  item_count INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT 'system',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_google_drive_backup_runs_created
  ON google_drive_backup_runs(created_at DESC);
