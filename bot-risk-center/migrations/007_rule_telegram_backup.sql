CREATE TABLE IF NOT EXISTS rule_backup_settings (
  id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  automatic_on_change BOOLEAN NOT NULL DEFAULT TRUE,
  telegram_chat_id TEXT NOT NULL DEFAULT '',
  telegram_token_ciphertext TEXT,
  telegram_token_iv TEXT,
  telegram_token_tag TEXT,
  backup_hour_bjt SMALLINT NOT NULL DEFAULT 3 CHECK (backup_hour_bjt BETWEEN 0 AND 23),
  part_size_mib SMALLINT NOT NULL DEFAULT 18 CHECK (part_size_mib BETWEEN 1 AND 18),
  last_backup_at TIMESTAMPTZ,
  last_content_sha256 TEXT NOT NULL DEFAULT '',
  last_error TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO rule_backup_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS rule_backup_runs (
  id BIGSERIAL PRIMARY KEY,
  backup_id TEXT NOT NULL UNIQUE,
  trigger_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  rule_count INTEGER NOT NULL DEFAULT 0,
  enabled_count INTEGER NOT NULL DEFAULT 0,
  disabled_count INTEGER NOT NULL DEFAULT 0,
  global_count INTEGER NOT NULL DEFAULT 0,
  site_specific_count INTEGER NOT NULL DEFAULT 0,
  content_sha256 TEXT NOT NULL DEFAULT '',
  parts_total INTEGER NOT NULL DEFAULT 0,
  uploaded_parts JSONB NOT NULL DEFAULT '[]'::jsonb,
  summary_sent BOOLEAN NOT NULL DEFAULT FALSE,
  encrypted_payload BYTEA,
  backup_key_ciphertext TEXT,
  backup_key_iv TEXT,
  backup_key_tag TEXT,
  last_error TEXT NOT NULL DEFAULT '',
  created_by TEXT NOT NULL DEFAULT 'system',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  next_retry_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_rule_backup_runs_status
  ON rule_backup_runs(status, created_at DESC);

