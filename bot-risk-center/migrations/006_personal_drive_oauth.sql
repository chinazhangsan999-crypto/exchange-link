ALTER TABLE google_drive_settings
  ADD COLUMN IF NOT EXISTS auth_mode TEXT NOT NULL DEFAULT 'service_account',
  ADD COLUMN IF NOT EXISTS oauth_client_id TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS oauth_client_secret_ciphertext TEXT,
  ADD COLUMN IF NOT EXISTS oauth_client_secret_iv TEXT,
  ADD COLUMN IF NOT EXISTS oauth_client_secret_tag TEXT,
  ADD COLUMN IF NOT EXISTS oauth_refresh_token_ciphertext TEXT,
  ADD COLUMN IF NOT EXISTS oauth_refresh_token_iv TEXT,
  ADD COLUMN IF NOT EXISTS oauth_refresh_token_tag TEXT,
  ADD COLUMN IF NOT EXISTS oauth_connected_email TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS oauth_connected_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS oauth_folder_id TEXT NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS oauth_folder_name TEXT NOT NULL DEFAULT '风险中心备份';

CREATE TABLE IF NOT EXISTS google_drive_oauth_states (
  state_hash TEXT PRIMARY KEY,
  verifier_ciphertext TEXT NOT NULL,
  verifier_iv TEXT NOT NULL,
  verifier_tag TEXT NOT NULL,
  created_by TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_google_drive_oauth_states_expires
  ON google_drive_oauth_states(expires_at);
