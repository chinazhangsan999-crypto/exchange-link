CREATE TABLE IF NOT EXISTS github_api_settings (
  id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  token_ciphertext TEXT,
  token_iv TEXT,
  token_tag TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO github_api_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;
