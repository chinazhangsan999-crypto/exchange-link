CREATE TABLE IF NOT EXISTS alert_settings (
  id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  enabled BOOLEAN NOT NULL DEFAULT FALSE,
  telegram_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  telegram_chat_id TEXT NOT NULL DEFAULT '',
  telegram_token_ciphertext TEXT,
  telegram_token_iv TEXT,
  telegram_token_tag TEXT,
  bark_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  bark_server_url TEXT NOT NULL DEFAULT 'https://api.day.app',
  bark_group TEXT NOT NULL DEFAULT '风险中心',
  bark_key_ciphertext TEXT,
  bark_key_iv TEXT,
  bark_key_tag TEXT,
  denied_count_5m INTEGER NOT NULL DEFAULT 10,
  suspicious_count_10m INTEGER NOT NULL DEFAULT 20,
  challenge_failure_count_10m INTEGER NOT NULL DEFAULT 10,
  challenge_failure_ratio NUMERIC(5,4) NOT NULL DEFAULT 0.4,
  replay_count_5m INTEGER NOT NULL DEFAULT 3,
  cross_site_count_10m INTEGER NOT NULL DEFAULT 3,
  cooldown_minutes INTEGER NOT NULL DEFAULT 30,
  hourly_digest_enabled BOOLEAN NOT NULL DEFAULT FALSE,
  daily_digest_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  telegram_interval_ms INTEGER NOT NULL DEFAULT 1200,
  bark_interval_ms INTEGER NOT NULL DEFAULT 2000,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO alert_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS alert_states (
  alert_key TEXT PRIMARY KEY,
  kind TEXT NOT NULL,
  site_key TEXT,
  severity TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  current_value NUMERIC NOT NULL DEFAULT 0,
  last_notified_value NUMERIC NOT NULL DEFAULT 0,
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_notified_at TIMESTAMPTZ,
  resolved_at TIMESTAMPTZ,
  details JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_alert_states_active_seen
  ON alert_states(active, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS alert_delivery_logs (
  id BIGSERIAL PRIMARY KEY,
  alert_key TEXT NOT NULL,
  provider TEXT NOT NULL,
  success BOOLEAN NOT NULL,
  status_code INTEGER,
  error_message TEXT NOT NULL DEFAULT '',
  payload_size INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alert_delivery_created
  ON alert_delivery_logs(created_at DESC);
