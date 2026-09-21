CREATE TABLE IF NOT EXISTS sites (
  id BIGSERIAL PRIMARY KEY,
  site_key TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  policy_id BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS api_clients (
  id BIGSERIAL PRIMARY KEY,
  client_id TEXT UNIQUE NOT NULL,
  site_key TEXT NOT NULL REFERENCES sites(site_key),
  secret_hash TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_api_clients_site ON api_clients(site_key);

CREATE TABLE IF NOT EXISTS policies (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL,
  version TEXT UNIQUE NOT NULL,
  configuration JSONB NOT NULL,
  active BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS risk_events (
  id BIGSERIAL PRIMARY KEY,
  event_id UUID UNIQUE NOT NULL,
  site_key TEXT NOT NULL,
  visitor_hash TEXT NOT NULL,
  event_type TEXT NOT NULL,
  occurred_at TIMESTAMPTZ NOT NULL,
  risk_delta INTEGER NOT NULL DEFAULT 0,
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_events_visitor_time
  ON risk_events(site_key, visitor_hash, occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_events_created
  ON risk_events(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_events_site_created
  ON risk_events(site_key, created_at DESC);

CREATE TABLE IF NOT EXISTS risk_decisions (
  id BIGSERIAL PRIMARY KEY,
  sequence BIGSERIAL UNIQUE NOT NULL,
  site_key TEXT NOT NULL,
  subject_type TEXT NOT NULL DEFAULT 'visitor',
  subject_hash TEXT NOT NULL,
  score INTEGER NOT NULL,
  decision TEXT NOT NULL,
  reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
  policy_version TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_risk_decisions_delta
  ON risk_decisions(site_key, sequence);
CREATE INDEX IF NOT EXISTS idx_risk_decisions_subject
  ON risk_decisions(site_key, subject_type, subject_hash, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_decisions_site_created
  ON risk_decisions(site_key, created_at DESC);

CREATE TABLE IF NOT EXISTS allowlists (
  id BIGSERIAL PRIMARY KEY,
  site_key TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_hash TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(site_key, subject_type, subject_hash)
);

CREATE TABLE IF NOT EXISTS blocklists (
  id BIGSERIAL PRIMARY KEY,
  site_key TEXT NOT NULL,
  subject_type TEXT NOT NULL,
  subject_hash TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(site_key, subject_type, subject_hash)
);

CREATE TABLE IF NOT EXISTS challenge_audits (
  id BIGSERIAL PRIMARY KEY,
  site_key TEXT NOT NULL,
  visitor_hash TEXT NOT NULL,
  challenge_type TEXT NOT NULL,
  succeeded BOOLEAN NOT NULL,
  elapsed_ms INTEGER,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS admin_audits (
  id BIGSERIAL PRIMARY KEY,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
