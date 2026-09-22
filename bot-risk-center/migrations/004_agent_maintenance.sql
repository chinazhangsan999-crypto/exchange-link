ALTER TABLE api_clients
  ADD COLUMN IF NOT EXISTS scopes JSONB NOT NULL DEFAULT '["risk.events.write","risk.decisions.read","risk.policy.read","maintenance.inventory.write","maintenance.advisory.read","maintenance.test-result.write"]'::jsonb;

CREATE TABLE IF NOT EXISTS site_runtime_inventory (
  site_key TEXT PRIMARY KEY REFERENCES sites(site_key) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES api_clients(client_id) ON DELETE CASCADE,
  schema_version TEXT NOT NULL,
  app_version TEXT NOT NULL DEFAULT '',
  git_commit TEXT NOT NULL DEFAULT '',
  node_version TEXT NOT NULL DEFAULT '',
  protocol_version TEXT NOT NULL DEFAULT '',
  components JSONB NOT NULL DEFAULT '[]'::jsonb,
  capabilities JSONB NOT NULL DEFAULT '[]'::jsonb,
  deployed_at TIMESTAMPTZ,
  reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_site_runtime_inventory_reported
  ON site_runtime_inventory(reported_at DESC);

CREATE TABLE IF NOT EXISTS maintenance_advisories (
  id BIGSERIAL PRIMARY KEY,
  site_key TEXT NOT NULL REFERENCES sites(site_key) ON DELETE CASCADE,
  project_key TEXT NOT NULL REFERENCES maintenance_projects(project_key) ON DELETE CASCADE,
  installed_version TEXT NOT NULL DEFAULT '',
  latest_version TEXT NOT NULL DEFAULT '',
  impact_level TEXT NOT NULL DEFAULT 'review',
  affected_features JSONB NOT NULL DEFAULT '[]'::jsonb,
  recommendation TEXT NOT NULL DEFAULT '',
  required_tests JSONB NOT NULL DEFAULT '[]'::jsonb,
  rollout_strategy JSONB NOT NULL DEFAULT '[]'::jsonb,
  status TEXT NOT NULL DEFAULT 'awaiting_assessment',
  generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  reviewed_at TIMESTAMPTZ,
  UNIQUE(site_key, project_key, latest_version)
);
CREATE INDEX IF NOT EXISTS idx_maintenance_advisories_site
  ON maintenance_advisories(site_key, generated_at DESC);

CREATE TABLE IF NOT EXISTS maintenance_test_results (
  id BIGSERIAL PRIMARY KEY,
  site_key TEXT NOT NULL REFERENCES sites(site_key) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES api_clients(client_id) ON DELETE CASCADE,
  project_key TEXT NOT NULL,
  target_version TEXT NOT NULL,
  test_commit TEXT NOT NULL DEFAULT '',
  automated JSONB NOT NULL DEFAULT '{}'::jsonb,
  browsers JSONB NOT NULL DEFAULT '{}'::jsonb,
  false_positive_delta NUMERIC,
  recommendation TEXT NOT NULL DEFAULT '',
  passed BOOLEAN NOT NULL DEFAULT FALSE,
  tested_at TIMESTAMPTZ NOT NULL,
  reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_maintenance_test_results_site
  ON maintenance_test_results(site_key, tested_at DESC);
