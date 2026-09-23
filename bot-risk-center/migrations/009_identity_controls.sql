ALTER TABLE allowlists ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE allowlists ADD COLUMN IF NOT EXISTS hit_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE allowlists ADD COLUMN IF NOT EXISTS last_hit_at TIMESTAMPTZ;
ALTER TABLE allowlists ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

ALTER TABLE blocklists ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE blocklists ADD COLUMN IF NOT EXISTS hit_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE blocklists ADD COLUMN IF NOT EXISTS last_hit_at TIMESTAMPTZ;
ALTER TABLE blocklists ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

INSERT INTO maintenance_projects
  (project_key, name, repository, integration_mode, installed_version)
VALUES
  ('isbot', 'isbot', 'omrilotan/isbot', 'direct', '5.2.2'),
  ('node-redis', 'node-redis', 'redis/node-redis', 'direct', '5.8.2'),
  ('goodbots', 'goodbots', 'eywu/goodbots', 'reference', '')
ON CONFLICT (project_key) DO UPDATE SET
  name = EXCLUDED.name,
  repository = EXCLUDED.repository,
  integration_mode = EXCLUDED.integration_mode,
  installed_version = CASE WHEN EXCLUDED.integration_mode='direct' THEN EXCLUDED.installed_version ELSE maintenance_projects.installed_version END;
