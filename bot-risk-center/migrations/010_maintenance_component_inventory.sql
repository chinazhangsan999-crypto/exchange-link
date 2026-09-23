ALTER TABLE maintenance_projects
  ADD COLUMN IF NOT EXISTS used_by JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE maintenance_projects
  ADD COLUMN IF NOT EXISTS component_kind TEXT NOT NULL DEFAULT 'library';

ALTER TABLE rule_backup_runs ADD COLUMN IF NOT EXISTS allow_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE rule_backup_runs ADD COLUMN IF NOT EXISTS block_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE rule_backup_runs ADD COLUMN IF NOT EXISTS policy_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE rule_backup_runs ADD COLUMN IF NOT EXISTS revision_count INTEGER NOT NULL DEFAULT 0;

INSERT INTO maintenance_projects
  (project_key, name, repository, integration_mode, installed_version, used_by, component_kind)
VALUES
  ('nodejs', 'Node.js', 'nodejs/node', 'direct', '', '["risk_center","navigation"]', 'runtime'),
  ('express', 'Express', 'expressjs/express', 'direct', '', '["risk_center","navigation"]', 'framework'),
  ('lru-cache', 'lru-cache', 'isaacs/node-lru-cache', 'direct', '', '["risk_center","navigation"]', 'library'),
  ('node-postgres', 'node-postgres', 'brianc/node-postgres', 'direct', '', '["risk_center"]', 'database_client'),
  ('pino', 'Pino', 'pinojs/pino', 'direct', '', '["risk_center"]', 'logging'),
  ('postgresql', 'PostgreSQL', 'postgres/postgres', 'direct', '17-alpine', '["risk_center"]', 'database'),
  ('redis-server', 'Redis Server', 'redis/redis', 'direct', '7-alpine', '["risk_center"]', 'cache'),
  ('caddy', 'Caddy', 'caddyserver/caddy', 'direct', '', '["risk_center","navigation"]', 'proxy'),
  ('cloudflare-workers-sdk', 'Cloudflare Workers SDK / Wrangler', 'cloudflare/workers-sdk', 'direct', '', '["navigation"]', 'edge_runtime'),
  ('cloudflare-workerd', 'Cloudflare workerd', 'cloudflare/workerd', 'direct', 'cloudflare-managed', '["navigation"]', 'edge_runtime'),
  ('cloudflare-docs', 'Cloudflare 官方文档', 'cloudflare/cloudflare-docs', 'reference', '', '["reference"]', 'reference'),
  ('crawler-user-agents', 'crawler-user-agents', 'monperrus/crawler-user-agents', 'reference', '', '["reference"]', 'reference'),
  ('alicloud-dns-sdk', '阿里云 DNS SDK', 'aliyun/alibabacloud-typescript-sdk', 'direct', '4.6.1', '["navigation"]', 'dns_sdk'),
  ('alicloud-openapi-client', '阿里云 OpenAPI Client', 'aliyun/darabonba-openapi', 'direct', '0.4.15', '["navigation"]', 'dns_sdk'),
  ('aws-route53-sdk', 'AWS Route 53 SDK', 'aws/aws-sdk-js-v3', 'direct', '3.1137.0', '["navigation"]', 'dns_sdk'),
  ('archiver', 'Archiver', 'archiverjs/node-archiver', 'direct', '8.0.0', '["navigation"]', 'backup'),
  ('async-mutex', 'async-mutex', 'DirtyHairy/async-mutex', 'direct', '0.5.0', '["navigation"]', 'library'),
  ('axios', 'Axios', 'axios/axios', 'direct', '1.20.0', '["navigation"]', 'http_client'),
  ('bcryptjs', 'bcrypt.js', 'dcodeIO/bcrypt.js', 'direct', '2.4.3', '["navigation"]', 'security'),
  ('cheerio', 'Cheerio', 'cheeriojs/cheerio', 'direct', '1.2.0', '["navigation"]', 'parser'),
  ('connect-sqlite3', 'connect-sqlite3', 'rawberg/connect-sqlite3', 'direct', '0.9.18', '["navigation"]', 'session_store'),
  ('csv-parse', 'CSV Parse', 'adaltas/node-csv', 'direct', '7.0.2', '["navigation"]', 'parser'),
  ('express-session', 'express-session', 'expressjs/session', 'direct', '1.19.0', '["navigation"]', 'session'),
  ('jsonwebtoken', 'jsonwebtoken', 'auth0/node-jsonwebtoken', 'direct', '9.0.3', '["navigation"]', 'security'),
  ('multer', 'Multer', 'expressjs/multer', 'direct', '2.3.0', '["navigation"]', 'upload'),
  ('node-cron', 'node-cron', 'node-cron/node-cron', 'direct', '4.6.0', '["navigation"]', 'scheduler'),
  ('sqlite3', 'SQLite3 for Node.js', 'TryGhost/node-sqlite3', 'direct', '5.1.7', '["navigation"]', 'database'),
  ('svg-captcha', 'SVG Captcha', 'steambap/svg-captcha', 'direct', '1.4.0', '["navigation"]', 'security'),
  ('tencentcloud-dnspod-sdk', '腾讯云 DNSPod SDK', 'tencentcloud/tencentcloud-sdk-nodejs', 'direct', '4.1.266', '["navigation"]', 'dns_sdk'),
  ('tldts', 'tldts', 'remusao/tldts', 'direct', '6.1.86', '["navigation"]', 'domain_parser'),
  ('ua-parser-js', 'UAParser.js', 'faisalman/ua-parser-js', 'direct', '1.0.41', '["navigation"]', 'client_parser')
ON CONFLICT (project_key) DO UPDATE SET
  name = EXCLUDED.name,
  repository = EXCLUDED.repository,
  integration_mode = EXCLUDED.integration_mode,
  used_by = EXCLUDED.used_by,
  component_kind = EXCLUDED.component_kind,
  installed_version = CASE WHEN EXCLUDED.installed_version <> '' THEN EXCLUDED.installed_version ELSE maintenance_projects.installed_version END;

UPDATE maintenance_projects SET used_by='["risk_center"]'::jsonb, component_kind='security'
 WHERE project_key='crowdsec';
UPDATE maintenance_projects SET used_by='["navigation"]'::jsonb, component_kind='detection'
 WHERE project_key IN ('botd','isbot');
UPDATE maintenance_projects SET used_by='["risk_center","navigation"]'::jsonb, component_kind='cache_client'
 WHERE project_key='node-redis';
UPDATE maintenance_projects SET used_by='["reference"]'::jsonb, component_kind='reference'
 WHERE project_key IN ('fingerprintjs','anubis','coraza','mcaptcha','openappsec','ja4-nginx','caddy-defender','creepjs','safeline','bunkerweb','goodbots');
