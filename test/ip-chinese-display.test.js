'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.resolve(__dirname, '..');
const read = relativePath => fs.readFileSync(path.join(root, relativePath), 'utf8');

test('IP displays prefer a Chinese mapping and fall back to the original value', () => {
  for (const relativePath of ['public/admin/traffic-logs.js', 'public/admin/monitor.js']) {
    const source = read(relativePath);
    assert.match(source, /const localized = \(translated, original\)/);
    assert.match(source, /\\u3400-\\u9fff/);
    assert.match(source, /localized\(item\.ip_asn_org_zh, asnLabels\[asn\] \|\| item\.ip_asn_org\)/);
    assert.match(source, /localized\(item\.ip_isp_zh, item\.ip_isp\)/);
    assert.doesNotMatch(source, /Cloudflare（边缘网络）|Amazon AWS/);
  }
});

test('IP profile cache stores translated fields separately from raw evidence', () => {
  const model = read('src/models/IpProfileModel.js');
  for (const field of [
    'isp_zh', 'special_purpose_zh', 'crawler_operator_zh',
    'crawler_type_zh', 'private_relay_region_zh'
  ]) {
    assert.match(model, new RegExp(`\\b${field}\\b`));
  }
});

test('navigation IP views do not render confidence labels', () => {
  for (const relativePath of [
    'public/admin/traffic-logs.js', 'public/admin/monitor.js',
    'public/admin/traffic-cell.css', 'public/admin/monitor.css'
  ]) {
    const source = read(relativePath);
    assert.doesNotMatch(source, /低可信|自动判断|高可信|置信度未知|ip-confidence/);
  }
  assert.doesNotMatch(read('public/admin/monitor.js'), /置信度：/);
});
