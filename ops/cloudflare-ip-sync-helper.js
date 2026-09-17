'use strict';

const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');

function options(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    if (!key?.startsWith('--') || argv[index + 1] === undefined) throw new Error(`参数不完整：${key || '(空)'}`);
    result[key.slice(2)] = argv[index + 1];
  }
  return result;
}

function normalizeCidr(value, expectedFamily) {
  const cidr = String(value || '').trim();
  const separator = cidr.lastIndexOf('/');
  const address = separator > 0 ? cidr.slice(0, separator) : '';
  const prefix = Number(cidr.slice(separator + 1));
  const family = net.isIP(address);
  const maxPrefix = family === 4 ? 32 : family === 6 ? 128 : 0;
  if (family !== expectedFamily || !Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
    throw new Error(`非法 IPv${expectedFamily} CIDR：${cidr || '(空)'}`);
  }
  return `${address.toLowerCase()}/${prefix}`;
}

function parseList(text, family) {
  const values = String(text || '').split(/\r?\n/).map(value => value.trim()).filter(Boolean)
    .map(value => normalizeCidr(value, family));
  const unique = [...new Set(values)];
  if (unique.length < (family === 4 ? 10 : 5)) throw new Error(`IPv${family} 官方清单数量异常：${unique.length}`);
  return unique;
}

function parseFragment(text) {
  const tokens = String(text || '').replace(/#[^\r\n]*/g, ' ').split(/\s+/).filter(Boolean)
    .filter(value => value !== '@cloudflare' && value !== 'remote_ip');
  return {
    ipv4: [...new Set(tokens.filter(value => net.isIP(value.slice(0, value.lastIndexOf('/'))) === 4)
      .map(value => normalizeCidr(value, 4)))],
    ipv6: [...new Set(tokens.filter(value => net.isIP(value.slice(0, value.lastIndexOf('/'))) === 6)
      .map(value => normalizeCidr(value, 6)))]
  };
}

function writeAtomic(file, content) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, content, { mode: 0o644 });
  fs.renameSync(temporary, file);
}

function readPreviousState(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch { return {}; }
}

function prepare(input) {
  const ipv4 = parseList(fs.readFileSync(input.ipv4, 'utf8'), 4);
  const ipv6 = parseList(fs.readFileSync(input.ipv6, 'utf8'), 6);
  const fragment = [
    '# 由 webring-cloudflare-ip-sync.service 管理；不要在运行服务器上手工编辑。',
    `@cloudflare remote_ip ${[...ipv4, ...ipv6].join(' ')}`,
    ''
  ].join('\n');
  writeAtomic(input.output, fragment);
  process.stdout.write(JSON.stringify({ ipv4: ipv4.length, ipv6: ipv6.length }));
}

function writeState(input) {
  const previous = readPreviousState(input.output);
  let official = previous.official || { ipv4: [], ipv6: [] };
  if (input.ipv4 && input.ipv6 && fs.existsSync(input.ipv4) && fs.existsSync(input.ipv6)) {
    official = {
      ipv4: parseList(fs.readFileSync(input.ipv4, 'utf8'), 4),
      ipv6: parseList(fs.readFileSync(input.ipv6, 'utf8'), 6)
    };
  }
  const configured = fs.existsSync(input.configured)
    ? parseFragment(fs.readFileSync(input.configured, 'utf8'))
    : { ipv4: [], ipv6: [] };
  const now = new Date().toISOString();
  const state = {
    schemaVersion: 1,
    status: input.status,
    checkedAt: now,
    appliedAt: input.status === 'synchronized' ? now : (previous.appliedAt || null),
    error: input.error || '',
    official,
    configured
  };
  writeAtomic(input.output, `${JSON.stringify(state, null, 2)}\n`);
}

function main(argv = process.argv.slice(2)) {
  const [command, ...rest] = argv;
  const input = options(rest);
  if (command === 'prepare') return prepare(input);
  if (command === 'state') return writeState(input);
  throw new Error(`未知命令：${command || '(空)'}`);
}

if (require.main === module) {
  try { main(); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { normalizeCidr, parseList, parseFragment, prepare, writeState };
