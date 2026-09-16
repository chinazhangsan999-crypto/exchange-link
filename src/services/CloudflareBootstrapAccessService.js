'use strict';

const fs = require('fs');
const path = require('path');
const CredentialStore = require('./IntegrationCredentialStore');

const STATE_FILE = path.resolve(process.env.CLOUDFLARE_BOOTSTRAP_STATE_FILE
  || path.join(path.dirname(CredentialStore.paths.cloudflareApiEdge), 'cloudflare-bootstrap-access.json'));
const TOKEN_FILE = path.resolve(process.env.CLOUDFLARE_BOOTSTRAP_TOKEN_FILE
  || path.join(path.dirname(CredentialStore.paths.cloudflareApiEdge), 'cloudflare-bootstrap-token.txt'));

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

async function writeAtomic(file, content) {
  await fs.promises.mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${process.pid}.${Date.now()}.tmp`;
  await fs.promises.writeFile(temporary, content, { encoding: 'utf8', mode: 0o600 });
  await fs.promises.chmod(temporary, 0o600);
  await fs.promises.rename(temporary, file);
}

async function removeTokenFile() {
  try { await fs.promises.unlink(TOKEN_FILE); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
}

async function initialize() {
  // 新版首次建站流程不再生成或读取明文初始化码；启动时清除旧版遗留文件。
  await removeTokenFile();
  const current = readJson(STATE_FILE);
  if (current?.consumed_at) {
    return { available: false, reason: 'consumed' };
  }
  return { available: true };
}

async function publicStatus() {
  const state = await initialize();
  return { available: state.available };
}

async function consume() {
  const current = readJson(STATE_FILE) || {};
  await writeAtomic(STATE_FILE, `${JSON.stringify({
    ...current,
    token_hash: null,
    expires_at: null,
    consumed_at: new Date().toISOString()
  }, null, 2)}\n`);
  await removeTokenFile();
}

module.exports = {
  STATE_FILE,
  TOKEN_FILE,
  initialize,
  publicStatus,
  consume
};
