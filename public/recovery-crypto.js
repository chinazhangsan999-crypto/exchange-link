/** 恢复清单验签、TXT 重组与 IndexedDB 存储。无第三方依赖。 */
(() => {
  const DB_NAME = 'navigation_recovery_v1';
  const STORE_NAME = 'state';
  const STATE_KEY = 'verified-recovery-state';

  function stableStringify(value) {
    if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
    if (value && typeof value === 'object') {
      return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stableStringify(value[key])}`).join(',')}}`;
    }
    return JSON.stringify(value);
  }

  function fromBase64Url(value) {
    const normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, char => char.charCodeAt(0));
  }

  async function verifyEnvelope(envelope, keys) {
    if (!envelope || typeof envelope !== 'object' || !envelope.signature || !envelope.keyId) return false;
    const trusted = (Array.isArray(keys) ? keys : []).find(item => item.keyId === envelope.keyId && item.spki);
    if (!trusted) return false;
    const unsigned = { ...envelope }; delete unsigned.signature;
    try {
      const key = await crypto.subtle.importKey('spki', fromBase64Url(trusted.spki), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      return crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' }, key, fromBase64Url(envelope.signature),
        new TextEncoder().encode(stableStringify(unsigned))
      );
    } catch { return false; }
  }

  function parseTxtValue(input) {
    let text = String(input || '').trim();
    if (text.startsWith('"') && text.endsWith('"')) text = text.slice(1, -1);
    return text.replace(/"\s*"/g, '').replace(/\\"/g, '"');
  }

  function assembleTxt(values) {
    const sets = new Map();
    for (const raw of values || []) {
      const match = /^r1;set=([^;]+);part=(\d+)\/(\d+);data=([A-Za-z0-9_-]+)$/.exec(parseTxtValue(raw));
      if (!match) continue;
      const [, set, indexRaw, totalRaw, data] = match;
      const index = Number(indexRaw), total = Number(totalRaw);
      if (index < 1 || total < 1 || total > 50 || index > total) continue;
      if (!sets.has(set)) sets.set(set, { total, parts: new Map() });
      const group = sets.get(set);
      if (group.total !== total) continue;
      group.parts.set(index, data);
    }
    const envelopes = [];
    for (const [set, group] of sets) {
      if (group.parts.size !== group.total) continue;
      try {
        const encoded = Array.from({ length: group.total }, (_, index) => group.parts.get(index + 1)).join('');
        const bytes = fromBase64Url(encoded);
        envelopes.push({ set, envelope: JSON.parse(new TextDecoder().decode(bytes)) });
      } catch { /* 丢弃损坏分片 */ }
    }
    return envelopes;
  }

  function validateEnvelopeShape(envelope, expectedProject, highestGeneration = 0) {
    if (!envelope || ![1, 2].includes(Number(envelope.schema))) return { valid: false, reason: '清单格式版本不受支持' };
    if (!envelope.project || (expectedProject && envelope.project !== expectedProject)) return { valid: false, reason: '恢复项目编号不匹配' };
    if (!Number.isInteger(Number(envelope.generation)) || Number(envelope.generation) < Number(highestGeneration || 0)) return { valid: false, reason: '检测到旧版本清单，已阻止回滚' };
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isFinite(Number(envelope.expiresAt)) || Number(envelope.expiresAt) <= now) return { valid: false, reason: '恢复清单已经过期' };
    if (!Array.isArray(envelope.domains) || envelope.domains.length < 1 || envelope.domains.length > 10) return { valid: false, reason: '候选线路数量不合法' };
    for (const item of envelope.domains) {
      try {
        const url = new URL(item.url);
        if (url.protocol !== 'https:' || url.username || url.password || url.port || url.pathname !== '/' || url.search || url.hash) throw new Error();
      } catch { return { valid: false, reason: '清单包含不安全的线路地址' }; }
    }
    return { valid: true };
  }

  function openDatabase() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE_NAME)) request.result.createObjectStore(STORE_NAME);
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error('无法打开恢复数据存储'));
    });
  }

  async function readState() {
    const database = await openDatabase();
    try {
      return await new Promise((resolve, reject) => {
        const request = database.transaction(STORE_NAME, 'readonly').objectStore(STORE_NAME).get(STATE_KEY);
        request.onsuccess = () => resolve(request.result || null);
        request.onerror = () => reject(request.error);
      });
    } finally { database.close(); }
  }

  async function writeState(value) {
    const database = await openDatabase();
    try {
      await new Promise((resolve, reject) => {
        const transaction = database.transaction(STORE_NAME, 'readwrite');
        transaction.objectStore(STORE_NAME).put(value, STATE_KEY);
        transaction.oncomplete = resolve;
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(transaction.error || new Error('恢复数据保存失败'));
      });
    } finally { database.close(); }
  }

  async function acceptManifest(manifest, existing = null) {
    if (!manifest?.enabled || !manifest.envelope) return existing;
    const bootstrapKeys = existing?.trustedKeys?.length ? existing.trustedKeys : manifest.publicKeys;
    const shape = validateEnvelopeShape(manifest.envelope, existing?.project || '', existing?.highestGeneration || 0);
    if (!shape.valid || !await verifyEnvelope(manifest.envelope, bootstrapKeys)) throw new Error(shape.reason || '恢复清单签名无效');
    const signedKeys = Array.isArray(manifest.envelope.trustedKeys) ? manifest.envelope.trustedKeys : [];
    const state = {
      enabled: true,
      project: manifest.envelope.project,
      signedEnvelope: manifest.envelope,
      highestGeneration: Number(manifest.envelope.generation),
      trustedKeys: signedKeys.length ? signedKeys : bootstrapKeys,
      bootstrapNames: Array.isArray(manifest.envelope.bootstrapNames) ? manifest.envelope.bootstrapNames : (manifest.bootstrapNames || []),
      lookupRoutes: Array.isArray(manifest.envelope.lookupRoutes) ? manifest.envelope.lookupRoutes : (manifest.lookupRoutes || []),
      lastVerifiedAt: new Date().toISOString(),
      componentVersion: manifest.componentVersion || 'recovery-v1'
    };
    await writeState(state);
    return state;
  }

  window.RecoveryCrypto = { stableStringify, verifyEnvelope, assembleTxt, validateEnvelopeShape, readState, writeState, acceptManifest };
})();
