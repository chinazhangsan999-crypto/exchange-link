/** 故障时才运行：本地签名清单 -> 动态图片测活 -> 多 DoH -> 手动前往。 */
(() => {
  const RESOLVERS = [
    { id: 'dnspod', label: 'DNSPod', url: 'https://doh.pub/dns-query' },
    { id: 'alidns', label: 'AliDNS', url: 'https://dns.alidns.com/resolve' },
    { id: 'cloudflare', label: 'Cloudflare', url: 'https://cloudflare-dns.com/dns-query' },
    { id: 'google', label: 'Google', url: 'https://dns.google/resolve' }
  ];
  const statusElement = document.querySelector('#recovery-status');
  const progressElement = document.querySelector('#recovery-progress');
  const logElement = document.querySelector('#recovery-log');
  let running = false;
  let savedState = null;

  function status(text) { statusElement.textContent = text; }
  function log(text) { const item = document.createElement('li'); item.textContent = text; logElement.append(item); }
  function finishProgress() { progressElement.classList.add('done'); }

  function probeOnce(origin, timeoutMs = 3000) {
    return new Promise(resolve => {
      const image = new Image(); let settled = false;
      const finish = value => { if (settled) return; settled = true; clearTimeout(timer); image.onload = null; image.onerror = null; resolve(value); };
      const timer = setTimeout(() => { image.src = ''; finish(false); }, timeoutMs);
      image.onload = () => finish(image.naturalWidth === 1 && image.naturalHeight === 1);
      image.onerror = () => finish(false);
      image.src = `${origin}/.well-known/route-health.gif?recovery=${crypto.randomUUID()}&t=${Date.now()}`;
    });
  }

  async function probe(origin) {
    if (await probeOnce(origin)) return true;
    return probeOnce(origin);
  }

  async function firstHealthy(domains) {
    const queue = [...domains].sort((a, b) => Number(b.priority || 0) - Number(a.priority || 0));
    let cursor = 0, winner = null;
    async function worker() {
      while (!winner && cursor < queue.length) {
        const item = queue[cursor++];
        log(`检测 ${item.title || item.url}`);
        if (await probe(item.url)) { winner = item; return; }
      }
    }
    await Promise.all(Array.from({ length: Math.min(3, queue.length) }, worker));
    return winner;
  }

  async function queryDoh(resolver, name) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4000);
    try {
      const url = new URL(resolver.url); url.searchParams.set('name', name); url.searchParams.set('type', 'TXT');
      const response = await fetch(url, { headers: { Accept: 'application/dns-json' }, signal: controller.signal, cache: 'no-store' });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const payload = await response.json();
      const values = (payload.Answer || []).filter(item => Number(item.type) === 16).map(item => item.data);
      return { resolver, name, envelopes: window.RecoveryCrypto.assembleTxt(values) };
    } catch (error) {
      log(`${resolver.label} 查询 ${name} 失败：${error.name === 'AbortError' ? '超时' : error.message}`);
      return { resolver, name, envelopes: [] };
    } finally { clearTimeout(timer); }
  }

  async function newestVerifiedFromDoh(state) {
    const names = Array.isArray(state.bootstrapNames) ? state.bootstrapNames.slice(0, 4) : [];
    if (!names.length) { log('本地清单未保存 Bootstrap DNS 名称'); return null; }
    status('已保存线路均不可用，正在从多个 DNS 解析源查询最新地址…');
    const results = await Promise.all(names.flatMap(name => RESOLVERS.map(resolver => queryDoh(resolver, name))));
    const candidates = results.flatMap(item => item.envelopes.map(value => ({ ...value, resolver: item.resolver.label, name: item.name })));
    const accepted = [];
    for (const candidate of candidates) {
      const shape = window.RecoveryCrypto.validateEnvelopeShape(candidate.envelope, state.project, state.highestGeneration || 0);
      if (!shape.valid) { log(`${candidate.resolver} 返回的清单被拒绝：${shape.reason}`); continue; }
      if (!await window.RecoveryCrypto.verifyEnvelope(candidate.envelope, state.trustedKeys)) { log(`${candidate.resolver} 返回的清单签名无效`); continue; }
      accepted.push(candidate);
    }
    accepted.sort((a, b) => Number(b.envelope.generation) - Number(a.envelope.generation));
    if (!accepted.length) return null;
    const selected = accepted[0];
    const confirmations = accepted.filter(item => Number(item.envelope.generation) === Number(selected.envelope.generation)).length;
    log(`已验签 generation ${selected.envelope.generation}，${confirmations} 个解析结果确认`);
    const nextState = {
      ...state,
      enabled: true,
      project: selected.envelope.project,
      signedEnvelope: selected.envelope,
      highestGeneration: Number(selected.envelope.generation),
      trustedKeys: Array.isArray(selected.envelope.trustedKeys) && selected.envelope.trustedKeys.length ? selected.envelope.trustedKeys : state.trustedKeys,
      bootstrapNames: selected.envelope.bootstrapNames || state.bootstrapNames,
      lastVerifiedAt: new Date().toISOString()
    };
    await window.RecoveryCrypto.writeState(nextState);
    savedState = nextState;
    return selected.envelope;
  }

  function fallbackValue(envelope, key) { return envelope?.fallback && typeof envelope.fallback[key] === 'string' ? envelope.fallback[key] : ''; }
  function showFound(item, envelope) {
    finishProgress(); status('已找到通过签名和动态线路检测的最新地址。');
    document.querySelector('#recovery-found-title').textContent = item.title || '可用线路';
    document.querySelector('#recovery-found-url').textContent = item.url;
    const link = document.querySelector('#recovery-go'); link.href = item.url;
    document.querySelector('#recovery-found-message').textContent = envelope.foundMessage || '该地址已经过恢复清单签名和动态线路检测。';
    document.querySelector('#recovery-found').hidden = false;
    document.querySelector('#recovery-fallback').hidden = true;
  }

  function contactRow(label, value, type = 'copy') {
    if (!value) return null;
    const row = document.createElement('div'); row.className = 'contact-row';
    const content = document.createElement('div'); const caption = document.createElement('span'); caption.textContent = label; const strong = document.createElement('strong'); strong.textContent = value; content.append(caption, strong);
    const action = document.createElement(type === 'link' ? 'a' : 'button'); action.className = 'copy-action';
    if (type === 'link') { action.href = value; action.target = '_blank'; action.rel = 'noopener'; action.textContent = '打开'; }
    else { action.type = 'button'; action.textContent = '复制'; action.addEventListener('click', async () => { try { await navigator.clipboard.writeText(value); action.textContent = '已复制'; } catch { action.textContent = '复制失败'; } }); }
    row.append(content, action); return row;
  }

  function showFallback(envelope, message) {
    finishProgress(); status(message || '暂时没有找到可用地址。');
    document.querySelector('#recovery-found').hidden = true;
    document.querySelector('#recovery-fallback').hidden = false;
    document.querySelector('#recovery-fallback-message').textContent = fallbackValue(envelope, 'message') || '请稍后重新检查，或通过以下恢复专用渠道获取最新地址。';
    const list = document.querySelector('#recovery-contact-list'); list.replaceChildren();
    [
      contactRow('恢复专用邮箱', fallbackValue(envelope, 'email')),
      contactRow('恢复专用发布页', fallbackValue(envelope, 'publishUrl'), 'link'),
      contactRow('恢复专用联系方式', fallbackValue(envelope, 'contact'))
    ].filter(Boolean).forEach(item => list.append(item));
    if (!list.children.length) { const empty = document.createElement('p'); empty.className = 'result-note'; empty.textContent = '当前浏览器没有保存恢复专用联系方式。'; list.append(empty); }
  }

  async function loadPreviewState() {
    if (!new URLSearchParams(location.search).has('preview')) return null;
    try {
      const response = await fetch('/api/recovery/manifest', { cache: 'no-store' }); const payload = await response.json();
      if (payload?.code === 200 && payload.data?.enabled) return window.RecoveryCrypto.acceptManifest(payload.data, await window.RecoveryCrypto.readState().catch(() => null));
    } catch (error) { log(`预览数据加载失败：${error.message}`); }
    return null;
  }

  async function run() {
    if (running) return; running = true;
    progressElement.classList.remove('done'); logElement.replaceChildren(); document.querySelector('#recovery-found').hidden = true; document.querySelector('#recovery-fallback').hidden = true;
    try {
      savedState = await loadPreviewState() || await window.RecoveryCrypto.readState();
      if (!savedState?.signedEnvelope) return showFallback(null, '此浏览器尚未保存恢复清单。');
      if (savedState.enabled === false) return showFallback(null, '恢复系统当前已由管理员停用。');
      const local = savedState.signedEnvelope;
      const shape = window.RecoveryCrypto.validateEnvelopeShape(local, savedState.project, 0);
      const signed = shape.valid && await window.RecoveryCrypto.verifyEnvelope(local, savedState.trustedKeys);
      if (!signed) log(`本地清单不可用于线路检测：${shape.reason || '签名无效'}`);
      if (navigator.onLine === false) return showFallback(local, '当前设备处于离线状态，请恢复网络后重试。');
      if (signed) {
        status('正在检查已经保存的可用线路…');
        const localWinner = await firstHealthy(local.domains);
        if (localWinner) return showFound(localWinner, local);
      }
      const remote = await newestVerifiedFromDoh(savedState);
      if (remote) {
        status('已获取新的签名清单，正在检测候选线路…');
        const remoteWinner = await firstHealthy(remote.domains);
        if (remoteWinner) return showFound(remoteWinner, remote);
      }
      showFallback(remote || local, '所有已验证线路暂时都无法连接。');
    } catch (error) {
      log(`恢复流程异常：${error.message}`);
      showFallback(savedState?.signedEnvelope, '恢复检查没有完成，请稍后重新尝试。');
    } finally { running = false; }
  }

  document.querySelector('#recovery-retry').addEventListener('click', run);
  void run();
})();
