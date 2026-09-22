'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const state = { csrf: '', sites: [], suspectPage: 1, suspectTotal: 0, currentSuspect: null, activeTab: 'connections' };
  const signalLabels = Object.freeze({
    cloudflare_confirmed_bot: 'Cloudflare 已确认机器人', verified_search_bot: '已验证搜索引擎蜘蛛',
    known_ai_crawler: '已知 AI 爬虫', token_replay: '读取凭证重放', sequential_detail_scan: '连续枚举详情页',
    high_concurrency: '异常并发读取', botd_detected: '浏览器自动化特征', webdriver_detected: 'WebDriver 特征',
    browser_automation_confirmed: '多项自动化证据确认', script_user_agent: '脚本型 User-Agent',
    trapdoor_hit: '访问隐藏探针', repeated_trapdoor: '重复访问隐藏探针', challenge_failed: '浏览器验证失败',
    missing_fetch_metadata: '缺少浏览器请求元数据', valid_browser_access: '持有有效浏览器通行证',
    valid_read_token: '持有有效读取凭证', challenge_passed: '已通过风险验证',
    browser_challenge_passed: '已通过浏览器挑战', normal_dwell: '正常页面停留', outbound_interaction: '存在真实出站交互'
  });
  const signalExplanations = Object.freeze({
    cloudflare_confirmed_bot: 'Cloudflare 已明确将该请求识别为自动程序。这是边缘平台给出的强证据，普通真人浏览器通常不会命中。',
    verified_search_bot: '请求来源与已验证的搜索引擎蜘蛛一致。它可能是正规蜘蛛，但仍属于自动抓取程序，不是普通访客。',
    known_ai_crawler: 'User-Agent 或风险情报命中了已知 AI 抓取工具特征。这类客户端通常以程序方式批量读取页面。',
    token_replay: '同一短效读取凭证被重复或异常使用。正常页面会按流程获取和消费凭证，重复使用更像脚本复制请求。',
    sequential_detail_scan: '短时间内连续访问多个详情编号，呈现按 ID 枚举页面的规律；真人浏览通常不会如此连续、机械地遍历。',
    high_concurrency: '同一访客同时发起的核心数据读取超过正常页面并发上限。人类操作通常有点击间隔，高并发更像批量抓取。',
    botd_detected: '浏览器环境暴露了无头浏览器或自动化框架特征。该信号较强，但仍建议结合其他证据复核。',
    webdriver_detected: '浏览器报告了 WebDriver 自动控制标识，常见于 Selenium、Playwright 等自动化工具。',
    browser_automation_confirmed: '多项浏览器自动化证据同时成立，已形成相互印证；误判概率显著低于单一环境信号。',
    script_user_agent: '请求标识命中 curl、python、wget、Go HTTP 等脚本客户端特征，和普通 Chrome、Safari 浏览器不一致。',
    trapdoor_hit: '访问了正常界面不可见、真人无法通过常规操作进入的探针路径，通常由自动遍历链接的程序触发。',
    repeated_trapdoor: '同一访客重复访问隐藏探针，说明并非偶然请求，自动扫描或遍历的可能性很高。',
    challenge_failed: '客户端未能通过浏览器静默验证，可能不具备完整浏览器能力，也可能禁用了必要脚本；应结合其他信号判断。',
    missing_fetch_metadata: '核心读取请求缺少现代浏览器通常自动携带的 Fetch Metadata。代理、旧浏览器或隐私工具也可能移除它，单独出现不足以判定机器人。',
    valid_browser_access: '客户端持有有效浏览器通行状态，这是降低风险的正向证据。',
    valid_read_token: '请求携带了有效短效读取凭证，说明经过了正常页面读取流程，是正向证据。',
    challenge_passed: '客户端已经通过风险验证，是降低风险的正向证据。',
    browser_challenge_passed: '客户端通过了浏览器挑战，是降低风险的正向证据。',
    normal_dwell: '页面停留时间符合真人阅读节奏，是降低风险的正向证据。',
    outbound_interaction: '访客产生了真实出站点击，表明存在正常浏览意图，是降低风险的正向证据。'
  });
  const evidenceLabels = Object.freeze({
    path: '请求路径', requestPath: '请求路径', url: '请求地址', userAgent: 'User-Agent', ua: 'User-Agent',
    concurrency: '并发数', count: '次数', detailCount: '详情数量', detailId: '详情编号', ids: '访问编号', windowMs: '统计窗口',
    reason: '检测依据', source: '信号来源', botName: '程序名称', botKind: '自动化类型', method: '请求方法', test: '测试标记',
    elapsedMs: '验证耗时(ms)', difficultyBits: '验证难度', webdriver: 'WebDriver', botDetected: 'BotD 结果',
    secFetchSite: 'Sec-Fetch-Site', secFetchMode: 'Sec-Fetch-Mode', secFetchDest: 'Sec-Fetch-Dest'
  });
  let toastTimer;

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    const method = String(options.method || 'GET').toUpperCase();
    if (options.body) headers.set('Content-Type', 'application/json');
    if (state.csrf && !['GET', 'HEAD'].includes(method)) headers.set('X-CSRF-Token', state.csrf);
    const response = await fetch(path, { ...options, headers, credentials: 'same-origin', cache: 'no-store' });
    const result = await response.json().catch(() => null);
    if (!response.ok) throw new Error(result?.message || `请求失败 (${response.status})`);
    return result;
  }
  function toast(message) { clearTimeout(toastTimer); $('status-message').textContent = message; $('status-message').hidden = false; toastTimer = setTimeout(() => { $('status-message').hidden = true; }, 4500); }
  function node(tag, text = '', className = '') { const element = document.createElement(tag); element.textContent = text; if (className) element.className = className; return element; }
  function formatDate(value) { if (!value) return '尚无记录'; const date = new Date(value); return Number.isNaN(date.getTime()) ? '未知' : new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(date); }
  function emptyRow(body, text, columns) { body.replaceChildren(); const tr = node('tr'); const td = node('td', text, 'empty-cell'); td.colSpan = columns; tr.append(td); body.append(tr); }
  function chip(text, on = true) { return node('span', text, `status-chip ${on ? 'on' : 'off'}`); }
  function actionButton(text, action, extra = '', id = '') { const button = node('button', text, `button small ${extra || 'secondary'}`); button.type = 'button'; button.dataset.action = action; if (id) button.dataset.id = id; return button; }
  function signalLabel(signal) { return signalLabels[signal] || signal; }
  function signalExplanation(signal) { return signalExplanations[signal] || '系统记录到了该风险信号，但暂未配置专用解释；请结合原始证据、命中次数和时间分布人工判断。'; }
  function evidenceSummary(evidence = {}) {
    if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) return '';
    const entries = Object.entries(evidence)
      .filter(([key, value]) => evidenceLabels[key] && value !== null && value !== '' && !/token|secret|password|cookie|authorization/i.test(key))
      .slice(0, 5)
      .map(([key, value]) => {
        const rendered = Array.isArray(value) ? value.join(', ') : (typeof value === 'object' ? JSON.stringify(value) : String(value));
        return `${evidenceLabels[key]}：${rendered.slice(0, 180)}`;
      });
    return entries.join('；');
  }
  function copySignalButton(signal) {
    const button = node('button', '复制信号', 'copy-signal');
    button.type = 'button';
    button.dataset.copySignal = signal;
    button.title = `复制 ${signal}`;
    return button;
  }
  function buildReasonDetail(item) {
    const box = node('article', '', 'reason-detail');
    const head = node('div', '', 'reason-detail-head');
    head.append(node('strong', signalLabel(item.signal)), node('code', item.signal), copySignalButton(item.signal));
    const score = Number(item.scoreImpact) || 0;
    box.append(
      head,
      node('p', signalExplanation(item.signal), 'reason-why'),
      node('p', `命中 ${Number(item.count) || 0} 次 · 单次分值影响 ${score > 0 ? '+' : ''}${score} · 首次 ${formatDate(item.firstSeen)} · 最近 ${formatDate(item.lastSeen)}`, 'reason-meta')
    );
    const evidence = evidenceSummary(item.latestEvidence);
    if (evidence) box.append(node('p', `最近证据：${evidence}`, 'reason-evidence'));
    return box;
  }
  function reasonLabel(reason) {
    const value = String(reason || '');
    if (value.startsWith('manual_override:')) return `人工处置：${value.slice(16) || '管理员指定'}`;
    if (value.startsWith('manual_rule:')) return `命中人工规则 #${value.slice(12)}`;
    return signalLabel(value);
  }
  function renderSignalChips(signals = []) {
    const box = node('div', '', 'signal-list');
    for (const item of signals.slice(0, 4)) {
      const score = Number(item.scoreImpact) || 0;
      const chipBox = node('span', '', `signal-chip ${score < 0 ? 'positive' : ''}`);
      chipBox.append(node('span', `${signalLabel(item.signal)} ×${item.count}${score ? ` (${score > 0 ? '+' : ''}${score})` : ''}`), node('code', item.signal), copySignalButton(item.signal));
      box.append(chipBox);
    }
    if (signals.length > 4) box.append(node('span', `另有 ${signals.length - 4} 项`, 'signal-chip'));
    return box;
  }

  function setAuthenticated(value) { $('login-view').hidden = value; $('dashboard-view').hidden = !value; }
  function fillSiteSelects() {
    for (const select of [$('suspect-site-filter'), $('rule-site')]) {
      const current = select.value;
      const first = select.id === 'suspect-site-filter' ? node('option', '全部站点') : node('option', '请选择站点');
      first.value = '';
      select.replaceChildren(first, ...state.sites.map(site => { const option = node('option', site.name || site.siteKey); option.value = site.siteKey; return option; }));
      select.value = current;
    }
  }

  function renderSites() {
    const body = $('sites-body'); body.replaceChildren();
    if (!state.sites.length) return emptyRow(body, '尚无对接站点，请点击“新增对接”。', 6);
    for (const site of state.sites) {
      const tr = node('tr'); tr.dataset.siteKey = site.siteKey;
      const siteCell = node('td'); siteCell.append(node('strong', site.name || site.siteKey, 'site-name'), node('span', site.siteKey, 'site-key'));
      const primary = site.urls?.find(item => item.isPrimary) || site.urls?.[0];
      if (primary) { const link = node('a', primary.url, 'site-url'); link.href = primary.url; link.target = '_blank'; link.rel = 'noopener'; siteCell.append(link); }
      const extras = (site.urls || []).filter(item => item.url !== primary?.url);
      if (extras.length) { const details = node('details', '', 'more-urls'); details.append(node('summary', `另有 ${extras.length} 个网址`)); for (const item of extras) { const link = node('a', item.url); link.href = item.url; link.target = '_blank'; link.rel = 'noopener'; details.append(link); } siteCell.append(details); }

      const clientCell = node('td');
      for (const client of site.clients || []) { const line = node('div', '', 'status-line'); line.append(node('span', client.clientId, 'client-chip'), node('small', `${client.transport === 'https' ? 'HTTPS 外网' : '内网'} · ${client.enabled ? '线路开启' : '线路关闭'}`)); clientCell.append(line); }
      if (!site.clients?.length) clientCell.textContent = '未登记';
      const activity = node('td'); activity.append(node('div', `事件 ${site.events24h || 0}`, 'numeric'), node('small', `决策 ${site.decisions24h || 0} · ${formatDate(site.lastUsedAt)}`));
      const collectCell = node('td'); collectCell.append(chip(site.collectionEnabled ? '采集中' : '已暂停', site.collectionEnabled));
      const enforceCell = node('td'); enforceCell.append(chip(site.enforcementEnabled ? site.enforcementMode : '不执行', site.enforcementEnabled));
      const actions = node('td', '', 'action-column'); const group = node('div', '', 'inline-actions');
      group.append(actionButton('编辑站点', 'edit-site'), actionButton('新增线路', 'add-client'));
      for (const client of site.clients || []) {
        const label = client.transport === 'https' ? 'HTTPS' : '内网';
        group.append(
          actionButton(`${client.enabled ? '关闭' : '开启'}${label}`, 'toggle-client', client.enabled ? 'danger' : 'success', client.clientId),
          actionButton(`轮换${label}密钥`, 'rotate-client', 'secondary', client.clientId)
        );
      }
      group.append(actionButton(site.enabled ? '关闭总开关' : '开启总开关', 'toggle-site', site.enabled ? 'danger' : 'success'));
      actions.append(group); tr.append(siteCell, clientCell, activity, collectCell, enforceCell, actions); body.append(tr);
    }
  }

  async function loadOverviewAndSites() {
    const [overview, sites] = await Promise.all([request('/admin/api/overview'), request('/admin/api/sites')]);
    state.sites = sites.data || [];
    $('metric-sites').textContent = overview.data.sites; $('metric-enabled').textContent = overview.data.enabledSites; $('metric-events').textContent = overview.data.events24h; $('metric-decisions').textContent = overview.data.decisions24h;
    renderSites(); fillSiteSelects();
  }

  function openIntegration(site = null, newClient = false) {
    $('integration-title').textContent = newClient ? '新增独立数据线路' : (site ? '编辑导航站对接' : '新增导航站对接');
    $('integration-name').value = site?.name || ''; $('integration-site-key').value = site?.siteKey || ''; $('integration-site-key').readOnly = Boolean(site);
    const client = newClient ? null : site?.clients?.[0]; $('integration-client-id').value = client?.clientId || ''; $('integration-client-id').readOnly = Boolean(client);
    $('integration-transport').value = client?.transport || (newClient ? 'https' : 'internal'); $('integration-urls').value = (site?.urls || []).sort((a, b) => Number(b.isPrimary) - Number(a.isPrimary)).map(item => item.url).join('\n');
    $('integration-collection').checked = site?.collectionEnabled ?? true; $('integration-enforcement').checked = site?.enforcementEnabled ?? false; $('integration-mode').value = site?.enforcementMode || 'observe';
    $('integration-dialog').showModal();
  }
  function showSecret(data) { $('secret-client').value = data.clientId; $('secret-endpoint').value = `${data.endpointUrl}/v1`; $('secret-value').value = data.secret; $('secret-dialog').showModal(); }

  async function loadSuspects() {
    const query = new URLSearchParams({ page: String(state.suspectPage), limit: '50', minScore: $('suspect-score-filter').value }); if ($('suspect-site-filter').value) query.set('siteKey', $('suspect-site-filter').value);
    const [summary, suspects] = await Promise.all([request(`/admin/api/risk/summary?${query}`), request(`/admin/api/risk/suspects?${query}`)]);
    $('risk-visitors').textContent = summary.data.visitors24h; $('risk-suspects').textContent = summary.data.suspects24h; $('risk-challenged').textContent = summary.data.challenged24h; $('risk-blocked').textContent = summary.data.blocked24h;
    $('signal-summary').replaceChildren(...(summary.data.signals || []).map(item => node('span', `${item.signal} · ${item.visitors} 人 / ${item.count} 次`, 'signal-chip')));
    const body = $('suspects-body'); body.replaceChildren(); const data = suspects.data; state.suspectTotal = data.total;
    if (!data.items.length) emptyRow(body, '当前筛选条件下没有疑似访客。', 8);
    for (const item of data.items) { const tr = node('tr'); tr.dataset.siteKey = item.siteKey; tr.dataset.visitorHash = item.visitorHash; const who = node('td'); who.append(node('strong', item.siteName), node('span', `${item.visitorHash.slice(0, 12)}…`, 'site-key')); const decision = node('td'); decision.append(chip(item.manualAction ? `人工：${item.manualAction}` : item.decision, !['deny', 'strong_challenge'].includes(item.manualAction || item.decision))); const signalItems = (item.signals || []).length ? item.signals : (item.reasons || []).filter(reason => !String(reason).startsWith('manual_')).map(signal => ({ signal, count: 1, scoreImpact: 0, firstSeen: item.firstSeen, lastSeen: item.lastSeen, latestEvidence: {} })); const reasons = node('td', '', 'reason-cell'); for (const signal of signalItems.slice(0, 3)) { const reason = node('div', '', 'reason-summary'); reason.append(node('strong', signalLabel(signal.signal)), node('span', signalExplanation(signal.signal)), node('small', `命中 ${signal.count} 次 · 最近 ${formatDate(signal.lastSeen)}`)); const evidence = evidenceSummary(signal.latestEvidence); if (evidence) reason.append(node('small', `最近证据：${evidence}`, 'reason-evidence-inline')); reasons.append(reason); } if (!signalItems.length) reasons.append(node('span', (item.reasons || []).map(reasonLabel).join('；') || '暂无可解释信号')); const signals = node('td'); signals.append(renderSignalChips(signalItems)); const action = node('td', '', 'action-column'); action.append(actionButton('查看证据 / 处置', 'view-suspect')); tr.append(who, node('td', String(item.score), 'numeric'), decision, reasons, signals, node('td', String(item.eventCount), 'numeric'), node('td', formatDate(item.lastSeen)), action); body.append(tr); }
    const pages = Math.max(1, Math.ceil(data.total / data.limit)); $('suspect-page').textContent = `第 ${data.page} / ${pages} 页 · 共 ${data.total} 人`; $('suspect-prev').disabled = data.page <= 1; $('suspect-next').disabled = data.page >= pages;
  }

  async function openSuspect(siteKey, visitorHash) {
    const result = await request(`/admin/api/risk/suspects/${encodeURIComponent(siteKey)}/${visitorHash}`); const data = result.data; state.currentSuspect = { siteKey, visitorHash, signals: data.signals || [] };
    $('suspect-title').textContent = `${data.siteName} · ${visitorHash.slice(0, 12)}…`;
    const primarySignal = (data.signals || [])[0];
    $('suspect-overview').replaceChildren(...[['风险分', data.score], ['当前结论', data.decision], ['主要判断依据', primarySignal ? `${signalLabel(primarySignal.signal)}：${signalExplanation(primarySignal.signal)}` : ((data.reasons || []).map(reasonLabel).join('；') || '无')]].map(([label, value]) => { const box = node('article'); box.append(node('span', label), node('strong', String(value))); return box; }));
    $('suspect-signal-details').replaceChildren(...(data.signals || []).map(buildReasonDetail));
    $('suspect-events').replaceChildren(...data.events.map(event => { const item = node('article', '', 'event-item'); item.append(node('code', event.eventType), node('span', ` · ${formatDate(event.occurredAt)}`), node('pre', JSON.stringify(event.evidence || {}, null, 2))); return item; }));
    const ruleSignal = $('suspect-rule-signal');
    ruleSignal.replaceChildren(...(data.signals || []).map(signal => { const option = node('option', `${signalLabel(signal.signal)} · ${signal.signal}`); option.value = signal.signal; return option; }));
    $('suspect-reason').value = ''; $('suspect-permanent').checked = false; $('suspect-duration').disabled = false;
    $('suspect-apply-all-sites').checked = false; $('suspect-apply-all-sites').disabled = !(data.signals || []).length; ruleSignal.disabled = true;
    $('suspect-dialog').showModal();
  }

  async function loadRules() { const result = await request('/admin/api/risk/rules'); const body = $('rules-body'); body.replaceChildren(); if (!result.data.length) return emptyRow(body, '尚未配置人工信号规则。', 6); for (const rule of result.data) { const tr = node('tr'); tr.dataset.ruleId = rule.id; const actions = node('td', '', 'action-column'); const group = node('div', '', 'inline-actions'); group.append(actionButton(rule.enabled ? '停用' : '启用', 'toggle-rule', rule.enabled ? 'danger' : 'success'), actionButton('删除', 'delete-rule', 'danger')); actions.append(group); tr.append(node('td', rule.scope === 'all' ? '任意站点' : rule.siteName), node('td', `${signalLabel(rule.signal)}\n${rule.signal}`), node('td', rule.action), node('td', rule.permanent ? '永久' : `${rule.durationMinutes} 分钟`), node('td', rule.enabled ? '已启用' : '已停用'), actions); body.append(tr); } }
  async function loadAudits() { const result = await request('/admin/api/audits?limit=100'); const body = $('audits-body'); body.replaceChildren(); if (!result.data.length) return emptyRow(body, '尚无管理操作记录。', 5); for (const item of result.data) { const tr = node('tr'); tr.append(node('td', formatDate(item.createdAt)), node('td', item.action), node('td', item.target), node('td', item.actor), node('td', JSON.stringify(item.details))); body.append(tr); } }
  function numberValue(id) { return Number($(id).value); }
  function renderAlertActivity(data) {
    const activityBody = $('alert-activity-body'); activityBody.replaceChildren();
    if (!data.active.length) emptyRow(activityBody, '尚未产生聚合告警。', 6);
    for (const item of data.active) {
      const tr = node('tr');
      tr.append(
        node('td', formatDate(item.lastSeenAt)),
        node('td', item.details?.siteName || item.siteKey || '所有站点'),
        node('td', item.kind),
        node('td', item.severity === 'critical' ? '紧急' : '高风险'),
        node('td', item.active ? '持续中' : '已恢复'),
        node('td', formatDate(item.lastNotifiedAt))
      );
      activityBody.append(tr);
    }
    const deliveryBody = $('alert-delivery-body'); deliveryBody.replaceChildren();
    if (!data.deliveries.length) emptyRow(deliveryBody, '尚无渠道投递记录。', 5);
    for (const item of data.deliveries) {
      const tr = node('tr');
      tr.append(node('td', formatDate(item.createdAt)), node('td', item.provider), node('td', item.alertKey), node('td', item.success ? '成功' : `失败：${item.error || '未知错误'}`), node('td', String(item.payloadSize || 0)));
      deliveryBody.append(tr);
    }
  }
  async function loadAlerts() {
    const [settingsResult, activityResult] = await Promise.all([
      request('/admin/api/alerts/settings'), request('/admin/api/alerts/activity?limit=100')
    ]);
    const data = settingsResult.data;
    $('alert-enabled').checked = data.enabled; $('alert-hourly').checked = data.hourlyDigestEnabled; $('alert-daily').checked = data.dailyDigestEnabled;
    $('alert-upstream-enabled').checked = data.upstreamUpdateAlertEnabled; $('alert-upstream-interval').value = data.upstreamCheckIntervalHours;
    $('alert-cooldown').value = data.cooldownMinutes; $('alert-telegram-enabled').checked = data.telegramEnabled; $('alert-telegram-chat').value = data.telegramChatId || '';
    $('alert-telegram-token').value = ''; $('alert-telegram-token').placeholder = data.telegramConfigured ? '已配置，留空保持不变' : '尚未配置'; $('alert-telegram-interval').value = data.telegramIntervalMs;
    $('alert-bark-enabled').checked = data.barkEnabled; $('alert-bark-server').value = data.barkServerUrl || 'https://api.day.app'; $('alert-bark-key').value = ''; $('alert-bark-key').placeholder = data.barkConfigured ? '已配置，留空保持不变' : '尚未配置'; $('alert-bark-group').value = data.barkGroup || '风险中心'; $('alert-bark-interval').value = data.barkIntervalMs;
    $('alert-denied').value = data.deniedCount5m; $('alert-suspicious').value = data.suspiciousCount10m; $('alert-failure-count').value = data.challengeFailureCount10m; $('alert-failure-ratio').value = data.challengeFailureRatio; $('alert-replay').value = data.replayCount5m; $('alert-cross-site').value = data.crossSiteCount10m;
    $('alert-master-status').textContent = data.enabled ? '告警已开启' : '告警已关闭'; $('alert-master-status').className = `status-chip ${data.enabled ? 'on' : 'off'}`;
    renderAlertActivity(activityResult.data);
  }
  function maintenanceStatus(item) {
    if (item.lastError) return { label: '检查失败', className: 'error' };
    return {
      update_available: { label: '有新版待评估', className: 'available' },
      followed: { label: '已跟进当前版本', className: 'followed' },
      ignored: { label: '已忽略当前版本', className: '' },
      current: { label: '当前已是最新版', className: 'followed' },
      unknown: { label: '尚未检查', className: '' }
    }[item.followStatus] || { label: item.followStatus || '未知', className: '' };
  }
  function renderMaintenance(items) {
    const body = $('maintenance-body'); body.replaceChildren();
    if (!items.length) return emptyRow(body, '尚未登记上游项目。', 7);
    const modeLabels = { direct: '直接集成', signal_source: '信号来源', reference: '仅参考' };
    for (const item of items) {
      const tr = node('tr'); tr.dataset.projectKey = item.projectKey;
      const project = node('td', '', 'maintenance-project');
      project.append(node('strong', item.name), node('span', item.projectKey, 'site-key'));
      const link = node('a', item.repository); link.href = `https://github.com/${item.repository}`; link.target = '_blank'; link.rel = 'noopener'; project.append(link);
      const versions = node('td', '', 'version-stack'); versions.append(node('span', item.installedVersion || '未直接安装'), node('small', item.followedVersion ? `已跟进：${item.followedVersion}` : '尚无跟进记录'));
      const latest = node('td', '', 'version-stack'); latest.append(node('span', item.latestVersion || '尚未获取'));
      if (item.releaseUrl) { const release = node('a', '查看发布说明'); release.href = item.releaseUrl; release.target = '_blank'; release.rel = 'noopener'; latest.append(release); }
      const times = node('td', '', 'version-stack'); times.append(node('span', `发布：${formatDate(item.latestReleaseAt)}`), node('small', `检查：${formatDate(item.lastCheckedAt)}`), node('small', `跟进：${formatDate(item.followedAt)}`));
      const statusData = maintenanceStatus(item); const statusCell = node('td'); statusCell.append(node('span', statusData.label, `update-status ${statusData.className}`)); if (item.lastError) statusCell.append(node('small', item.lastError));
      const actions = node('td', '', 'action-column'); const group = node('div', '', 'inline-actions');
      if (item.latestVersion && item.followStatus === 'update_available') group.append(actionButton('标记已跟进', 'follow-project', 'success'), actionButton('忽略此版本', 'ignore-project'));
      if (['followed', 'ignored'].includes(item.followStatus)) group.append(actionButton('重置状态', 'reset-project'));
      actions.append(group); tr.append(project, node('td', modeLabels[item.integrationMode] || item.integrationMode), versions, latest, times, statusCell, actions); body.append(tr);
    }
  }
  async function loadMaintenance() { const result = await request('/admin/api/maintenance/projects'); renderMaintenance(result.data || []); }
  async function loadActiveTab() { if (state.activeTab === 'suspects') await loadSuspects(); else if (state.activeTab === 'rules') await loadRules(); else if (state.activeTab === 'alerts') await loadAlerts(); else if (state.activeTab === 'maintenance') await loadMaintenance(); else if (state.activeTab === 'audits') await loadAudits(); }
  async function loadDashboard() { await loadOverviewAndSites(); await loadActiveTab(); }

  $('login-form').addEventListener('submit', async event => { event.preventDefault(); const formElement = event.currentTarget; $('login-error').hidden = true; $('login-button').disabled = true; try { const form = new FormData(formElement); const result = await request('/admin/api/login', { method: 'POST', body: JSON.stringify({ username: String(form.get('username') || '').trim(), password: String(form.get('password') || '') }) }); state.csrf = result.data.csrfToken; formElement.reset(); setAuthenticated(true); await loadDashboard(); } catch (error) { $('login-error').textContent = error.message; $('login-error').hidden = false; } finally { $('login-button').disabled = false; } });
  $('logout-button').addEventListener('click', async () => { try { await request('/admin/api/logout', { method: 'POST' }); } catch {} state.csrf = ''; setAuthenticated(false); });
  $('refresh-button').addEventListener('click', () => loadDashboard().then(() => toast('数据已刷新')).catch(error => toast(error.message)));
  document.querySelector('.tabs').addEventListener('click', event => { const tab = event.target.closest('[data-tab]'); if (!tab) return; state.activeTab = tab.dataset.tab; document.querySelectorAll('.tab').forEach(item => item.classList.toggle('active', item === tab)); document.querySelectorAll('.tab-panel').forEach(panel => { panel.hidden = panel.id !== `panel-${state.activeTab}`; }); loadActiveTab().catch(error => toast(error.message)); });
  document.addEventListener('click', async event => {
    const closeButton = event.target.closest('[data-close-dialog]');
    if (closeButton) $(closeButton.dataset.closeDialog).close();
    const copyButton = event.target.closest('[data-copy-signal]');
    if (copyButton) { await navigator.clipboard.writeText(copyButton.dataset.copySignal); toast(`已复制风险信号：${copyButton.dataset.copySignal}`); }
  });
  $('add-integration').addEventListener('click', () => openIntegration());
  $('integration-form').addEventListener('submit', async event => { event.preventDefault(); const urls = $('integration-urls').value.split(/\r?\n/).map(value => value.trim()).filter(Boolean).map((url, index) => ({ url, isPrimary: index === 0 })); try { const result = await request('/admin/api/integrations', { method: 'POST', body: JSON.stringify({ name: $('integration-name').value.trim(), siteKey: $('integration-site-key').value.trim(), clientId: $('integration-client-id').value.trim(), transport: $('integration-transport').value, urls, collectionEnabled: $('integration-collection').checked, enforcementEnabled: $('integration-enforcement').checked, enforcementMode: $('integration-mode').value }) }); $('integration-dialog').close(); if (result.data.secret) showSecret(result.data); toast(result.message); await loadOverviewAndSites(); } catch (error) { toast(error.message); } });
  $('copy-secret').addEventListener('click', async () => { await navigator.clipboard.writeText(`BOT_RISK_URL=${$('secret-endpoint').value}\nBOT_RISK_CLIENT_ID=${$('secret-client').value}\nBOT_RISK_HMAC_SECRET=${$('secret-value').value}`); toast('接入信息已复制'); });

  $('sites-body').addEventListener('click', async event => { const button = event.target.closest('[data-action]'); if (!button) return; const site = state.sites.find(item => item.siteKey === button.closest('tr')?.dataset.siteKey); if (!site) return; try { if (button.dataset.action === 'edit-site') return openIntegration(site); if (button.dataset.action === 'add-client') return openIntegration(site, true); if (button.dataset.action === 'toggle-site') { if (site.enabled && !confirm(`确定关闭 ${site.name} 的总对接吗？`)) return; await request(`/admin/api/sites/${encodeURIComponent(site.siteKey)}/status`, { method: 'PUT', body: JSON.stringify({ enabled: !site.enabled }) }); } else if (button.dataset.action === 'toggle-client') { const client = site.clients.find(item => item.clientId === button.dataset.id); await request(`/admin/api/clients/${encodeURIComponent(client.clientId)}/status`, { method: 'PUT', body: JSON.stringify({ enabled: !client.enabled }) }); } else if (button.dataset.action === 'rotate-client') { if (!confirm('轮换后旧密钥会立即失效，确定继续吗？')) return; const result = await request(`/admin/api/clients/${encodeURIComponent(button.dataset.id)}/rotate`, { method: 'POST' }); showSecret(result.data); } toast('配置已更新'); await loadOverviewAndSites(); } catch (error) { toast(error.message); } });

  $('suspect-site-filter').addEventListener('change', () => { state.suspectPage = 1; loadSuspects().catch(error => toast(error.message)); }); $('suspect-score-filter').addEventListener('change', () => { state.suspectPage = 1; loadSuspects().catch(error => toast(error.message)); }); $('suspect-prev').addEventListener('click', () => { state.suspectPage--; loadSuspects().catch(error => toast(error.message)); }); $('suspect-next').addEventListener('click', () => { state.suspectPage++; loadSuspects().catch(error => toast(error.message)); });
  $('suspects-body').addEventListener('click', event => { const button = event.target.closest('[data-action="view-suspect"]'); const row = button?.closest('tr'); if (row) openSuspect(row.dataset.siteKey, row.dataset.visitorHash).catch(error => toast(error.message)); });
  $('suspect-permanent').addEventListener('change', event => { $('suspect-duration').disabled = event.currentTarget.checked; });
  $('suspect-apply-all-sites').addEventListener('change', event => { $('suspect-rule-signal').disabled = !event.currentTarget.checked; });
  $('suspect-action-form').addEventListener('submit', async event => { event.preventDefault(); if (!state.currentSuspect) return; const applyToAllSites = $('suspect-apply-all-sites').checked; const ruleSignal = $('suspect-rule-signal').value; if (applyToAllSites && !confirm(`将把风险信号“${ruleSignal}”的同类处置应用到所有接入站点，确定继续吗？`)) return; try { const { siteKey, visitorHash } = state.currentSuspect; const result = await request(`/admin/api/risk/suspects/${encodeURIComponent(siteKey)}/${visitorHash}/action`, { method: 'POST', body: JSON.stringify({ action: $('suspect-action').value, durationMinutes: Number($('suspect-duration').value), permanent: $('suspect-permanent').checked, reason: $('suspect-reason').value.trim(), applyToAllSites, ruleSignal: applyToAllSites ? ruleSignal : '' }) }); $('suspect-dialog').close(); toast(result.message || ($('suspect-permanent').checked ? '永久人工处置已生效' : '人工处置已生效')); await loadSuspects(); } catch (error) { toast(error.message); } });
  $('clear-suspect-action').addEventListener('click', async () => { if (!state.currentSuspect) return; const { siteKey, visitorHash } = state.currentSuspect; try { await request(`/admin/api/risk/suspects/${encodeURIComponent(siteKey)}/${visitorHash}/action`, { method: 'DELETE' }); $('suspect-dialog').close(); toast('人工处置已解除'); await loadSuspects(); } catch (error) { toast(error.message); } });

  $('rule-scope').addEventListener('change', event => { const anySite = event.currentTarget.value === 'all'; $('rule-site').disabled = anySite; $('rule-site').required = !anySite; });
  $('rule-permanent').addEventListener('change', event => { $('rule-duration').disabled = event.currentTarget.checked; $('rule-duration').required = !event.currentTarget.checked; });
  $('preview-rule').addEventListener('click', async () => { try { const siteKey = $('rule-scope').value === 'all' ? '*' : $('rule-site').value; const query = new URLSearchParams({ siteKey, signal: $('rule-signal').value.trim() }); const result = await request(`/admin/api/risk/rules/preview?${query}`); $('rule-preview-result').textContent = `近 24 小时将影响 ${result.data.visitors24h} 个访客、${result.data.events24h} 次事件。`; } catch (error) { toast(error.message); } });
  $('rule-form').addEventListener('submit', async event => { event.preventDefault(); try { const siteKey = $('rule-scope').value === 'all' ? '*' : $('rule-site').value; await request('/admin/api/risk/rules', { method: 'POST', body: JSON.stringify({ siteKey, signal: $('rule-signal').value.trim(), action: $('rule-action').value, permanent: $('rule-permanent').checked, durationMinutes: $('rule-permanent').checked ? null : Number($('rule-duration').value), reason: $('rule-reason').value.trim() }) }); toast('规则已创建'); $('rule-signal').value = ''; $('rule-reason').value = ''; $('rule-permanent').checked = false; $('rule-duration').disabled = false; $('rule-duration').required = true; await loadRules(); } catch (error) { toast(error.message); } });
  $('rules-body').addEventListener('click', async event => { const button = event.target.closest('[data-action]'); const row = button?.closest('tr'); if (!row) return; try { if (button.dataset.action === 'delete-rule') { if (!confirm('确定删除该规则吗？')) return; await request(`/admin/api/risk/rules/${row.dataset.ruleId}`, { method: 'DELETE' }); } else { const enabled = row.children[4].textContent !== '已启用'; await request(`/admin/api/risk/rules/${row.dataset.ruleId}/status`, { method: 'PUT', body: JSON.stringify({ enabled }) }); } await loadRules(); toast('规则已更新'); } catch (error) { toast(error.message); } });

  $('alert-form').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const result = await request('/admin/api/alerts/settings', { method: 'PUT', body: JSON.stringify({
        enabled: $('alert-enabled').checked, hourlyDigestEnabled: $('alert-hourly').checked, dailyDigestEnabled: $('alert-daily').checked,
        upstreamUpdateAlertEnabled: $('alert-upstream-enabled').checked, upstreamCheckIntervalHours: numberValue('alert-upstream-interval'),
        cooldownMinutes: numberValue('alert-cooldown'), telegramEnabled: $('alert-telegram-enabled').checked,
        telegramToken: $('alert-telegram-token').value.trim(), telegramChatId: $('alert-telegram-chat').value.trim(), telegramIntervalMs: numberValue('alert-telegram-interval'),
        barkEnabled: $('alert-bark-enabled').checked, barkServerUrl: $('alert-bark-server').value.trim(), barkDeviceKey: $('alert-bark-key').value.trim(), barkGroup: $('alert-bark-group').value.trim(), barkIntervalMs: numberValue('alert-bark-interval'),
        deniedCount5m: numberValue('alert-denied'), suspiciousCount10m: numberValue('alert-suspicious'), challengeFailureCount10m: numberValue('alert-failure-count'), challengeFailureRatio: numberValue('alert-failure-ratio'), replayCount5m: numberValue('alert-replay'), crossSiteCount10m: numberValue('alert-cross-site')
      }) });
      toast(result.message); await loadAlerts();
    } catch (error) { toast(error.message); }
  });
  async function testAlert(provider) {
    const button = provider === 'telegram' ? $('test-telegram') : $('test-bark');
    const original = button.textContent; button.disabled = true; button.textContent = '发送中…';
    try { const result = await request(`/admin/api/alerts/test/${provider}`, { method: 'POST' }); toast(result.message); await loadAlerts(); }
    catch (error) { toast(error.message); }
    finally { button.disabled = false; button.textContent = original; }
  }
  $('test-telegram').addEventListener('click', () => testAlert('telegram'));
  $('test-bark').addEventListener('click', () => testAlert('bark'));

  $('check-upstreams').addEventListener('click', async event => {
    const button = event.currentTarget; const original = button.textContent; button.disabled = true; button.textContent = '正在检查…';
    try { const result = await request('/admin/api/maintenance/check', { method: 'POST' }); toast(result.message); renderMaintenance(result.data.items || []); }
    catch (error) { toast(error.message); }
    finally { button.disabled = false; button.textContent = original; }
  });
  $('generate-maintenance-token').addEventListener('click', async () => {
    try {
      const result = await request('/admin/api/maintenance/token', { method: 'POST' });
      $('maintenance-snapshot-url').value = result.data.snapshotUrl; $('maintenance-upstreams-url').value = result.data.upstreamsUrl; $('maintenance-token').value = result.data.token;
      $('maintenance-token-expiry').textContent = `有效至 ${formatDate(result.data.expiresAt)} · 最多 ${result.data.maxUses} 次`; $('copy-maintenance-access').disabled = false; toast(result.message);
    } catch (error) { toast(error.message); }
  });
  $('copy-maintenance-endpoints').addEventListener('click', async () => {
    const value = `只读诊断接口：${$('maintenance-snapshot-url').value}\n上游更新信息接口：${$('maintenance-upstreams-url').value}`;
    await navigator.clipboard.writeText(value); toast('维护接口地址已复制');
  });
  $('copy-maintenance-access').addEventListener('click', async () => {
    const value = `只读诊断接口：${$('maintenance-snapshot-url').value}\n上游更新信息接口：${$('maintenance-upstreams-url').value}\nAuthorization: Bearer ${$('maintenance-token').value}`;
    await navigator.clipboard.writeText(value); toast('只读接入信息已复制');
  });
  $('maintenance-body').addEventListener('click', async event => {
    const button = event.target.closest('[data-action]'); const row = button?.closest('tr'); if (!row) return;
    const action = { 'follow-project': 'followed', 'ignore-project': 'ignored', 'reset-project': 'reset' }[button.dataset.action]; if (!action) return;
    if (action === 'followed' && !confirm('这里只记录已经完成评估或代码跟进，不会自动安装上游版本。确认标记吗？')) return;
    try { const result = await request(`/admin/api/maintenance/projects/${encodeURIComponent(row.dataset.projectKey)}/status`, { method: 'PUT', body: JSON.stringify({ action }) }); toast(result.message); await loadMaintenance(); }
    catch (error) { toast(error.message); }
  });

  $('maintenance-snapshot-url').value = `${window.location.origin}/v1/maintenance/snapshot`;
  $('maintenance-upstreams-url').value = `${window.location.origin}/v1/maintenance/upstreams`;
  request('/admin/api/session').then(result => { state.csrf = result.data.csrfToken; setAuthenticated(true); return loadDashboard(); }).catch(() => setAuthenticated(false));
})();
