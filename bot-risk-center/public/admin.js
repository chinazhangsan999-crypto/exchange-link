'use strict';
(() => {
  const $ = id => document.getElementById(id);
  const validTabs = new Set(['connections', 'suspects', 'detection', 'rules', 'alerts', 'maintenance', 'security', 'audits']);
  const requestedTab = window.location.hash.replace(/^#/, '');
  const initialTab = requestedTab === 'quality' ? 'connections' : (validTabs.has(requestedTab) ? requestedTab : 'connections');
  const state = { csrf: '', sites: [], suspectPage: 1, suspectTotal: 0, suspectItems: [], selectedSuspects: new Set(), currentSuspect: null, activeTab: initialTab, riskRange: '24h', identityPage: 1, identityTotal: 0, identityItems: [], editingIdentity: null, maintenanceItems: [], maintenanceScope: 'all' };
  const signalLabels = Object.freeze({
    cloudflare_confirmed_bot: 'Cloudflare 已确认机器人', verified_search_bot: '已验证搜索引擎蜘蛛', search_bot_spoofed: '搜索蜘蛛身份不一致',
    known_ai_crawler: '已知 AI 爬虫', token_replay: '读取凭证重放', sequential_detail_scan: '连续枚举详情页',
    known_crawler_ua: '已知通用爬虫 UA',
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
    search_bot_spoofed: '客户端声称自己是搜索引擎蜘蛛，但其 IP 未通过反向域名与正向地址的双向校验，可能是伪造 User-Agent 的自动程序。',
    known_ai_crawler: 'User-Agent 或风险情报命中了已知 AI 抓取工具特征。这类客户端通常以程序方式批量读取页面。',
    known_crawler_ua: '请求标识命中了持续维护的通用爬虫规则库。由于 User-Agent 可以伪造，该信号只增加观察分，需结合并发、遍历或验证失败等证据判断。',
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
    secFetchSite: 'Sec-Fetch-Site', secFetchMode: 'Sec-Fetch-Mode', secFetchDest: 'Sec-Fetch-Dest',
    hostname: '反向域名', verificationReason: '身份校验结果'
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
  async function requestBlob(path, body) {
    const response = await fetch(path, {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': state.csrf }, body: JSON.stringify(body)
    });
    if (!response.ok) {
      const result = await response.json().catch(() => null);
      throw new Error(result?.message || `请求失败 (${response.status})`);
    }
    return response.blob();
  }
  function toast(message) { clearTimeout(toastTimer); $('status-message').textContent = message; $('status-message').hidden = false; toastTimer = setTimeout(() => { $('status-message').hidden = true; }, 4500); }
  function node(tag, text = '', className = '') { const element = document.createElement(tag); element.textContent = text; if (className) element.className = className; return element; }
  function formatDate(value) { if (!value) return '尚无记录'; const date = new Date(value); return Number.isNaN(date.getTime()) ? '未知' : new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(date); }
  function emptyRow(body, text, columns) { body.replaceChildren(); const tr = node('tr'); const td = node('td', text, 'empty-cell'); td.colSpan = columns; tr.append(td); body.append(tr); }
  function chip(text, on = true) { return node('span', text, `status-chip ${on ? 'on' : 'off'}`); }
  function installDriveCallbackCopyControl() {
    const input = $('drive-oauth-callback');
    if (!input || input.parentElement?.querySelector('#copy-drive-oauth-callback')) return;
    const row = node('div', '', 'readonly-copy-row');
    const button = node('button', '复制回调地址', 'button secondary');
    button.id = 'copy-drive-oauth-callback';
    button.type = 'button';
    button.addEventListener('click', async () => {
      await navigator.clipboard.writeText(input.value);
      toast('Google OAuth 回调地址已复制');
    });
    input.before(row);
    row.append(input, button);
  }
  function installIdentityControls() {
    const form = $('identity-form'); const section = form.closest('.panel-subsection');
    section.classList.add('identity-section'); form.classList.remove('inline-form'); form.classList.add('identity-editor');
    section.querySelector('.subtle').textContent = '单站规则优先于全站规则；同一范围的同一对象不能同时允许和阻止。UA、ASN、JA4 等弱身份不建议单独永久拒绝。';
    const subject = $('identity-subject'); const help = node('small', '填写风险中心显示的访客摘要，区分大小写。'); help.id = 'identity-subject-help'; subject.after(help);
    const duration = $('identity-duration'); const durationLabel = duration.closest('label'); durationLabel.classList.add('identity-duration-field');
    const validity = document.createElement('select'); validity.id = 'identity-validity';
    for (const [value, label] of [['60','60 分钟'],['1440','24 小时'],['10080','7 天'],['custom','自定义'],['0','永久']]) { const option = node('option', label); option.value = value; validity.append(option); }
    durationLabel.firstChild.textContent = '有效期'; duration.before(validity); duration.hidden = true;
    $('identity-permanent').closest('label').hidden = true;
    const error = node('p', '', 'form-note identity-error'); error.id = 'identity-form-error'; error.setAttribute('role', 'alert');
    const actions = form.querySelector('.form-actions'); actions.before(error);
    const submit = actions.querySelector('button[type="submit"]'); submit.id = 'identity-submit';
    const cancel = actionButton('取消编辑', 'cancel-identity'); cancel.id = 'identity-cancel-edit'; cancel.hidden = true; actions.prepend(cancel);
    const filters = node('div', '', 'identity-filters');
    const filterDefs = [['identity-filter-list','名单',[['','全部'],['allow','允许'],['block','阻止']]],['identity-filter-site','站点',[['','全部站点'],['*','所有站点规则']]],['identity-filter-subject','对象',[['','全部类型'],['visitor','访客摘要'],['bot_identity','机器人身份'],['ua','User-Agent'],['ja4','JA4'],['asn','ASN']]],['identity-filter-status','状态',[['','全部'],['enabled','启用'],['disabled','停用']]]];
    for (const [id,labelText,options] of filterDefs) { const label=node('label', labelText); const select=document.createElement('select'); select.id=id; for(const [value,text] of options){const option=node('option',text); option.value=value; select.append(option);} label.append(select); filters.append(label); }
    const keywordLabel=node('label','搜索','identity-keyword'); const keyword=document.createElement('input'); keyword.id='identity-filter-keyword'; keyword.maxLength=120; keyword.placeholder='对象值或原因'; keywordLabel.append(keyword); filters.append(keywordLabel);
    const tableWrap = section.querySelector('.table-wrap'); tableWrap.classList.add('identity-table-wrap'); tableWrap.before(filters);
    const table=tableWrap.querySelector('table'); table.classList.add('identity-table'); table.querySelector('thead tr').replaceChildren(...['名单 / 状态','范围','对象','有效期','原因','命中','操作'].map(text=>node('th',text)));
    const pagination=node('div','','identity-pagination'); const summary=node('span','共 0 条'); summary.id='identity-page-summary'; const buttons=node('div','','button-row');
    const prev=actionButton('上一页','identity-prev'); prev.id='identity-prev'; const page=node('span','1 / 1'); page.id='identity-page'; const next=actionButton('下一页','identity-next'); next.id='identity-next'; buttons.append(prev,page,next); pagination.append(summary,buttons); tableWrap.after(pagination);
  }
  function installMaintenanceScopeFilter() {
    const legend = document.querySelector('#panel-maintenance .maintenance-legend');
    const label = node('label', '显示范围', 'maintenance-scope-filter');
    const select = document.createElement('select'); select.id = 'maintenance-scope-filter';
    for (const [value, text] of [['all','全部项目'],['risk_center','风险中心'],['navigation','导航站'],['reference','仅参考项目']]) {
      const option = node('option', text); option.value = value; select.append(option);
    }
    select.addEventListener('change', event => { state.maintenanceScope = event.currentTarget.value; renderMaintenance(state.maintenanceItems); });
    label.append(select); legend.prepend(label);
  }
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
    const identitySite = $('identity-site');
    if (identitySite) {
      const current = identitySite.value || '*';
      const all = node('option', '所有站点'); all.value = '*';
      identitySite.replaceChildren(all, ...state.sites.map(site => { const option = node('option', site.name || site.siteKey); option.value = site.siteKey; return option; }));
      identitySite.value = current;
    }
    const identityFilterSite = $('identity-filter-site');
    if (identityFilterSite) {
      const current = identityFilterSite.value;
      const all = node('option', '全部站点'); all.value = '';
      const global = node('option', '所有站点规则'); global.value = '*';
      identityFilterSite.replaceChildren(all, global, ...state.sites.map(site => { const option = node('option', site.name || site.siteKey); option.value = site.siteKey; return option; }));
      identityFilterSite.value = current;
    }
    const driveSites = $('drive-sites');
    if (driveSites) {
      const selected = new Set([...driveSites.selectedOptions].map(option => option.value));
      driveSites.replaceChildren(...state.sites.map(site => { const option = node('option', site.name || site.siteKey); option.value = site.siteKey; option.selected = selected.has(site.siteKey); return option; }));
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

  function renderOverview(overview) {
    $('metric-sites').textContent = overview.sites;
    $('metric-enabled').textContent = overview.enabledSites;
    $('metric-events').textContent = overview.events;
    $('metric-decisions').textContent = overview.decisions;
    $('metric-events-label').textContent = `${overview.rangeLabel}风险事件`;
    $('metric-decisions-label').textContent = `${overview.rangeLabel}风险决定`;
  }

  async function loadOverview() {
    const overview = await request(`/admin/api/overview?range=${encodeURIComponent(state.riskRange)}`);
    renderOverview(overview.data);
  }

  async function loadOverviewAndSites() {
    const [overview, sites] = await Promise.all([request(`/admin/api/overview?range=${encodeURIComponent(state.riskRange)}`), request('/admin/api/sites')]);
    state.sites = sites.data || [];
    renderOverview(overview.data);
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
    const query = new URLSearchParams({ page: String(state.suspectPage), limit: '50', minScore: $('suspect-score-filter').value, range: state.riskRange }); if ($('suspect-site-filter').value) query.set('siteKey', $('suspect-site-filter').value);
    const [summary, suspects] = await Promise.all([request(`/admin/api/risk/summary?${query}`), request(`/admin/api/risk/suspects?${query}`)]);
    const rangeLabel = summary.data.rangeLabel || '近 24 小时';
    $('risk-visitors').textContent = summary.data.visitors; $('risk-suspects').textContent = summary.data.suspects; $('risk-challenged').textContent = summary.data.challenged; $('risk-blocked').textContent = summary.data.blocked;
    $('risk-visitors-label').textContent = `${rangeLabel}访客`;
    $('risk-suspects-label').textContent = `${rangeLabel}疑似访客`;
    $('risk-challenged-label').textContent = `${rangeLabel}挑战处置`;
    $('risk-blocked-label').textContent = `${rangeLabel}拒绝处置`;
    $('signal-summary').replaceChildren(...(summary.data.signals || []).map(item => node('span', `${item.signal} · ${item.visitors} 人 / ${item.count} 次`, 'signal-chip')));
    const body = $('suspects-body'); body.replaceChildren(); const data = suspects.data; state.suspectTotal = data.total; state.suspectItems = data.items || [];
    if (!data.items.length) emptyRow(body, `${rangeLabel}内没有符合当前筛选条件的疑似访客。`, 9);
    for (const item of data.items) { const tr = node('tr'); tr.dataset.siteKey = item.siteKey; tr.dataset.visitorHash = item.visitorHash; const key = `${item.siteKey}:${item.visitorHash}`; const selectCell = node('td', '', 'select-column'); const checkbox = document.createElement('input'); checkbox.type = 'checkbox'; checkbox.dataset.selectSuspect = key; checkbox.setAttribute('aria-label', `选择 ${item.siteName} 访客`); checkbox.checked = state.selectedSuspects.has(key); selectCell.append(checkbox); const who = node('td'); who.append(node('strong', item.siteName), node('span', `${item.visitorHash.slice(0, 12)}…`, 'site-key')); const decision = node('td'); decision.append(chip(item.manualAction ? `人工：${item.manualAction}` : item.decision, !['deny', 'strong_challenge'].includes(item.manualAction || item.decision))); const signalItems = (item.signals || []).length ? item.signals : (item.reasons || []).filter(reason => !String(reason).startsWith('manual_')).map(signal => ({ signal, count: 1, scoreImpact: 0, firstSeen: item.firstSeen, lastSeen: item.lastSeen, latestEvidence: {} })); const reasons = node('td', '', 'reason-cell'); for (const signal of signalItems.slice(0, 3)) { const reason = node('div', '', 'reason-summary'); reason.append(node('strong', signalLabel(signal.signal)), node('span', signalExplanation(signal.signal)), node('small', `命中 ${signal.count} 次 · 最近 ${formatDate(signal.lastSeen)}`)); const evidence = evidenceSummary(signal.latestEvidence); if (evidence) reason.append(node('small', `最近证据：${evidence}`, 'reason-evidence-inline')); reasons.append(reason); } if (!signalItems.length) reasons.append(node('span', (item.reasons || []).map(reasonLabel).join('；') || '暂无可解释信号')); const signals = node('td'); signals.append(renderSignalChips(signalItems)); const action = node('td', '', 'action-column'); const actions = node('div', '', 'inline-actions'); actions.append(actionButton('复制分析包', 'copy-analysis-package'), actionButton('查看证据 / 处置', 'view-suspect')); action.append(actions); tr.append(selectCell, who, node('td', String(item.score), 'numeric'), decision, reasons, signals, node('td', String(item.eventCount), 'numeric'), node('td', formatDate(item.lastSeen)), action); body.append(tr); }
    const visibleKeys = data.items.map(item => `${item.siteKey}:${item.visitorHash}`); $('select-all-suspects').checked = visibleKeys.length > 0 && visibleKeys.every(key => state.selectedSuspects.has(key)); $('select-all-suspects').indeterminate = visibleKeys.some(key => state.selectedSuspects.has(key)) && !$('select-all-suspects').checked; $('export-analysis-selected').disabled = state.selectedSuspects.size === 0;
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

  async function loadRules() {
    const [result, revisions, policies] = await Promise.all([request('/admin/api/risk/rules'), request('/admin/api/risk/rules/revisions?limit=100'), request('/admin/api/risk/policies')]);
    const body = $('rules-body'); body.replaceChildren();
    if (!result.data.length) emptyRow(body, '尚未配置人工信号规则。', 7);
    for (const rule of result.data) {
      const tr = node('tr'); tr.dataset.ruleId = rule.id;
      const actions = node('td', '', 'action-column'); const group = node('div', '', 'inline-actions');
      group.append(actionButton(rule.enabled ? '停用' : '启用', 'toggle-rule', rule.enabled ? 'danger' : 'success'), actionButton('删除', 'delete-rule', 'danger')); actions.append(group);
      tr.append(node('td', rule.scope === 'all' ? '任意站点' : rule.siteName), node('td', `${signalLabel(rule.signal)}\n${rule.signal}`), node('td', rule.action), node('td', rule.mode === 'shadow' ? '影子观察' : '正式执行'), node('td', rule.permanent ? '永久' : `${rule.durationMinutes} 分钟`), node('td', rule.enabled ? '已启用' : '已停用'), actions); body.append(tr);
    }
    const revisionsBody = $('rule-revisions-body'); revisionsBody.replaceChildren();
    if (!revisions.data.length) emptyRow(revisionsBody, '尚无规则修订记录。', 5);
    for (const item of revisions.data) {
      const snapshot = item.snapshot || {};
      const tr = node('tr'); tr.append(node('td', formatDate(item.createdAt)), node('td', String(item.ruleId || '—')),
        node('td', item.operation), node('td', item.createdBy), node('td', `${snapshot.signal || '—'} · ${snapshot.action || '—'} · ${snapshot.mode || 'enforce'}`));
      revisionsBody.append(tr);
    }
    const policiesBody = $('policies-body'); policiesBody.replaceChildren();
    for (const item of policies.data || []) {
      const values = item.configuration?.thresholds || {};
      const tr = node('tr'); tr.dataset.policyId = item.id;
      const action = node('td', '', 'action-column');
      if (!item.active) action.append(actionButton('启用 / 回滚到此版本', 'activate-policy', 'secondary'));
      tr.append(node('td', item.version), node('td', item.name), node('td', `${values.observe ?? 25} / ${values.silentChallenge ?? 50} / ${values.strongChallenge ?? 75} / ${values.deny ?? 90}`),
        node('td', item.active ? '当前生效' : '历史 / 草稿'), node('td', formatDate(item.createdAt)), action); policiesBody.append(tr);
    }
  }

  function identityQuery() {
    const params = new URLSearchParams({ page: state.identityPage, pageSize: 100 });
    for (const [key, id] of [['listType', 'identity-filter-list'], ['siteKey', 'identity-filter-site'], ['subjectType', 'identity-filter-subject'], ['status', 'identity-filter-status'], ['keyword', 'identity-filter-keyword']]) {
      if ($(id)?.value.trim()) params.set(key, $(id).value.trim());
    }
    return params.toString();
  }

  function resetIdentityEditor() {
    state.editingIdentity = null; $('identity-form').reset(); $('identity-duration').value = '60';
    $('identity-list-type').disabled = false; $('identity-validity').value = '60'; $('identity-duration').hidden = true;
    $('identity-permanent').checked = false; $('identity-duration').disabled = false;
    $('identity-form-error').textContent = ''; $('identity-submit').textContent = '保存名单项'; $('identity-cancel-edit').hidden = true;
  }

  async function loadDetection() {
    const range = $('detection-range').value;
    const capabilities = await request(`/admin/api/detection/capabilities?range=${encodeURIComponent(range)}`);
    const body = $('detection-body'); body.replaceChildren();
    const statusLabels = { connected: '已接入', partial: '部分接入', not_connected: '尚未接入' };
    const confidenceLabels = { high: '强', medium: '中', low: '弱' };
    for (const item of capabilities.data.items || []) {
      const tr = node('tr');
      const name = node('td'); name.append(node('strong', item.label), node('code', item.signal));
      const status = node('td'); status.append(chip(statusLabels[item.integrationStatus] || item.integrationStatus, item.integrationStatus === 'connected'));
      const score = node('td', `${item.weight > 0 ? '+' : ''}${item.weight}${item.hardDeny ? ' · 强制拒绝' : ''}`, 'numeric');
      tr.append(name, node('td', item.category), status, node('td', confidenceLabels[item.confidence] || item.confidence), score,
        node('td', `${item.events} 次 / ${item.visitors} 人`, 'numeric'), node('td', formatDate(item.lastSeen)), node('td', item.implementationNote));
      body.append(tr);
    }
  }

  async function loadIdentityLists() {
    const identities = await request(`/admin/api/detection/identity-lists?${identityQuery()}`);
    const identityData = identities.data || { items: [], total: 0, page: 1, pageSize: 100 };
    state.identityItems = identityData.items || []; state.identityTotal = identityData.total || 0; state.identityPage = identityData.page || 1;
    const totalPages = Math.max(1, Math.ceil(state.identityTotal / (identityData.pageSize || 100)));
    $('identity-page-summary').textContent = `共 ${state.identityTotal} 条 · 每页最多 100 条`;
    $('identity-page').textContent = `${state.identityPage} / ${totalPages}`;
    $('identity-prev').disabled = state.identityPage <= 1; $('identity-next').disabled = state.identityPage >= totalPages;
    const identityBody = $('identity-body'); identityBody.replaceChildren();
    if (!state.identityItems.length) emptyRow(identityBody, '当前筛选条件下没有名单项。', 7);
    for (const item of state.identityItems) {
      const tr = node('tr'); tr.dataset.id = item.id; tr.dataset.listType = item.listType;
      const action = node('td', '', 'action-column'); action.dataset.label = '操作';
      action.append(actionButton('编辑', 'edit-identity'), actionButton(item.enabled ? '停用' : '启用', 'toggle-identity'), actionButton('删除', 'delete-identity', 'danger'));
      const status = node('td'); status.dataset.label = '名单 / 状态'; status.append(chip(`${item.listType === 'allow' ? '允许' : '阻止'} · ${item.enabled ? '启用' : '停用'}`, item.enabled));
      const range = node('td', item.siteKey === '*' ? '所有站点' : item.siteKey); range.dataset.label = '范围';
      const subject = node('td', `${item.subjectType}\n${item.subjectHash}`); subject.dataset.label = '对象';
      const expiry = node('td', item.expiresAt ? formatDate(item.expiresAt) : '永久'); expiry.dataset.label = '有效期';
      const reason = node('td', item.reason || '—'); reason.dataset.label = '原因';
      const hits = node('td', `${item.hitCount || 0} 次\n${item.lastHitAt ? formatDate(item.lastHitAt) : '尚未命中'}`); hits.dataset.label = '命中';
      tr.append(status, range, subject, expiry, reason, hits, action);
      identityBody.append(tr);
    }
  }

  async function loadQuality() {
    const [result, pipelineResult] = await Promise.all([request(`/admin/api/detection/quality?range=${encodeURIComponent($('quality-range').value)}`), request('/admin/api/detection/pipeline')]);
    const data = result.data; const challenge = data.challenge || {};
    $('quality-total').textContent = challenge.total || 0; $('quality-passed').textContent = challenge.passed || 0;
    $('quality-failed').textContent = challenge.failed || 0; $('quality-corrections').textContent = data.manualCorrections || 0;
    $('quality-average').textContent = `${challenge.averageMs || 0} ms`; $('quality-p95').textContent = `${challenge.p95Ms || 0} ms`;
    $('quality-pass-rate').textContent = challenge.total ? `${Math.round(challenge.passed * 1000 / challenge.total) / 10}%` : '暂无数据';
    $('quality-decisions').replaceChildren(...(data.decisions || []).map(item => node('span', `${item.decision} · ${item.count}`, 'signal-chip')));
    $('quality-signals').replaceChildren(...(data.topSignals || []).map(item => node('span', `${signalLabel(item.signal)} · ${item.visitors} 人 / ${item.count} 次`, 'signal-chip')));
    const pipeline = pipelineResult.data;
    $('pipeline-summary').replaceChildren(
      chip(`PostgreSQL ${pipeline.database ? '正常' : '异常'}`, pipeline.database),
      chip(`Redis ${pipeline.redis ? '正常' : '异常'}`, pipeline.redis),
      node('span', `5分钟：事件 ${pipeline.events5m || 0} · 决策 ${pipeline.decisions5m || 0} · 验证 ${pipeline.challenges5m || 0}`, 'signal-chip')
    );
    const pipelineBody = $('pipeline-body'); pipelineBody.replaceChildren();
    if (!pipeline.sites.length) emptyRow(pipelineBody, '没有启用的导航站。', 5);
    for (const item of pipeline.sites) {
      const tr = node('tr'); const status = node('td'); status.append(chip(item.stale ? '上报过期' : '正常', !item.stale));
      tr.append(node('td', `${item.name}\n${item.siteKey}`), node('td', String(item.events24h), 'numeric'), node('td', formatDate(item.lastUsedAt)), status, node('td', item.lastError || '—')); pipelineBody.append(tr);
    }
  }

  async function loadSecurity() {
    const result = await request('/admin/api/security'); const data = result.data;
    $('security-username').value = data.account.username || '';
    $('security-account-meta').textContent = `当前账号：${data.account.username || '—'} · 最近修改：${formatDate(data.account.passwordChangedAt)}`;
    const githubToken = $('github-token');
    githubToken.value = '';
    githubToken.required = !data.githubApi?.configured;
    $('github-token-status').textContent = data.githubApi?.configured
      ? `${data.githubApi.source === 'admin' ? '后台已配置' : '服务器环境已配置'} · 最近更新：${formatDate(data.githubApi.updatedAt)}`
      : '未配置 · 当前检查会受 GitHub 匿名限额限制';
    const body = $('security-sessions-body'); body.replaceChildren();
    if (!data.sessions.length) return emptyRow(body, '没有有效会话。', 5);
    for (const item of data.sessions) {
      const tr = node('tr'); tr.dataset.sessionId = item.id;
      const device = String(item.userAgent || '未知设备').slice(0, 120);
      const status = item.revokedAt ? '已撤销' : item.current ? '当前设备' : '有效';
      const action = node('td', '', 'action-column');
      if (!item.revokedAt) action.append(actionButton(item.current ? '退出当前设备' : '下线', 'revoke-session', 'danger'));
      tr.append(node('td', device), node('td', item.sourceIp || '未知'), node('td', formatDate(item.lastSeenAt)), node('td', status), action); body.append(tr);
    }
  }
  async function loadAudits() { const result = await request('/admin/api/audits?limit=100'); const body = $('audits-body'); body.replaceChildren(); if (!result.data.length) return emptyRow(body, '尚无管理操作记录。', 5); for (const item of result.data) { const tr = node('tr'); const actorCell = node('td'); actorCell.append(node('strong', item.actor), node('small', item.sourceIp || '未记录来源')); tr.append(node('td', formatDate(item.createdAt)), node('td', item.action), node('td', item.target), actorCell, node('td', JSON.stringify(item.details))); body.append(tr); } }
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
    const [settingsResult, activityResult, backupResult] = await Promise.all([
      request('/admin/api/alerts/settings'), request('/admin/api/alerts/activity?limit=100'),
      request('/admin/api/rule-backups/status')
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
    renderRuleBackup(backupResult.data || {});
  }
  function renderRuleBackup(data) {
    const settings = data.settings || {};
    $('rule-backup-enabled').checked = Boolean(settings.enabled);
    $('rule-backup-on-change').checked = settings.automaticOnChange !== false;
    $('rule-backup-token').value = '';
    $('rule-backup-token').placeholder = settings.telegramConfigured ? '已加密保存，留空保持不变' : '尚未配置';
    $('rule-backup-chat').value = settings.telegramChatId || '';
    $('rule-backup-hour').value = settings.backupHourBjt ?? 3;
    $('rule-backup-part-size').value = settings.partSizeMiB ?? 18;
    const status = $('rule-backup-status');
    status.textContent = data.running ? '备份执行中' : (settings.enabled && settings.telegramConfigured ? '自动备份已开启' : (settings.telegramConfigured ? '自动备份已关闭' : '尚未配置'));
    status.className = `status-chip ${settings.enabled && settings.telegramConfigured ? 'on' : 'off'}`;
    const body = $('rule-backup-body'); body.replaceChildren();
    const triggerLabels = { manual: '手动', scheduled: '定时', rule_change: '规则变更', retry: '重试' };
    const statusLabels = { success: '成功', failed: '失败', uploading: '上传中', pending: '等待中' };
    const runs = data.runs || [];
    if (!runs.length) return emptyRow(body, '尚无人工规则备份记录。', 6);
    for (const run of runs) {
      const tr = node('tr');
      const uploaded = (run.uploadedParts || []).length;
      tr.append(
        node('td', formatDate(run.createdAt)),
        node('td', triggerLabels[run.triggerType] || run.triggerType),
        node('td', `信号规则 ${run.ruleCount}（启用 ${run.enabledCount}）\n允许 ${run.allowCount || 0} · 阻止 ${run.blockCount || 0}\n策略 ${run.policyCount || 0} · 修订 ${run.revisionCount || 0}`),
        node('td', `${uploaded}/${run.partsTotal}`),
        node('td', run.lastError ? `${statusLabels[run.status] || run.status}：${run.lastError}` : (statusLabels[run.status] || run.status)),
        node('td', run.contentSha256 ? `${run.contentSha256.slice(0, 16)}…` : '—')
      );
      body.append(tr);
    }
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
    state.maintenanceItems = Array.isArray(items) ? items : [];
    const visible = state.maintenanceItems.filter(item => {
      if (state.maintenanceScope === 'all') return true;
      if (state.maintenanceScope === 'reference') return item.integrationMode === 'reference';
      return Array.isArray(item.usedBy) && item.usedBy.includes(state.maintenanceScope);
    });
    const body = $('maintenance-body'); body.replaceChildren();
    if (!visible.length) return emptyRow(body, state.maintenanceItems.length ? '当前范围没有项目。' : '尚未登记上游项目。', 7);
    const modeLabels = { direct: '直接集成', signal_source: '信号来源', reference: '仅参考' };
    const scopeLabels = { risk_center: '风险中心', navigation: '导航站', reference: '参考' };
    for (const item of visible) {
      const tr = node('tr'); tr.dataset.projectKey = item.projectKey;
      const project = node('td', '', 'maintenance-project');
      project.append(node('strong', item.name), node('span', item.projectKey, 'site-key'));
      const link = node('a', item.repository); link.href = `https://github.com/${item.repository}`; link.target = '_blank'; link.rel = 'noopener'; project.append(link);
      const versions = node('td', '', 'version-stack'); versions.append(node('span', item.installedVersion || (item.integrationMode === 'reference' ? '未直接安装' : '版本待上报')), node('small', item.followedVersion ? `已跟进：${item.followedVersion}` : '尚无跟进记录'));
      const latest = node('td', '', 'version-stack'); latest.append(node('span', item.latestVersion || '尚未获取'));
      if (item.releaseUrl) { const release = node('a', '查看发布说明'); release.href = item.releaseUrl; release.target = '_blank'; release.rel = 'noopener'; latest.append(release); }
      const times = node('td', '', 'version-stack'); times.append(node('span', `发布：${formatDate(item.latestReleaseAt)}`), node('small', `检查：${formatDate(item.lastCheckedAt)}`), node('small', `跟进：${formatDate(item.followedAt)}`));
      const statusData = maintenanceStatus(item); const statusCell = node('td'); statusCell.append(node('span', statusData.label, `update-status ${statusData.className}`)); if (item.lastError) statusCell.append(node('small', item.lastError));
      const access = node('td', '', 'component-access'); access.append(node('strong', modeLabels[item.integrationMode] || item.integrationMode));
      const scopeList = node('div', '', 'component-scope-list');
      for (const scope of item.usedBy || []) scopeList.append(node('span', scopeLabels[scope] || scope, 'component-scope-chip'));
      if (item.componentKind) scopeList.append(node('span', item.componentKind, 'component-scope-chip muted'));
      access.append(scopeList);
      const actions = node('td', '', 'action-column'); const group = node('div', '', 'inline-actions');
      if (item.latestVersion && item.followStatus === 'update_available') group.append(actionButton('标记已跟进', 'follow-project', 'success'), actionButton('忽略此版本', 'ignore-project'));
      if (['followed', 'ignored'].includes(item.followStatus)) group.append(actionButton('重置状态', 'reset-project'));
      actions.append(group); tr.append(project, access, versions, latest, times, statusCell, actions); body.append(tr);
    }
  }
  function renderMaintenanceSites(items) {
    const body = $('maintenance-sites-body'); body.replaceChildren();
    if (!items.length) return emptyRow(body, '尚无导航站运行清单。导航站启动后会在约 5 秒内首次上报。', 6);
    for (const item of items) {
      const tr = node('tr');
      const site = node('td'); site.append(node('strong', item.siteName || item.siteKey, 'site-name'), node('span', item.siteKey, 'site-key'));
      const app = node('td', '', 'version-stack'); app.append(node('span', item.appVersion || '尚未上报'), node('small', item.gitCommit ? `提交：${item.gitCommit.slice(0, 12)}` : '提交未知'));
      const runtime = node('td', '', 'version-stack'); runtime.append(node('span', item.nodeVersion || '—'), node('small', item.protocolCompatible ? item.protocolVersion : `${item.protocolVersion || '协议未知'} · 不兼容`));
      const components = node('td', '', 'version-stack');
      for (const component of (item.components || [])) {
        const versions = [component.packageVersion && `npm ${component.packageVersion}`, component.assetVersion && `资源 ${component.assetVersion}`].filter(Boolean).join(' · ');
        components.append(node('span', `${component.key}：${versions || '版本未知'}`));
        if (component.assetSha256) components.append(node('small', `SHA-256 ${component.assetSha256.slice(0, 16)}…`));
      }
      if (!(item.components || []).length) components.append(node('span', '尚无组件证明'));
      const reported = node('td', '', 'version-stack'); reported.append(node('span', formatDate(item.reportedAt)), node('small', item.stale ? '清单已过期' : '清单有效'));
      const advice = node('td', '', 'version-stack');
      advice.append(node('span', `${(item.advisories || []).length} 条更新建议`), node('small', `${(item.tests || []).length} 条最近测试结果`));
      for (const current of (item.advisories || []).slice(0, 2)) advice.append(node('small', `${current.project_name || current.project_key}：${current.installed_version || '未知'} → ${current.latest_version || '未知'}（${current.status}）`));
      tr.append(site, app, runtime, components, reported, advice); body.append(tr);
    }
  }
  async function loadMaintenance() {
    const [projects, sites] = await Promise.all([
      request('/admin/api/maintenance/projects'), request('/admin/api/maintenance/sites')
    ]);
    renderMaintenance(projects.data || []); renderMaintenanceSites(sites.data || []);
  }
  function analysisSince() {
    const hours = state.riskRange === '24h' ? 24 : state.riskRange === '7d' ? 7 * 24 : state.riskRange === '30d' ? 30 * 24 : 90 * 24;
    return new Date(Date.now() - hours * 60 * 60_000).toISOString();
  }
  function subjectFromKey(key) { const separator = key.indexOf(':'); return { siteKey: key.slice(0, separator), visitorHash: key.slice(separator + 1) }; }
  function analysisExportBody(subjects = []) {
    return { siteKey: $('suspect-site-filter').value, minScore: Number($('suspect-score-filter').value), since: analysisSince(), subjects, selectedOnly: true };
  }
  async function downloadAnalysis(subjects, fileName) {
    const blob = await requestBlob('/admin/api/analysis/export', analysisExportBody(subjects));
    const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = fileName; link.click(); URL.revokeObjectURL(url);
  }
  async function copyAnalysisPackage(subject) {
    const blob = await requestBlob('/admin/api/analysis/export', analysisExportBody([subject]));
    await navigator.clipboard.writeText(await blob.text()); toast('脱敏分析包已复制');
  }
  async function loadDriveSettings() {
    const result = await request('/admin/api/analysis/google-drive'); const data = result.data || {};
    $('drive-enabled').checked = Boolean(data.enabled); $('drive-prefix').value = data.filePrefix || 'risk-center';
    $('drive-range').value = data.backupRange || '7d'; $('drive-min-score').value = data.minScore ?? 25; $('drive-hour').value = data.backupHourBjt ?? 3;
    $('drive-oauth-client-id').value = data.oauthClientId || '';
    $('drive-oauth-client-secret').value = '';
    $('drive-oauth-client-secret').placeholder = data.oauthClientConfigured ? '已加密保存，留空保持不变' : '填写 Google OAuth Client Secret';
    $('drive-oauth-callback').value = data.oauthCallbackUrl || `${window.location.origin}/admin/api/analysis/google-drive/oauth/callback`;
    const selected = new Set(data.siteKeys || []); [...$('drive-sites').options].forEach(option => { option.selected = selected.has(option.value); });
    const status = $('drive-account-status');
    status.replaceChildren(
      node('strong', data.personalConnected ? `已连接：${data.connectedEmail || '个人 Google 账号'}` : '尚未连接个人 Google Drive'),
      node('span', data.personalConnected ? `备份位置：我的云端硬盘 / ${data.personalFolderName || '风险中心备份'}` : (data.oauthClientConfigured ? 'OAuth 配置已保存，请连接个人网盘。' : '请先保存 OAuth Client ID 与 Client Secret。'))
    );
    status.classList.toggle('connected', Boolean(data.personalConnected));
    $('connect-drive').textContent = data.personalConnected ? '重新授权' : '连接个人网盘';
    $('connect-drive').disabled = false;
    $('disconnect-drive').hidden = !data.personalConnected;
    $('open-drive-folder').hidden = !data.personalFolderUrl;
    if (data.personalFolderUrl) $('open-drive-folder').href = data.personalFolderUrl;
    $('test-drive').disabled = !data.personalConnected;
    $('backup-drive-now').disabled = !data.personalConnected;
    $('drive-last-status').textContent = data.lastError ? `最近错误：${data.lastError}` : (data.lastBackupAt ? `最近成功备份：${formatDate(data.lastBackupAt)} · 文件 ID ${data.lastFileId || '—'}` : '尚无备份记录。');
  }
  async function loadActiveTab() {
    if (state.activeTab === 'connections') await loadQuality();
    else if (state.activeTab === 'suspects') { await loadSuspects(); if ($('analysis-backup-details').open) await loadDriveSettings(); }
    else if (state.activeTab === 'detection') await loadDetection();
    else if (state.activeTab === 'rules') await Promise.all([loadRules(), loadIdentityLists()]);
    else if (state.activeTab === 'alerts') await loadAlerts();
    else if (state.activeTab === 'maintenance') await loadMaintenance();
    else if (state.activeTab === 'security') await loadSecurity();
    else if (state.activeTab === 'audits') await loadAudits();
  }
  async function loadDashboard() { await loadOverviewAndSites(); await loadActiveTab(); }
  function activateTab(name, load = true) {
    const tab = document.querySelector(`[data-tab="${name}"]`);
    if (!tab) return;
    state.activeTab = name;
    document.querySelectorAll('.tab').forEach(item => item.classList.toggle('active', item === tab));
    document.querySelectorAll('.tab-panel').forEach(panel => { panel.hidden = panel.id !== `panel-${name}`; });
    $('identity-rules-section').hidden = name !== 'rules';
    if (load) loadActiveTab().catch(error => toast(error.message));
  }

  $('login-form').addEventListener('submit', async event => { event.preventDefault(); const formElement = event.currentTarget; $('login-error').hidden = true; $('login-button').disabled = true; try { const form = new FormData(formElement); const result = await request('/admin/api/login', { method: 'POST', body: JSON.stringify({ username: String(form.get('username') || '').trim(), password: String(form.get('password') || '') }) }); state.csrf = result.data.csrfToken; formElement.reset(); setAuthenticated(true); activateTab(state.activeTab, false); await loadDashboard(); } catch (error) { $('login-error').textContent = error.message; $('login-error').hidden = false; } finally { $('login-button').disabled = false; } });
  $('logout-button').addEventListener('click', async () => { try { await request('/admin/api/logout', { method: 'POST' }); } catch {} state.csrf = ''; setAuthenticated(false); });
  $('refresh-button').addEventListener('click', () => loadDashboard().then(() => toast('数据已刷新')).catch(error => toast(error.message)));
  document.querySelector('.tabs').addEventListener('click', event => { const tab = event.target.closest('[data-tab]'); if (!tab) return; activateTab(tab.dataset.tab); });
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

  $('suspect-range-filter').addEventListener('change', event => { state.riskRange = event.currentTarget.value; state.suspectPage = 1; Promise.all([loadOverview(), loadSuspects()]).catch(error => toast(error.message)); }); $('suspect-site-filter').addEventListener('change', () => { state.suspectPage = 1; loadSuspects().catch(error => toast(error.message)); }); $('suspect-score-filter').addEventListener('change', () => { state.suspectPage = 1; loadSuspects().catch(error => toast(error.message)); }); $('suspect-prev').addEventListener('click', () => { state.suspectPage--; loadSuspects().catch(error => toast(error.message)); }); $('suspect-next').addEventListener('click', () => { state.suspectPage++; loadSuspects().catch(error => toast(error.message)); });
  $('suspects-body').addEventListener('change', event => { const checkbox = event.target.closest('[data-select-suspect]'); if (!checkbox) return; if (checkbox.checked) state.selectedSuspects.add(checkbox.dataset.selectSuspect); else state.selectedSuspects.delete(checkbox.dataset.selectSuspect); $('export-analysis-selected').disabled = state.selectedSuspects.size === 0; const pageBoxes = [...$('suspects-body').querySelectorAll('[data-select-suspect]')]; $('select-all-suspects').checked = pageBoxes.length > 0 && pageBoxes.every(item => item.checked); $('select-all-suspects').indeterminate = pageBoxes.some(item => item.checked) && !$('select-all-suspects').checked; });
  $('suspects-body').addEventListener('click', event => { const button = event.target.closest('[data-action]'); const row = button?.closest('tr'); if (!row) return; if (button.dataset.action === 'view-suspect') openSuspect(row.dataset.siteKey, row.dataset.visitorHash).catch(error => toast(error.message)); if (button.dataset.action === 'copy-analysis-package') copyAnalysisPackage({ siteKey: row.dataset.siteKey, visitorHash: row.dataset.visitorHash }).catch(error => toast(error.message)); });
  $('select-all-suspects').addEventListener('change', event => { for (const checkbox of $('suspects-body').querySelectorAll('[data-select-suspect]')) { checkbox.checked = event.currentTarget.checked; if (checkbox.checked) state.selectedSuspects.add(checkbox.dataset.selectSuspect); else state.selectedSuspects.delete(checkbox.dataset.selectSuspect); } $('export-analysis-selected').disabled = state.selectedSuspects.size === 0; });
  $('generate-analysis-token').addEventListener('click', async () => { try { const siteKeys = $('suspect-site-filter').value ? [$('suspect-site-filter').value] : state.sites.map(site => site.siteKey); const result = await request('/admin/api/analysis/token', { method: 'POST', body: JSON.stringify({ siteKeys }) }); $('analysis-list-url').value = result.data.listUrl; $('analysis-token').value = result.data.token; $('analysis-token-meta').value = `有效至 ${formatDate(result.data.expiresAt)} · 最多 ${result.data.maxUses} 次`; $('analysis-token-box').hidden = false; toast(result.message); } catch (error) { toast(error.message); } });
  $('copy-analysis-endpoint').addEventListener('click', async () => { await navigator.clipboard.writeText(`${window.location.origin}/v1/analysis/suspects`); toast('只读分析接口已复制'); });
  $('copy-analysis-access').addEventListener('click', async () => { const value = `请分析以下疑似访客，只提供判断和处置建议，不执行任何修改。\n\n接口：${$('analysis-list-url').value}\n临时令牌：${$('analysis-token').value}\n令牌有效期：15 分钟\nAuthorization: Bearer ${$('analysis-token').value}`; await navigator.clipboard.writeText(value); toast('完整只读接入信息已复制'); });
  $('export-analysis-page').addEventListener('click', () => downloadAnalysis(state.suspectItems.map(item => ({ siteKey: item.siteKey, visitorHash: item.visitorHash })), 'risk-analysis-page.json').then(() => toast('本页脱敏分析包已导出')).catch(error => toast(error.message)));
  $('export-analysis-selected').addEventListener('click', () => downloadAnalysis([...state.selectedSuspects].map(subjectFromKey), 'risk-analysis-selected.json').then(() => toast('选中访客脱敏分析包已导出')).catch(error => toast(error.message)));
  $('suspect-permanent').addEventListener('change', event => { $('suspect-duration').disabled = event.currentTarget.checked; });
  $('suspect-apply-all-sites').addEventListener('change', event => { $('suspect-rule-signal').disabled = !event.currentTarget.checked; });
  $('suspect-action-form').addEventListener('submit', async event => { event.preventDefault(); if (!state.currentSuspect) return; const applyToAllSites = $('suspect-apply-all-sites').checked; const ruleSignal = $('suspect-rule-signal').value; if (applyToAllSites && !confirm(`将把风险信号“${ruleSignal}”的同类处置应用到所有接入站点，确定继续吗？`)) return; try { const { siteKey, visitorHash } = state.currentSuspect; const result = await request(`/admin/api/risk/suspects/${encodeURIComponent(siteKey)}/${visitorHash}/action`, { method: 'POST', body: JSON.stringify({ action: $('suspect-action').value, durationMinutes: Number($('suspect-duration').value), permanent: $('suspect-permanent').checked, reason: $('suspect-reason').value.trim(), applyToAllSites, ruleSignal: applyToAllSites ? ruleSignal : '' }) }); $('suspect-dialog').close(); toast(result.message || ($('suspect-permanent').checked ? '永久人工处置已生效' : '人工处置已生效')); await loadSuspects(); } catch (error) { toast(error.message); } });
  $('clear-suspect-action').addEventListener('click', async () => { if (!state.currentSuspect) return; const { siteKey, visitorHash } = state.currentSuspect; try { await request(`/admin/api/risk/suspects/${encodeURIComponent(siteKey)}/${visitorHash}/action`, { method: 'DELETE' }); $('suspect-dialog').close(); toast('人工处置已解除'); await loadSuspects(); } catch (error) { toast(error.message); } });

  $('rule-scope').addEventListener('change', event => { const anySite = event.currentTarget.value === 'all'; $('rule-site').disabled = anySite; $('rule-site').required = !anySite; });
  $('rule-permanent').addEventListener('change', event => { $('rule-duration').disabled = event.currentTarget.checked; $('rule-duration').required = !event.currentTarget.checked; });
  $('preview-rule').addEventListener('click', async () => { try { const siteKey = $('rule-scope').value === 'all' ? '*' : $('rule-site').value; const query = new URLSearchParams({ siteKey, signal: $('rule-signal').value.trim() }); const result = await request(`/admin/api/risk/rules/preview?${query}`); $('rule-preview-result').textContent = `近 24 小时将影响 ${result.data.visitors24h} 个访客、${result.data.events24h} 次事件。`; } catch (error) { toast(error.message); } });
  $('rule-form').addEventListener('submit', async event => { event.preventDefault(); try { const siteKey = $('rule-scope').value === 'all' ? '*' : $('rule-site').value; await request('/admin/api/risk/rules', { method: 'POST', body: JSON.stringify({ siteKey, signal: $('rule-signal').value.trim(), action: $('rule-action').value, mode: $('rule-mode').value, permanent: $('rule-permanent').checked, durationMinutes: $('rule-permanent').checked ? null : Number($('rule-duration').value), reason: $('rule-reason').value.trim() }) }); toast($('rule-mode').value === 'shadow' ? '影子规则已创建，不会执行处置' : '正式规则已创建'); $('rule-signal').value = ''; $('rule-reason').value = ''; $('rule-permanent').checked = false; $('rule-duration').disabled = false; $('rule-duration').required = true; await loadRules(); } catch (error) { toast(error.message); } });
  $('rules-body').addEventListener('click', async event => { const button = event.target.closest('[data-action]'); const row = button?.closest('tr'); if (!row) return; try { if (button.dataset.action === 'delete-rule') { if (!confirm('确定删除该规则吗？修订历史仍会保留。')) return; await request(`/admin/api/risk/rules/${row.dataset.ruleId}`, { method: 'DELETE' }); } else { const enabled = row.children[5].textContent !== '已启用'; await request(`/admin/api/risk/rules/${row.dataset.ruleId}/status`, { method: 'PUT', body: JSON.stringify({ enabled }) }); } await loadRules(); toast('规则已更新'); } catch (error) { toast(error.message); } });
  $('policy-form').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const result = await request('/admin/api/risk/policies', { method: 'POST', body: JSON.stringify({
        name: $('policy-name').value.trim(), version: $('policy-version').value.trim(), thresholds: {
          observe: Number($('policy-observe').value), silentChallenge: Number($('policy-silent').value),
          strongChallenge: Number($('policy-strong').value), deny: Number($('policy-deny').value)
        }
      }) });
      toast(result.message); $('policy-version').value = ''; await loadRules();
    } catch (error) { toast(error.message); }
  });
  $('policies-body').addEventListener('click', async event => {
    const button = event.target.closest('[data-action="activate-policy"]'); const row = button?.closest('tr'); if (!row) return;
    if (!confirm('启用该策略版本后，所有未指定独立策略的站点会立即使用它。确定继续吗？')) return;
    try { const result = await request(`/admin/api/risk/policies/${row.dataset.policyId}/activate`, { method: 'POST' }); toast(result.message); await loadRules(); }
    catch (error) { toast(error.message); }
  });

  installIdentityControls();
  installMaintenanceScopeFilter();
  $('detection-range').addEventListener('change', () => loadDetection().catch(error => toast(error.message)));
  $('quality-range').addEventListener('change', () => loadQuality().catch(error => toast(error.message)));
  $('identity-validity').addEventListener('change', event => {
    const custom = event.currentTarget.value === 'custom'; $('identity-duration').hidden = !custom;
    $('identity-permanent').checked = event.currentTarget.value === '0';
    if (!custom && event.currentTarget.value !== '0') $('identity-duration').value = event.currentTarget.value;
  });
  $('identity-subject-type').addEventListener('change', event => {
    const help = { visitor: '填写风险中心显示的访客摘要，区分大小写。', bot_identity: '例如 Googlebot、GPTBot；保存时会转为小写。', ua: '填写稳定且尽量具体的 User-Agent 片段。', ja4: '填写完整 JA4 指纹。', asn: '只填写数字，例如 15169。' };
    $('identity-subject-help').textContent = help[event.currentTarget.value] || '';
  });
  $('identity-form').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      $('identity-form-error').textContent = '';
      const subjectHash = $('identity-subject').value.trim(); const reason = $('identity-reason').value.trim();
      if (!subjectHash || reason.length < 2) { $('identity-form-error').textContent = '请填写有效对象值和至少 2 个字的处置原因。'; return; }
      const path = state.editingIdentity ? `/admin/api/detection/identity-lists/${state.editingIdentity.listType}/${state.editingIdentity.id}` : '/admin/api/detection/identity-lists';
      const result = await request(path, { method: state.editingIdentity ? 'PUT' : 'POST', body: JSON.stringify({
        listType: $('identity-list-type').value, siteKey: $('identity-site').value,
        subjectType: $('identity-subject-type').value, subjectHash,
        reason, permanent: $('identity-permanent').checked,
        durationMinutes: Number($('identity-duration').value)
      }) });
      toast(result.message); resetIdentityEditor(); await loadIdentityLists();
    } catch (error) { $('identity-form-error').textContent = error.message; toast(error.message); }
  });
  $('identity-body').addEventListener('click', async event => {
    const button = event.target.closest('[data-action]'); const row = button?.closest('tr'); if (!row) return;
    const item = state.identityItems.find(entry => String(entry.id) === row.dataset.id && entry.listType === row.dataset.listType); if (!item) return;
    if (button.dataset.action === 'edit-identity') {
      state.editingIdentity = item; $('identity-list-type').value=item.listType; $('identity-list-type').disabled=true; $('identity-site').value=item.siteKey; $('identity-subject-type').value=item.subjectType; $('identity-subject').value=item.subjectHash; $('identity-reason').value=item.reason || '';
      $('identity-validity').value = item.expiresAt ? 'custom' : '0'; $('identity-permanent').checked=!item.expiresAt; $('identity-duration').hidden=!item.expiresAt; $('identity-duration').value=item.expiresAt ? String(Math.max(1,Math.ceil((new Date(item.expiresAt).getTime()-Date.now())/60000))) : '60'; $('identity-submit').textContent='保存修改'; $('identity-cancel-edit').hidden=false; $('identity-subject').focus(); return;
    }
    if (button.dataset.action === 'toggle-identity') { try { const result=await request(`/admin/api/detection/identity-lists/${item.listType}/${item.id}/toggle`,{method:'POST'}); toast(result.message); await loadIdentityLists(); } catch(error){toast(error.message);} return; }
    if (button.dataset.action !== 'delete-identity' || !confirm('确定删除该名单项吗？该操作会写入审计日志。')) return;
    try { await request(`/admin/api/detection/identity-lists/${row.dataset.listType}/${row.dataset.id}`, { method: 'DELETE' }); toast('名单项已删除'); await loadIdentityLists(); }
    catch (error) { toast(error.message); }
  });
  $('identity-cancel-edit').addEventListener('click', resetIdentityEditor);
  for (const id of ['identity-filter-list','identity-filter-site','identity-filter-subject','identity-filter-status']) $(id).addEventListener('change', () => { state.identityPage=1; loadIdentityLists().catch(error=>toast(error.message)); });
  let identitySearchTimer; $('identity-filter-keyword').addEventListener('input', () => { clearTimeout(identitySearchTimer); identitySearchTimer=setTimeout(()=>{state.identityPage=1; loadIdentityLists().catch(error=>toast(error.message));},250); });
  $('identity-prev').addEventListener('click',()=>{if(state.identityPage>1){state.identityPage-=1;loadIdentityLists().catch(error=>toast(error.message));}});
  $('identity-next').addEventListener('click',()=>{state.identityPage+=1;loadIdentityLists().catch(error=>toast(error.message));});

  $('credential-form').addEventListener('submit', async event => {
    event.preventDefault();
    const nextPassword = $('security-new-password').value;
    if (nextPassword !== $('security-confirm-password').value) return toast('两次输入的新密码不一致');
    if (!confirm('修改后所有设备（包括当前设备）都会退出，确定继续吗？')) return;
    try {
      const result = await request('/admin/api/security/credentials', { method: 'PUT', body: JSON.stringify({
        currentPassword: $('security-current-password').value,
        username: $('security-username').value.trim(), newPassword: nextPassword
      }) });
      toast(result.message); setTimeout(() => { setAuthenticated(false); }, 600);
    } catch (error) { toast(error.message); }
  });
  $('github-token-form').addEventListener('submit', async event => {
    event.preventDefault();
    const token = $('github-token').value.trim();
    if (!token) return toast('请填入 GitHub API Token');
    const button = event.currentTarget.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      const result = await request('/admin/api/security/github-token', { method: 'PUT', body: JSON.stringify({ token }) });
      $('github-token').value = '';
      toast(result.message);
      await loadSecurity();
    } catch (error) { toast(error.message); }
    finally { button.disabled = false; }
  });
  $('security-sessions-body').addEventListener('click', async event => {
    const button = event.target.closest('[data-action="revoke-session"]'); const row = button?.closest('tr'); if (!row) return;
    if (!confirm('确定撤销这个登录会话吗？')) return;
    try { const result = await request(`/admin/api/security/sessions/${row.dataset.sessionId}`, { method: 'DELETE' }); toast(result.message); if (result.data.current) setAuthenticated(false); else await loadSecurity(); }
    catch (error) { toast(error.message); }
  });
  $('revoke-other-sessions').addEventListener('click', async () => {
    if (!confirm('确定让其他所有登录设备下线吗？当前设备会保留。')) return;
    try { const result = await request('/admin/api/security/sessions/revoke-others', { method: 'POST' }); toast(result.message); await loadSecurity(); }
    catch (error) { toast(error.message); }
  });
  $('revoke-all-sessions').addEventListener('click', async () => {
    if (!confirm('确定让所有登录设备（包括当前设备）立即下线吗？')) return;
    try {
      const result = await request('/admin/api/security/sessions/revoke-all', { method: 'POST' });
      toast(result.message); setTimeout(() => { setAuthenticated(false); }, 600);
    } catch (error) { toast(error.message); }
  });

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
  $('rule-backup-form').addEventListener('submit', async event => {
    event.preventDefault();
    try {
      const result = await request('/admin/api/rule-backups/settings', { method: 'PUT', body: JSON.stringify({
        enabled: $('rule-backup-enabled').checked,
        automaticOnChange: $('rule-backup-on-change').checked,
        telegramToken: $('rule-backup-token').value.trim(),
        telegramChatId: $('rule-backup-chat').value.trim(),
        backupHourBjt: numberValue('rule-backup-hour'),
        partSizeMiB: numberValue('rule-backup-part-size')
      }) });
      toast(result.message); await loadAlerts();
    } catch (error) { toast(error.message); }
  });
  async function ruleBackupAction(button, path, loadingText) {
    const original = button.textContent; button.disabled = true; button.textContent = loadingText;
    try { const result = await request(path, { method: 'POST' }); toast(result.message); await loadAlerts(); }
    catch (error) { toast(error.message); }
    finally { button.disabled = false; button.textContent = original; }
  }
  $('test-rule-backup').addEventListener('click', event => ruleBackupAction(event.currentTarget, '/admin/api/rule-backups/test', '测试中…'));
  $('run-rule-backup').addEventListener('click', event => ruleBackupAction(event.currentTarget, '/admin/api/rule-backups/run', '备份中…'));
  $('retry-rule-backup').addEventListener('click', event => ruleBackupAction(event.currentTarget, '/admin/api/rule-backups/retry', '重试中…'));

  async function saveDriveSettings(showToast = true) {
    const result = await request('/admin/api/analysis/google-drive', { method: 'PUT', body: JSON.stringify({
      enabled: $('drive-enabled').checked,
      filePrefix: $('drive-prefix').value.trim(),
      backupRange: $('drive-range').value,
      minScore: Number($('drive-min-score').value),
      backupHourBjt: Number($('drive-hour').value),
      siteKeys: [...$('drive-sites').selectedOptions].map(option => option.value),
      oauthClientId: $('drive-oauth-client-id').value.trim(),
      oauthClientSecret: $('drive-oauth-client-secret').value.trim()
    }) });
    if (showToast) toast(result.message);
    await loadDriveSettings();
    return result;
  }
  installDriveCallbackCopyControl();
  $('drive-form').addEventListener('submit', event => { event.preventDefault(); saveDriveSettings().catch(error => toast(error.message)); });
  async function driveAction(button, path, loadingText) { const original = button.textContent; button.disabled = true; button.textContent = loadingText; try { const result = await request(path, { method: 'POST' }); toast(result.message); await loadDriveSettings(); } catch (error) { toast(error.message); } finally { button.disabled = false; button.textContent = original; } }
  $('test-drive').addEventListener('click', event => driveAction(event.currentTarget, '/admin/api/analysis/google-drive/test', '测试中…'));
  $('backup-drive-now').addEventListener('click', event => driveAction(event.currentTarget, '/admin/api/analysis/google-drive/backup', '备份中…'));
  $('analysis-backup-details').addEventListener('toggle', event => {
    event.currentTarget.querySelector('.details-state').textContent = event.currentTarget.open ? '收起设置' : '展开设置';
    if (event.currentTarget.open) loadDriveSettings().catch(error => toast(error.message));
  });
  $('connect-drive').addEventListener('click', async event => {
    const button = event.currentTarget; const original = button.textContent; button.disabled = true; button.textContent = '准备授权…';
    try {
      await saveDriveSettings(false);
      const result = await request('/admin/api/analysis/google-drive/connect', { method: 'POST' });
      window.location.assign(result.data.authorizationUrl);
    } catch (error) { toast(error.message); button.disabled = false; button.textContent = original; }
  });
  $('disconnect-drive').addEventListener('click', async event => {
    if (!confirm('确定断开个人 Google Drive 吗？自动备份会同时关闭，网盘中的历史文件不会被删除。')) return;
    await driveAction(event.currentTarget, '/admin/api/analysis/google-drive/disconnect', '正在断开…');
  });

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
  request('/admin/api/session').then(async result => {
    state.csrf = result.data.csrfToken; setAuthenticated(true); activateTab(state.activeTab, false); await loadDashboard();
    const driveResult = new URLSearchParams(window.location.search).get('drive');
    if (driveResult) {
      $('analysis-backup-details').open = true;
      toast(driveResult === 'connected' ? '个人 Google Drive 已连接' : 'Google Drive 授权失败，请查看最近错误');
      history.replaceState(null, '', `${window.location.pathname}#suspects`);
    }
  }).catch(() => setAuthenticated(false));
})();
