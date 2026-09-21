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
      box.append(node('span', `${signalLabel(item.signal)} ×${item.count}${score ? ` (${score > 0 ? '+' : ''}${score})` : ''}`, `signal-chip ${score < 0 ? 'positive' : ''}`));
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
    for (const item of data.items) { const tr = node('tr'); tr.dataset.siteKey = item.siteKey; tr.dataset.visitorHash = item.visitorHash; const who = node('td'); who.append(node('strong', item.siteName), node('span', `${item.visitorHash.slice(0, 12)}…`, 'site-key')); const decision = node('td'); decision.append(chip(item.manualAction ? `人工：${item.manualAction}` : item.decision, !['deny', 'strong_challenge'].includes(item.manualAction || item.decision))); const reasons = node('td', '', 'reason-cell'); reasons.append(...(item.reasons || []).slice(0, 3).map(reason => node('span', reasonLabel(reason)))); const signalItems = (item.signals || []).length ? item.signals : (item.reasons || []).filter(reason => !String(reason).startsWith('manual_')).map(signal => ({ signal, count: 1, scoreImpact: 0 })); const signals = node('td'); signals.append(renderSignalChips(signalItems)); const action = node('td', '', 'action-column'); action.append(actionButton('查看证据 / 处置', 'view-suspect')); tr.append(who, node('td', String(item.score), 'numeric'), decision, reasons, signals, node('td', String(item.eventCount), 'numeric'), node('td', formatDate(item.lastSeen)), action); body.append(tr); }
    const pages = Math.max(1, Math.ceil(data.total / data.limit)); $('suspect-page').textContent = `第 ${data.page} / ${pages} 页 · 共 ${data.total} 人`; $('suspect-prev').disabled = data.page <= 1; $('suspect-next').disabled = data.page >= pages;
  }

  async function openSuspect(siteKey, visitorHash) {
    const result = await request(`/admin/api/risk/suspects/${encodeURIComponent(siteKey)}/${visitorHash}`); const data = result.data; state.currentSuspect = { siteKey, visitorHash };
    $('suspect-title').textContent = `${data.siteName} · ${visitorHash.slice(0, 12)}…`;
    $('suspect-overview').replaceChildren(...[['风险分', data.score], ['当前结论', data.decision], ['详细原因', (data.reasons || []).map(reasonLabel).join('；') || '无']].map(([label, value]) => { const box = node('article'); box.append(node('span', label), node('strong', String(value))); return box; }));
    $('suspect-signal-details').replaceChildren(...(data.signals || []).map(signal => { const box = node('article'); const score = Number(signal.scoreImpact) || 0; box.append(node('strong', signalLabel(signal.signal)), node('span', `${signal.count} 次 · 分值影响 ${score > 0 ? '+' : ''}${score} · 最近 ${formatDate(signal.lastSeen)}`)); return box; }));
    $('suspect-events').replaceChildren(...data.events.map(event => { const item = node('article', '', 'event-item'); item.append(node('code', event.eventType), node('span', ` · ${formatDate(event.occurredAt)}`), node('pre', JSON.stringify(event.evidence || {}, null, 2))); return item; }));
    $('suspect-reason').value = ''; $('suspect-permanent').checked = false; $('suspect-duration').disabled = false; $('suspect-dialog').showModal();
  }

  async function loadRules() { const result = await request('/admin/api/risk/rules'); const body = $('rules-body'); body.replaceChildren(); if (!result.data.length) return emptyRow(body, '尚未配置人工信号规则。', 6); for (const rule of result.data) { const tr = node('tr'); tr.dataset.ruleId = rule.id; const actions = node('td', '', 'action-column'); const group = node('div', '', 'inline-actions'); group.append(actionButton(rule.enabled ? '停用' : '启用', 'toggle-rule', rule.enabled ? 'danger' : 'success'), actionButton('删除', 'delete-rule', 'danger')); actions.append(group); tr.append(node('td', rule.scope === 'all' ? '任意站点' : rule.siteName), node('td', `${signalLabel(rule.signal)}\n${rule.signal}`), node('td', rule.action), node('td', rule.permanent ? '永久' : `${rule.durationMinutes} 分钟`), node('td', rule.enabled ? '已启用' : '已停用'), actions); body.append(tr); } }
  async function loadAudits() { const result = await request('/admin/api/audits?limit=100'); const body = $('audits-body'); body.replaceChildren(); if (!result.data.length) return emptyRow(body, '尚无管理操作记录。', 5); for (const item of result.data) { const tr = node('tr'); tr.append(node('td', formatDate(item.createdAt)), node('td', item.action), node('td', item.target), node('td', item.actor), node('td', JSON.stringify(item.details))); body.append(tr); } }
  async function loadActiveTab() { if (state.activeTab === 'suspects') await loadSuspects(); else if (state.activeTab === 'rules') await loadRules(); else if (state.activeTab === 'audits') await loadAudits(); }
  async function loadDashboard() { await loadOverviewAndSites(); await loadActiveTab(); }

  $('login-form').addEventListener('submit', async event => { event.preventDefault(); const formElement = event.currentTarget; $('login-error').hidden = true; $('login-button').disabled = true; try { const form = new FormData(formElement); const result = await request('/admin/api/login', { method: 'POST', body: JSON.stringify({ username: String(form.get('username') || '').trim(), password: String(form.get('password') || '') }) }); state.csrf = result.data.csrfToken; formElement.reset(); setAuthenticated(true); await loadDashboard(); } catch (error) { $('login-error').textContent = error.message; $('login-error').hidden = false; } finally { $('login-button').disabled = false; } });
  $('logout-button').addEventListener('click', async () => { try { await request('/admin/api/logout', { method: 'POST' }); } catch {} state.csrf = ''; setAuthenticated(false); });
  $('refresh-button').addEventListener('click', () => loadDashboard().then(() => toast('数据已刷新')).catch(error => toast(error.message)));
  document.querySelector('.tabs').addEventListener('click', event => { const tab = event.target.closest('[data-tab]'); if (!tab) return; state.activeTab = tab.dataset.tab; document.querySelectorAll('.tab').forEach(item => item.classList.toggle('active', item === tab)); document.querySelectorAll('.tab-panel').forEach(panel => { panel.hidden = panel.id !== `panel-${state.activeTab}`; }); loadActiveTab().catch(error => toast(error.message)); });
  document.addEventListener('click', event => { const button = event.target.closest('[data-close-dialog]'); if (button) $(button.dataset.closeDialog).close(); });
  $('add-integration').addEventListener('click', () => openIntegration());
  $('integration-form').addEventListener('submit', async event => { event.preventDefault(); const urls = $('integration-urls').value.split(/\r?\n/).map(value => value.trim()).filter(Boolean).map((url, index) => ({ url, isPrimary: index === 0 })); try { const result = await request('/admin/api/integrations', { method: 'POST', body: JSON.stringify({ name: $('integration-name').value.trim(), siteKey: $('integration-site-key').value.trim(), clientId: $('integration-client-id').value.trim(), transport: $('integration-transport').value, urls, collectionEnabled: $('integration-collection').checked, enforcementEnabled: $('integration-enforcement').checked, enforcementMode: $('integration-mode').value }) }); $('integration-dialog').close(); if (result.data.secret) showSecret(result.data); toast(result.message); await loadOverviewAndSites(); } catch (error) { toast(error.message); } });
  $('copy-secret').addEventListener('click', async () => { await navigator.clipboard.writeText(`BOT_RISK_URL=${$('secret-endpoint').value}\nBOT_RISK_CLIENT_ID=${$('secret-client').value}\nBOT_RISK_HMAC_SECRET=${$('secret-value').value}`); toast('接入信息已复制'); });

  $('sites-body').addEventListener('click', async event => { const button = event.target.closest('[data-action]'); if (!button) return; const site = state.sites.find(item => item.siteKey === button.closest('tr')?.dataset.siteKey); if (!site) return; try { if (button.dataset.action === 'edit-site') return openIntegration(site); if (button.dataset.action === 'add-client') return openIntegration(site, true); if (button.dataset.action === 'toggle-site') { if (site.enabled && !confirm(`确定关闭 ${site.name} 的总对接吗？`)) return; await request(`/admin/api/sites/${encodeURIComponent(site.siteKey)}/status`, { method: 'PUT', body: JSON.stringify({ enabled: !site.enabled }) }); } else if (button.dataset.action === 'toggle-client') { const client = site.clients.find(item => item.clientId === button.dataset.id); await request(`/admin/api/clients/${encodeURIComponent(client.clientId)}/status`, { method: 'PUT', body: JSON.stringify({ enabled: !client.enabled }) }); } else if (button.dataset.action === 'rotate-client') { if (!confirm('轮换后旧密钥会立即失效，确定继续吗？')) return; const result = await request(`/admin/api/clients/${encodeURIComponent(button.dataset.id)}/rotate`, { method: 'POST' }); showSecret(result.data); } toast('配置已更新'); await loadOverviewAndSites(); } catch (error) { toast(error.message); } });

  $('suspect-site-filter').addEventListener('change', () => { state.suspectPage = 1; loadSuspects().catch(error => toast(error.message)); }); $('suspect-score-filter').addEventListener('change', () => { state.suspectPage = 1; loadSuspects().catch(error => toast(error.message)); }); $('suspect-prev').addEventListener('click', () => { state.suspectPage--; loadSuspects().catch(error => toast(error.message)); }); $('suspect-next').addEventListener('click', () => { state.suspectPage++; loadSuspects().catch(error => toast(error.message)); });
  $('suspects-body').addEventListener('click', event => { const button = event.target.closest('[data-action="view-suspect"]'); const row = button?.closest('tr'); if (row) openSuspect(row.dataset.siteKey, row.dataset.visitorHash).catch(error => toast(error.message)); });
  $('suspect-permanent').addEventListener('change', event => { $('suspect-duration').disabled = event.currentTarget.checked; });
  $('suspect-action-form').addEventListener('submit', async event => { event.preventDefault(); if (!state.currentSuspect) return; try { const { siteKey, visitorHash } = state.currentSuspect; await request(`/admin/api/risk/suspects/${encodeURIComponent(siteKey)}/${visitorHash}/action`, { method: 'POST', body: JSON.stringify({ action: $('suspect-action').value, durationMinutes: Number($('suspect-duration').value), permanent: $('suspect-permanent').checked, reason: $('suspect-reason').value.trim() }) }); $('suspect-dialog').close(); toast($('suspect-permanent').checked ? '永久人工处置已生效' : '人工处置已生效'); await loadSuspects(); } catch (error) { toast(error.message); } });
  $('clear-suspect-action').addEventListener('click', async () => { if (!state.currentSuspect) return; const { siteKey, visitorHash } = state.currentSuspect; try { await request(`/admin/api/risk/suspects/${encodeURIComponent(siteKey)}/${visitorHash}/action`, { method: 'DELETE' }); $('suspect-dialog').close(); toast('人工处置已解除'); await loadSuspects(); } catch (error) { toast(error.message); } });

  $('rule-scope').addEventListener('change', event => { const anySite = event.currentTarget.value === 'all'; $('rule-site').disabled = anySite; $('rule-site').required = !anySite; });
  $('rule-permanent').addEventListener('change', event => { $('rule-duration').disabled = event.currentTarget.checked; $('rule-duration').required = !event.currentTarget.checked; });
  $('preview-rule').addEventListener('click', async () => { try { const siteKey = $('rule-scope').value === 'all' ? '*' : $('rule-site').value; const query = new URLSearchParams({ siteKey, signal: $('rule-signal').value.trim() }); const result = await request(`/admin/api/risk/rules/preview?${query}`); $('rule-preview-result').textContent = `近 24 小时将影响 ${result.data.visitors24h} 个访客、${result.data.events24h} 次事件。`; } catch (error) { toast(error.message); } });
  $('rule-form').addEventListener('submit', async event => { event.preventDefault(); try { const siteKey = $('rule-scope').value === 'all' ? '*' : $('rule-site').value; await request('/admin/api/risk/rules', { method: 'POST', body: JSON.stringify({ siteKey, signal: $('rule-signal').value.trim(), action: $('rule-action').value, permanent: $('rule-permanent').checked, durationMinutes: $('rule-permanent').checked ? null : Number($('rule-duration').value), reason: $('rule-reason').value.trim() }) }); toast('规则已创建'); $('rule-signal').value = ''; $('rule-reason').value = ''; $('rule-permanent').checked = false; $('rule-duration').disabled = false; $('rule-duration').required = true; await loadRules(); } catch (error) { toast(error.message); } });
  $('rules-body').addEventListener('click', async event => { const button = event.target.closest('[data-action]'); const row = button?.closest('tr'); if (!row) return; try { if (button.dataset.action === 'delete-rule') { if (!confirm('确定删除该规则吗？')) return; await request(`/admin/api/risk/rules/${row.dataset.ruleId}`, { method: 'DELETE' }); } else { const enabled = row.children[4].textContent !== '已启用'; await request(`/admin/api/risk/rules/${row.dataset.ruleId}/status`, { method: 'PUT', body: JSON.stringify({ enabled }) }); } await loadRules(); toast('规则已更新'); } catch (error) { toast(error.message); } });

  request('/admin/api/session').then(result => { state.csrf = result.data.csrfToken; setAuthenticated(true); return loadDashboard(); }).catch(() => setAuthenticated(false));
})();
