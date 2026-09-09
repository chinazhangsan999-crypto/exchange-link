/** 站点风控监控：量化诊断、环境画像、连续审核与快捷决策。 */
(() => {
  if (!document.querySelector('link[href^="/admin/monitor.css"]')) {
    const stylesheet = document.createElement('link');
    stylesheet.rel = 'stylesheet';
    stylesheet.href = '/admin/monitor.css?v=20260910-wide-client-audit';
    document.head.append(stylesheet);
  }

  const token = () => localStorage.getItem('webring_admin_token') || '';
  const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[character]));
  const state = { currentId: null, requestSequence: 0, clients: [], clientFilter: 'all', clientQuery: '' };

  function toast(message) {
    const element = document.querySelector('#toast');
    if (!element) return alert(message);
    element.textContent = message;
    element.classList.add('show');
    setTimeout(() => element.classList.remove('show'), 2400);
  }

  async function api(url, options = {}) {
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token()}`,
        ...(options.headers || {})
      }
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok || result.code !== 200) throw new Error(result.msg || `请求失败 (${response.status})`);
    return result.data;
  }

  function closeDialog() {
    document.querySelector('#analytics-modal')?.classList.remove('open');
  }

  function suspiciousIds() {
    return [...document.querySelectorAll('#suspicious-body .see-risk[data-id]')]
      .map(button => Number(button.dataset.id))
      .filter((id, index, ids) => Number.isInteger(id) && id > 0 && ids.indexOf(id) === index);
  }

  function adjacentIds(currentId = state.currentId) {
    const ids = suspiciousIds();
    const index = ids.indexOf(Number(currentId));
    return {
      ids,
      previousId: index > 0 ? ids[index - 1] : null,
      nextId: index >= 0 && index < ids.length - 1 ? ids[index + 1] : null
    };
  }

  function renderNavigation() {
    const container = document.querySelector('#analytics-navigation');
    if (!container) return;
    const { ids, previousId, nextId } = adjacentIds();
    const currentIndex = ids.indexOf(Number(state.currentId));
    container.innerHTML = `
      <button type="button" class="action analytics-nav-button" data-nav-id="${previousId || ''}" ${previousId ? '' : 'disabled'}>◀ 上一个</button>
      <span class="analytics-nav-progress">${currentIndex >= 0 ? `${currentIndex + 1} / ${ids.length}` : '单站查看'}</span>
      <button type="button" class="action analytics-nav-button" data-nav-id="${nextId || ''}" ${nextId ? '' : 'disabled'}>下一个 ▶</button>`;
  }

  function ensureDialog() {
    let modal = document.querySelector('#analytics-modal');
    if (modal) return modal;
    modal = document.createElement('div');
    modal.id = 'analytics-modal';
    modal.className = 'modal analytics-modal';
    modal.innerHTML = `
      <div class="dialog analytics-dialog" role="dialog" aria-modal="true" aria-labelledby="analytics-dialog-title">
        <div class="box-head analytics-dialog-head">
          <div>
            <h3 class="analytics-dialog-title" id="analytics-dialog-title">站点风控监控</h3>
            <p class="hint analytics-name-hint" id="analytics-name"></p>
          </div>
          <div class="analytics-head-actions">
            <div class="analytics-navigation" id="analytics-navigation"></div>
            <button type="button" class="action" id="close-analytics">关闭</button>
          </div>
        </div>
        <div id="analytics-content"></div>
        <div class="dialog-foot analytics-decision-bar" id="analytics-decision-bar">
          <button type="button" class="button danger" data-decision="disable">🚫 禁用/拉黑</button>
          <button type="button" class="button ghost" data-decision="sandbox">📉 降权/沙盒</button>
          <button type="button" class="button ghost" data-decision="clear">🗑️ 清空该站流量</button>
          <button type="button" class="button" data-decision="approve">✅ 审核通过</button>
          <button type="button" class="button whitelist-button" data-decision="whitelist">🛡️ 加入白名单 (免检)</button>
        </div>
      </div>`;
    document.body.append(modal);
    modal.querySelector('#close-analytics').addEventListener('click', closeDialog);
    modal.addEventListener('click', event => { if (event.target === modal) closeDialog(); });
    modal.querySelector('#analytics-navigation').addEventListener('click', event => {
      const button = event.target.closest('.analytics-nav-button[data-nav-id]');
      const id = Number(button?.dataset.navId);
      if (button && !button.disabled && Number.isInteger(id) && id > 0) showAnalytics(id);
    });
    modal.querySelector('#analytics-decision-bar').addEventListener('click', handleDecision);
    return modal;
  }

  const percent = ratio => `${(Number(ratio || 0) * 100).toFixed(2)}%`;
  const numberText = value => Number(value || 0).toFixed(2).replace(/\.00$/, '');

  const deviceIcons = { '电脑': '🖥️', '手机': '📱', '平板': '▤' };
  function profileRows(stats) {
    const names = ['电脑', '手机', '平板'];
    const lookup = new Map((stats || []).map(item => [item.name, item]));
    return names.map(name => {
      const item = lookup.get(name) || { ratio: 0, count: 0 };
      const ratio = Math.max(0, Math.min(100, Number(item.ratio) || 0));
      return `<div class="profile-row"><span>${deviceIcons[name]} ${name}</span><progress class="profile-progress" max="100" value="${ratio}">${ratio}%</progress><b>${ratio}%</b></div>`;
    }).join('');
  }

  function distributionRows(stats, emptyText) {
    return (stats || []).slice(0, 10).map(item => `
      <div class="distribution-row">
        <span title="${escapeHtml(item.name)}">${escapeHtml(item.name)}</span>
        <b>${Number(item.ratio || 0).toFixed(1)}%</b>
      </div>`).join('') || `<span class="hint">${emptyText}</span>`;
  }

  function statusTag(isRisk, riskText, healthyText, warning = false) {
    return isRisk
      ? `<span class="tag ${warning ? 'warn' : 'off'}">${riskText}</span>`
      : `<span class="tag healthy">🟢 ${healthyText}</span>`;
  }

  const sourceLabels = {
    sid_domain_match: 'SID + 域名一致', sid_fallback_no_referer: 'SID（无 Referer）',
    sid_fallback_unknown_domain: 'SID + 未登记来源', domain_only: '来源域名匹配',
    legacy_domain: '旧版域名匹配', invalid_sid_domain_match: '无效 SID + 域名匹配',
    sid_domain_mismatch: 'SID 与域名冲突'
  };

  function formatTime(value) {
    if (!value) return '—';
    if (typeof window.formatAdminTime === 'function') return window.formatAdminTime(value);
    const raw = String(value);
    const date = new Date(/[zZ]|[+-]\d\d:?\d\d$/.test(raw) ? raw : `${raw.replace(' ', 'T')}Z`);
    return Number.isNaN(date.getTime()) ? raw : new Intl.DateTimeFormat('zh-CN', {
      timeZone: 'Asia/Shanghai', hour12: false, year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    }).format(date).replaceAll('/', '-');
  }

  function durationText(seconds) {
    const value = Math.max(0, Number(seconds) || 0);
    if (value < 60) return `${Math.round(value)} 秒`;
    if (value < 3600) return `${Math.round(value / 60)} 分钟`;
    return `${(value / 3600).toFixed(value < 36000 ? 1 : 0)} 小时`;
  }

  function riskTag(item) {
    if (item.risk_level === 'high') return '<span class="client-risk high">🔴 高风险证据</span>';
    if (item.risk_level === 'observe') return '<span class="client-risk observe">🟡 建议观察</span>';
    return '<span class="client-risk normal">🟢 暂无明显异常</span>';
  }

  function clientEvidence(item) {
    const flags = item.flags || {};
    const reasons = item.risk_reasons || [];
    const source = sourceLabels[item.attribution_method] || item.attribution_method || '历史数据未记录';
    const recent = (item.recent_times || []).map(time => `<span>${escapeHtml(formatTime(time))}</span>`).join('') || '<span>暂无</span>';
    const interactionRate = item.sessions ? (Number(item.interacted_sessions || 0) / Number(item.sessions) * 100).toFixed(1) : '0.0';
    return `<tr class="client-evidence-row" data-detail-index="${item._index}" hidden><td colspan="8">
      <div class="client-evidence">
        <div class="evidence-grid">
          <section><b>完整客户端信息</b><p>UA：${escapeHtml(item.raw_user_agent || '历史数据未采集')}</p><p>平台：${escapeHtml(item.client_platform || '历史数据未采集')} · 分辨率：${escapeHtml(item.screen_resolution || '未采集')} · 语言：${escapeHtml(item.client_language || '未采集')}</p></section>
          <section><b>来源证据</b><p>识别方式：${escapeHtml(source)}</p><p>Referer：${escapeHtml(item.referer || '空 Referer')}</p><p>本客户端空 Referer：${Number(item.empty_referer_count || 0)} 次</p></section>
          <section><b>行为证据</b><p>首次：${escapeHtml(formatTime(item.first_seen))}</p><p>最近：${escapeHtml(formatTime(item.timestamp))}</p><p>中位间隔：${item.median_interval_seconds == null ? '样本不足' : durationText(item.median_interval_seconds)} · 1 分钟峰值：${Number(item.max_events_1m || 0)} 次 · 5 分钟峰值：${Number(item.max_events_5m || 0)} 次</p></section>
          <section><b>互动与关联</b><p>有效会话互动：${Number(item.interacted_sessions || 0)}/${Number(item.sessions || 0)}（${interactionRate}%）· 出站点击：${Number(item.interaction_clicks || 0)}</p><p>首次互动延迟：${item.first_interaction_seconds == null ? '无互动' : durationText(item.first_interaction_seconds)}</p><p>匿名访客涉及 ${Number(item.ip_count || 1)} 个 IP；同 IP 涉及 ${Number(item.ip_visitor_count || 1)} 个匿名访客；同环境涉及 ${Number(item.environment_ip_count || 0)} 个 IP</p></section>
        </div>
        <div class="recent-times"><b>最近访问（北京时间）</b>${recent}</div>
        <div class="evidence-verdict"><b>审核依据：</b>${escapeHtml(reasons.join('；') || '目前没有发现明显的自动化、来源冲突或环境关联证据。')} ${flags.risky ? '请结合站点总体 KPI 人工判断，不会自动处罚。' : ''}</div>
      </div>
    </td></tr>`;
  }

  function clientRows(items) {
    if (!items.length) return '<tr><td colspan="8" class="empty-inflow">暂无近 24 小时入站数据</td></tr>';
    return items.map((raw, index) => {
      const item = { ...raw, _index: index };
      const flags = item.flags || {};
      const reasons = item.risk_reasons || [];
      const source = sourceLabels[item.attribution_method] || item.attribution_method || '历史数据未记录';
      const identity = item.visitor_short ? `访客 …${item.visitor_short}` : '历史记录（按 IP 聚合）';
      const environment = item.environment_short ? `环境 …${item.environment_short}` : '环境摘要未采集';
      const searchText = [item.ip, item.visitor_short, item.client, item.raw_user_agent, item.source_domain, item.referer, reasons.join(' ')].join(' ').toLowerCase();
      return `<tr class="client-audit-row" data-client-index="${index}" data-risk="${flags.risky ? 1 : 0}" data-no-interaction="${flags.no_interaction ? 1 : 0}" data-source-anomaly="${flags.source_anomaly ? 1 : 0}" data-periodic="${flags.periodic ? 1 : 0}" data-environment-anomaly="${flags.environment_anomaly ? 1 : 0}" data-search="${escapeHtml(searchText)}">
        <td><strong>${escapeHtml(item.ip || '未知 IP')}</strong><small>${escapeHtml(identity)}</small></td>
        <td><span class="env-tag model-tag" title="${escapeHtml(item.raw_user_agent || item.client)}">${escapeHtml(item.client || item.device_model || '未知客户端')}</span><small>${escapeHtml(environment)}</small></td>
        <td><strong>${escapeHtml(item.source_domain || '空 Referer')}</strong><small>${escapeHtml(source)}</small></td>
        <td><strong>${Number(item.ip_count || 1)} UV / ${Number(item.requests || 0)} PV</strong><small>当前 IP ${Number(item.ip_requests || 0)} PV · ${Number(item.ip_ratio || 0).toFixed(1)}%</small></td>
        <td><strong>${Number(item.interacted_sessions || 0)}/${Number(item.sessions || 0)} 会话</strong><small>${Number(item.interaction_clicks || 0)} 次出站点击</small></td>
        <td><strong>跨度 ${durationText(item.duration_seconds)}</strong><small>中位间隔 ${item.median_interval_seconds == null ? '样本不足' : durationText(item.median_interval_seconds)} · 1min ${Number(item.max_events_1m || 0)} 次</small></td>
        <td>${riskTag(item)}<small>${escapeHtml(reasons.slice(0, 2).join('；') || '无明显异常')}${reasons.length > 2 ? `；另 ${reasons.length - 2} 项` : ''}</small></td>
        <td><strong>${escapeHtml(formatTime(item.timestamp))}</strong><button type="button" class="client-detail-button" data-client-detail="${index}" aria-expanded="false">展开证据</button></td>
      </tr>${clientEvidence(item)}`;
    }).join('');
  }

  function applyClientFilters() {
    const filter = state.clientFilter;
    const query = state.clientQuery.toLowerCase();
    document.querySelectorAll('#client-audit-body .client-audit-row').forEach(row => {
      const filterMatch = filter === 'all' || row.dataset[filter] === '1';
      const queryMatch = !query || row.dataset.search.includes(query);
      row.hidden = !(filterMatch && queryMatch);
      if (row.hidden) {
        const detail = document.querySelector(`#client-audit-body [data-detail-index="${row.dataset.clientIndex}"]`);
        if (detail) detail.hidden = true;
      }
    });
    const visible = document.querySelectorAll('#client-audit-body .client-audit-row:not([hidden])').length;
    const counter = document.querySelector('#client-filter-count');
    if (counter) counter.textContent = `显示 ${visible} / ${state.clients.length} 个客户端`;
  }

  function bindClientAudit() {
    document.querySelectorAll('[data-client-filter]').forEach(button => button.addEventListener('click', () => {
      state.clientFilter = button.dataset.clientFilter;
      document.querySelectorAll('[data-client-filter]').forEach(item => item.classList.toggle('active', item === button));
      applyClientFilters();
    }));
    document.querySelector('#client-audit-search')?.addEventListener('input', event => {
      state.clientQuery = event.target.value.trim();
      applyClientFilters();
    });
    document.querySelector('#client-audit-body')?.addEventListener('click', event => {
      const button = event.target.closest('[data-client-detail]');
      if (!button) return;
      const detail = document.querySelector(`#client-audit-body [data-detail-index="${button.dataset.clientDetail}"]`);
      if (!detail) return;
      detail.hidden = !detail.hidden;
      button.setAttribute('aria-expanded', String(!detail.hidden));
      button.textContent = detail.hidden ? '展开证据' : '收起证据';
    });
    applyClientFilters();
  }

  function renderAnalytics(data) {
    const diagnostics = data.diagnostics || {};
    const deadWaterInteraction = percent(diagnostics.dead_water_interaction_rate);
    const attributedInteraction = percent(diagnostics.attributed_interaction_rate);
    const hourly = percent(diagnostics.peak_hourly_ratio);
    const emptyReferer = percent(diagnostics.empty_referer_ratio);
    const pvUv = numberText(diagnostics.pv_uv_ratio ?? data.pvUvRatio);
    const ips = data.inflow_ips || data.all_inflow_ips || [];
    state.clients = ips;
    state.clientFilter = 'all';
    state.clientQuery = '';

    document.querySelector('#analytics-name').textContent = `${data.partner.name} · ${data.partner.domain}`;
    document.querySelector('#analytics-content').innerHTML = `
      <section class="diagnostic-section" aria-label="核心指标与智能诊断">
        <h4>核心 KPI 与智能诊断</h4>
        <div class="diagnostic-grid">
          <article class="diagnostic-card">
            <p>近 24h 入站概况</p><strong>UV：${Number(data.uv24h || 0)} · PV：${Number(data.pv24h || 0)}</strong>
            <span class="tag healthy">🟢 近 24 小时数据概览</span>
          </article>
          <article class="diagnostic-card">
            <p>行为时间特征</p><strong>1小时峰值UV占比：${hourly}</strong>
            ${statusTag(diagnostics.time_burst, `🟡 异常并发: 集中爆发达 ${hourly}`, `访问时段分布健康：${hourly}`, true)}
          </article>
          <article class="diagnostic-card">
            <p>基础刷新率</p><strong>PV/UV 比值：${pvUv}</strong>
            ${statusTag(diagnostics.pv_uv_anomaly, `🔴 PV/UV严重异常 (比值: ${pvUv})`, `刷新率健康：${pvUv}`)}
          </article>
          <article class="diagnostic-card">
            <p>死水交互率（近24h数据）</p><strong>${deadWaterInteraction}</strong>
            ${statusTag(diagnostics.dead_water_low, `🟡 低于阈值: ${deadWaterInteraction}（仅供人工审核）`, `近24h 后续行为率：${deadWaterInteraction}`, true)}
          </article>
          <article class="diagnostic-card">
            <p>可归因站内互动率（30min）</p><strong>${attributedInteraction}</strong>
            ${diagnostics.attribution_available
              ? statusTag(diagnostics.attributed_interaction_low, `🟡 低于阈值: ${attributedInteraction}（仅供人工审核）`, `30min 会话互动率：${attributedInteraction}`, true)
              : '<span class="tag">等待新的可归因会话数据</span>'}
          </article>
          <article class="diagnostic-card">
            <p>来源合法性</p><strong>空 Referer 占比：${emptyReferer}</strong>
            ${statusTag(diagnostics.empty_referer, `🟡 空 Referer 偏高: ${emptyReferer}（仅供人工审核）`, `来源结构健康：${emptyReferer}`, true)}
          </article>
        </div>
      </section>
      <section class="profile-section" aria-label="设备与环境画像">
        <h4>设备与环境画像</h4>
        <div class="profile-grid">
          <article class="profile-card"><h5>设备类型占比</h5>${profileRows(data.device_type_stats)}</article>
          <article class="profile-card"><h5>操作系统分布 Top 10</h5><div class="distribution-list">${distributionRows(data.os_stats || data.operatingSystems, '暂无系统数据')}</div></article>
          <article class="profile-card"><h5>浏览器分布 Top 10</h5><div class="distribution-list">${distributionRows(data.browsers, '暂无浏览器数据')}</div></article>
        </div>
      </section>
      <section class="analytics-table">
        <div class="client-table-head"><div><h4>客户端明细</h4><p id="client-filter-count" class="hint"></p></div>
          <div class="client-filters" role="group" aria-label="客户端风险筛选">
            <button type="button" class="active" data-client-filter="all">全部</button><button type="button" data-client-filter="risk">风险/观察</button>
            <button type="button" data-client-filter="noInteraction">无互动</button><button type="button" data-client-filter="sourceAnomaly">来源异常</button>
            <button type="button" data-client-filter="periodic">规律访问</button><button type="button" data-client-filter="environmentAnomaly">环境关联</button>
            <input id="client-audit-search" type="search" placeholder="搜索 IP、访客、来源或 UA" autocomplete="off">
          </div>
        </div>
        ${data.client_events_truncated ? `<p class="client-data-note">为保证后台流畅，仅分析最近 ${Number(data.pv24h || 0) > 2000 ? '2,000 条访问并优先展示 300 个客户端' : '300 个客户端'}；总体 KPI 仍基于完整的近 24 小时数据。</p>` : ''}
        <div class="table-wrap"><table>
          <thead><tr><th>IP / 匿名访客</th><th>客户端环境</th><th>来源校验</th><th>24h 访问</th><th>后续互动</th><th>时间特征</th><th>风险证据</th><th>最近访问 / 操作</th></tr></thead>
          <tbody id="client-audit-body">${clientRows(ips)}</tbody>
        </table></div>
      </section>`;
    bindClientAudit();
  }

  async function showAnalytics(id) {
    const numericId = Number(id);
    if (!Number.isInteger(numericId) || numericId <= 0) return toast('站点编号不合法');
    const sequence = ++state.requestSequence;
    state.currentId = numericId;
    const modal = ensureDialog();
    modal.classList.add('open');
    modal.querySelector('#analytics-content').innerHTML = '<div class="analytics-loading">正在生成智能诊断…</div>';
    renderNavigation();
    try {
      const data = await api(`/api/admin/partners/${numericId}/analytics`);
      if (sequence !== state.requestSequence) return;
      renderAnalytics(data);
      renderNavigation();
    } catch (error) {
      if (sequence !== state.requestSequence) return;
      modal.querySelector('#analytics-content').innerHTML = `<div class="analytics-error">${escapeHtml(error.message || '获取监控数据失败')}</div>`;
    }
  }

  function setDecisionBusy(busy) {
    document.querySelectorAll('#analytics-decision-bar button').forEach(button => { button.disabled = busy; });
  }

  async function refreshBackground() {
    const tasks = [];
    if (typeof window.loadDashboardStats === 'function') tasks.push(Promise.resolve().then(() => window.loadDashboardStats()));
    if (typeof window.loadPartners === 'function') tasks.push(Promise.resolve().then(() => window.loadPartners()));
    const results = await Promise.allSettled(tasks);
    if (document.querySelector('#analytics-modal.open')) renderNavigation();
    return results;
  }

  async function handleDecision(event) {
    const button = event.target.closest('button[data-decision]');
    if (!button || button.disabled || !state.currentId) return;
    const id = state.currentId;
    const action = button.dataset.decision;
    try {
      setDecisionBusy(true);
      if (action === 'disable') {
        if (!confirm('确定禁用/拉黑该站点吗？禁用后前台将立即隐藏。')) return;
        await api(`/api/admin/partners/${id}`, { method: 'PATCH', body: JSON.stringify({ is_approved: 0 }) });
        toast('站点已禁用');
        closeDialog();
      } else if (action === 'sandbox') {
        if (!confirm('确定将该站点权重降为 0 并进入观察状态吗？')) return;
        await api(`/api/admin/partners/${id}`, { method: 'PUT', body: JSON.stringify({ priority: 0 }) });
        toast('站点已降权至观察状态');
        await showAnalytics(id);
      } else if (action === 'clear') {
        if (!confirm('确定永久清空该站点的入站、出站及待认领流量记录吗？此操作不可撤销。')) return;
        await api(`/api/admin/partners/${id}/traffic/clear`, { method: 'POST' });
        toast('该站点流量数据已清空');
        await showAnalytics(id);
      } else if (action === 'approve') {
        await api(`/api/admin/partners/${id}`, { method: 'PATCH', body: JSON.stringify({ is_approved: 1 }) });
        toast('站点已审核通过');
        closeDialog();
      } else if (action === 'whitelist') {
        if (!confirm('确定将该站点加入风控白名单并免除疑似刷量预警吗？')) return;
        const { nextId } = adjacentIds(id);
        await api(`/api/admin/partners/${id}/whitelist`, { method: 'POST' });
        toast('已加入风控白名单');
        if (nextId) await showAnalytics(nextId);
        else closeDialog();
      }
      await refreshBackground();
    } catch (error) {
      toast(error.message || '操作失败，请稍后重试');
    } finally {
      setDecisionBusy(false);
    }
  }

  // 兼容其他管理表格显式声明的风控按钮，不自动向紧凑表格插入额外列。
  function bindDeclaredButtons() {
    document.querySelectorAll('.action-btn-group[data-enable-monitor] .monitor[data-id]').forEach(button => {
      if (button.dataset.monitorBound === '1') return;
      button.dataset.monitorBound = '1';
      button.addEventListener('click', () => showAnalytics(button.dataset.id));
    });
  }

  new MutationObserver(bindDeclaredButtons).observe(document.body, { childList: true, subtree: true });
  bindDeclaredButtons();
  window.openPartnerMonitor = showAnalytics;
})();
