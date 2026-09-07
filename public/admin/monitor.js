/** 站点风控监控：量化诊断、环境画像、连续审核与快捷决策。 */
(() => {
  if (!document.querySelector('link[href^="/admin/monitor.css"]')) {
    const stylesheet = document.createElement('link');
    stylesheet.rel = 'stylesheet';
    stylesheet.href = '/admin/monitor.css?v=20260906-2';
    document.head.append(stylesheet);
  }

  const token = () => localStorage.getItem('webring_admin_token') || '';
  const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[character]));
  const state = { currentId: null, requestSequence: 0 };

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

  function renderAnalytics(data) {
    const diagnostics = data.diagnostics || {};
    const deadWaterInteraction = percent(diagnostics.dead_water_interaction_rate);
    const attributedInteraction = percent(diagnostics.attributed_interaction_rate);
    const hourly = percent(diagnostics.peak_hourly_ratio);
    const emptyReferer = percent(diagnostics.empty_referer_ratio);
    const pvUv = numberText(diagnostics.pv_uv_ratio ?? data.pvUvRatio);
    const ips = data.inflow_ips || data.all_inflow_ips || [];

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
        <h4>客户端明细</h4>
        <div class="table-wrap"><table>
          <thead><tr><th>入站 IP</th><th>客户端</th><th>请求次数</th><th>占比</th><th>最近访问</th></tr></thead>
          <tbody>${ips.map(item => `<tr><td>${escapeHtml(item.ip)}</td><td><span class="env-tag model-tag" title="${escapeHtml(item.client || item.device_model)}">${escapeHtml(item.client || item.device_model || '未知客户端')}</span></td><td>${Number(item.requests || 0)}</td><td>${Number(item.ratio || 0).toFixed(1)}%</td><td>${escapeHtml(item.timestamp || '—')}</td></tr>`).join('') || '<tr><td colspan="5" class="empty-inflow">暂无近 24 小时入站数据</td></tr>'}</tbody>
        </table></div>
      </section>`;
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
