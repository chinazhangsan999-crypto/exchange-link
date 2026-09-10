/** 后台有效带量与未入站用户明细：服务端筛选后分页，每页 100 条。 */
(() => {
  const PAGE_SIZE = 100;
  const token = () => localStorage.getItem('webring_admin_token') || '';
  const esc = value => String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[character]));
  const states = {
    accepted: { page: 1, query: '', sequence: 0, controller: null },
    rejected: { page: 1, query: '', sequence: 0, controller: null }
  };
  const request = async (url, signal) => {
    const response = await fetch(url, { signal, headers: { Authorization: `Bearer ${token()}` } });
    const result = await response.json().catch(() => ({}));
    if (!response.ok || result.code !== 200) throw Error(result.msg || `请求失败 (${response.status})`);
    return result.data;
  };
  const time = value => window.formatAdminTime?.(value) || value || '—';
  const debounce = (handler, wait = 300) => {
    let timer;
    return (...args) => {
      clearTimeout(timer);
      timer = setTimeout(() => handler(...args), wait);
    };
  };
  const attributionLabels = {
    domain_only: 'Referer 域名归属',
    sid_domain_match: 'SID 与域名一致',
    sid_domain_mismatch: 'SID 与域名冲突，按域名归属',
    sid_fallback_no_referer: 'SID 归属（无 Referer）',
    sid_fallback_unknown_domain: 'SID 归属（未知来源）',
    invalid_sid_domain_match: '无效 SID，按已登记域名归属'
  };
  const stageLabels = {
    sid_resolution: 'SID 解析', source_resolution: '来源识别', claim_issue: '凭证签发',
    heartbeat: '有效心跳', fingerprint: '浏览器环境', database_write: '最终写入'
  };

  function compactClient(userAgent) {
    const ua = String(userAgent || '');
    const device = /iPhone/i.test(ua) ? 'iPhone' : /iPad/i.test(ua) ? 'iPad'
      : /Android/i.test(ua) ? 'Android' : /Windows/i.test(ua) ? 'Windows'
        : /Macintosh|Mac OS/i.test(ua) ? 'macOS' : /Linux/i.test(ua) ? 'Linux' : '未知设备';
    const browser = /Edg\//i.test(ua) ? 'Edge' : /Firefox\//i.test(ua) ? 'Firefox'
      : /Chrome\//i.test(ua) ? 'Chrome' : /Safari\//i.test(ua) ? 'Safari' : '未知浏览器';
    return `${device} · ${browser}`;
  }

  function sourceText(item) {
    if (item.partner_name) return `<b>${esc(item.partner_name)}</b><span class="domain">${esc(item.domain || item.observed_domain || '—')}</span>`;
    if (item.observed_domain) return `<b>${esc(item.observed_domain)}</b><span class="domain">未登记来源域名</span>`;
    return '<span class="hint">无可归属来源</span>';
  }

  function renderPagination(containerId, pagination, kind) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const meta = pagination || { page: 1, totalPages: 1, total: 0, from: 0, to: 0 };
    container.innerHTML = `
      <div class="pagination-summary" role="status" aria-live="polite">
        共 <strong>${Number(meta.total || 0)}</strong> 条，当前显示 ${Number(meta.from || 0)}–${Number(meta.to || 0)}，每页最多 ${PAGE_SIZE} 条
      </div>
      <div class="pagination-actions" aria-label="明细翻页">
        <button type="button" data-page-action="first" ${meta.hasPrevious ? '' : 'disabled'}>首页</button>
        <button type="button" data-page-action="previous" ${meta.hasPrevious ? '' : 'disabled'}>上一页</button>
        <span>第 <strong>${Number(meta.page || 1)}</strong> / ${Number(meta.totalPages || 1)} 页</span>
        <button type="button" data-page-action="next" ${meta.hasNext ? '' : 'disabled'}>下一页</button>
        <button type="button" data-page-action="last" ${meta.hasNext ? '' : 'disabled'}>末页</button>
      </div>`;
    container.dataset.kind = kind;
    container.dataset.page = String(meta.page || 1);
    container.dataset.totalPages = String(meta.totalPages || 1);
  }

  function normalizePayload(payload) {
    if (Array.isArray(payload)) {
      return { items: payload, pagination: { page: 1, totalPages: 1, total: payload.length, from: payload.length ? 1 : 0, to: payload.length, hasPrevious: false, hasNext: false } };
    }
    return { items: payload?.items || [], pagination: payload?.pagination || {} };
  }

  async function loadLogs(page = states.accepted.page) {
    const body = document.querySelector('#log-body');
    const input = document.querySelector('#log-q');
    if (!body || !token()) return;
    const state = states.accepted;
    state.page = Math.max(1, Number(page) || 1);
    state.query = String(input?.value || '').trim();
    state.controller?.abort();
    state.controller = new AbortController();
    const sequence = ++state.sequence;
    body.innerHTML = '<tr><td colspan="6" class="hint">正在加载有效带量明细…</td></tr>';
    try {
      const payload = normalizePayload(await request(`/api/admin/logs?page=${state.page}&pageSize=${PAGE_SIZE}&q=${encodeURIComponent(state.query)}`, state.controller.signal));
      if (sequence !== state.sequence) return;
      state.page = Number(payload.pagination.page || 1);
      body.innerHTML = payload.items.map(item => `<tr>
        <td>${esc(time(item.timestamp))}</td>
        <td><b>${esc(item.partner_name)}</b><span class="domain">${esc(item.domain)}</span></td>
        <td>${esc(attributionLabels[item.attribution_method] || item.attribution_method || '未知')}</td>
        <td>${esc(item.ip)}</td>
        <td><span class="tag"${Number(item.newly_counted) ? '' : ' style="background:#f3f4f6;color:#64748b"'}>${Number(item.newly_counted) ? '新增 1 UV' : '24h 重复，仅 PV'}</span></td>
        <td title="${esc(item.user_agent)}">${esc(compactClient(item.user_agent))}</td>
      </tr>`).join('') || '<tr><td colspan="6" class="hint">暂无有效带量明细</td></tr>';
      renderPagination('log-pagination', payload.pagination, 'accepted');
    } catch (error) {
      if (error.name === 'AbortError' || sequence !== state.sequence) return;
      body.innerHTML = `<tr><td colspan="6" class="hint">${esc(error.message)}</td></tr>`;
    }
  }

  async function loadRejectedLogs(page = states.rejected.page) {
    const body = document.querySelector('#rejected-log-body');
    const input = document.querySelector('#rejected-log-q');
    if (!body || !token()) return;
    const state = states.rejected;
    state.page = Math.max(1, Number(page) || 1);
    state.query = String(input?.value || '').trim();
    state.controller?.abort();
    state.controller = new AbortController();
    const sequence = ++state.sequence;
    body.innerHTML = '<tr><td colspan="6" class="hint">正在加载未入站明细…</td></tr>';
    try {
      const payload = normalizePayload(await request(`/api/admin/rejected-inbound-logs?page=${state.page}&pageSize=${PAGE_SIZE}&q=${encodeURIComponent(state.query)}`, state.controller.signal));
      if (sequence !== state.sequence) return;
      state.page = Number(payload.pagination.page || 1);
      body.innerHTML = payload.items.map(item => `<tr>
        <td>${esc(time(item.timestamp))}</td>
        <td><span class="tag ${item.visitor_type === 'ordinary_direct' ? '' : 'off'}">${item.visitor_type === 'ordinary_direct' ? '普通直访' : '入站校验未通过'}</span></td>
        <td>${sourceText(item)}</td>
        <td>${esc(item.ip)}</td>
        <td><b>${esc(stageLabels[item.stage] || item.stage || '未知阶段')}</b><span class="domain">${esc(item.reason_text || item.reason_code || '未通过入站校验')}</span></td>
        <td title="${esc(item.user_agent)}">${esc(compactClient(item.user_agent))}<span class="domain">近10分钟合并：${Number(item.occurrence_count || 1)} 次</span></td>
      </tr>`).join('') || '<tr><td colspan="6" class="hint">暂无未入站用户记录</td></tr>';
      renderPagination('rejected-log-pagination', payload.pagination, 'rejected');
    } catch (error) {
      if (error.name === 'AbortError' || sequence !== state.sequence) return;
      body.innerHTML = `<tr><td colspan="6" class="hint">${esc(error.message)}</td></tr>`;
    }
  }

  function handlePagination(event) {
    const button = event.target.closest('button[data-page-action]');
    if (!button || button.disabled) return;
    const container = button.closest('.pagination-bar');
    const state = states[container?.dataset.kind];
    if (!state) return;
    const current = Number(container.dataset.page || 1);
    const totalPages = Number(container.dataset.totalPages || 1);
    const actions = { first: 1, previous: current - 1, next: current + 1, last: totalPages };
    const target = Math.max(1, Math.min(totalPages, actions[button.dataset.pageAction] || current));
    (container.dataset.kind === 'accepted' ? loadLogs : loadRejectedLogs)(target);
  }

  window.loadLogs = loadLogs;
  window.loadRejectedLogs = loadRejectedLogs;
  const logSearch = document.querySelector('#log-q');
  if (logSearch) logSearch.oninput = null;
  logSearch?.addEventListener('input', debounce(() => loadLogs(1)));
  const rejectedSearch = document.querySelector('#rejected-log-q');
  if (rejectedSearch) rejectedSearch.oninput = null;
  rejectedSearch?.addEventListener('input', debounce(() => loadRejectedLogs(1)));
  document.querySelector('#log-pagination')?.addEventListener('click', handlePagination);
  document.querySelector('#rejected-log-pagination')?.addEventListener('click', handlePagination);
})();
