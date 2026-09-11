/** 友链管理统一表格渲染：防止多脚本重复插列造成布局失控。 */
(() => {
  const token = () => localStorage.getItem('webring_admin_token') || '';
  const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
  const toast = text => { const el = document.querySelector('#toast'); if (!el) return; el.textContent = text; el.classList.add('show'); setTimeout(() => el.classList.remove('show'), 2400); };
  const request = async (url, options = {}) => { const response = await fetch(url, { ...options, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token()}`, ...(options.headers || {}) } }); const result = await response.json(); if (result.code !== 200) throw Error(result.msg || '请求失败'); return result.data; };
  const time = value => window.formatAdminTime?.(value) || '—';
  let rows = [], sort = { key: 'priority', direction: 'desc' };

  /** 渲染反链巡检状态；Ping 连通状态在独立列展示。 */
  function inspectionStatus(item) {
    if (Number(item.is_exempt) === 1) return '<span class="status-pill protected" title="该站点已设置为反链免检">🛡️ 免检/受保护</span>';
    const backlink = item.backlink_status || 'pending';
    const failed = Number(item.failed_check_count || 0), lost = Number(item.lost_count || 0);
    if (backlink === 'lost') return `<span class="status-pill danger" title="未在对方页面找到本站反链">🔴 掉链${lost ? `（${lost}次）` : ''}</span>`;
    if (backlink === 'pending') return '<span class="status-pill pending" title="尚未执行反向友链巡检">⚪ 待检测</span>';
    if (backlink === 'protected') return '<span class="status-pill protected" title="对方开启防爬安全盾，请人工抽查">🛡️ 受保护/防爬</span>';
    if (backlink === 'unreachable' || backlink === 'dead') return `<span class="status-pill warn" title="网络超时、DNS 异常或连续巡检失败">🟡 网络异常 ${failed}/3</span>`;
    const trafficTitle = Number(item.score_24h || 0) > 0 ? ' title="近24h有真实访问，触发流量免检"' : '';
    return `<span class="status-pill valid"${trafficTitle} title="反向友链巡检正常">🟢 正常</span>`;
  }

  /** 独立渲染 Ping 探活状态，便于识别待探活、预警及自动下架。 */
  function renderPingStatusBadge(item) {
    const failed = Number(item.ping_failed_count || 0), status = item.ping_status || 'ok';
    if (Number(item.ping_exempt) === 1) return '<span class="status-pill protected" title="该站点不执行自动 HEAD/GET 连通性探活">🛡️ Ping 免检</span>';
    if (!item.last_ping_at) return '<span class="status-pill pending" title="尚未执行 Ping 探活">⚪ 待探活</span>';
    if (status === 'unreachable' || failed >= 3) return `<span class="status-pill danger" title="连续 ${failed} 次探活失败，前台已自动下架">🔴 失效(${failed}/3)</span>`;
    if (failed > 0) { const hint = failed === 1 ? '第 1 次探活超时/失败' : '已连续 2 次失败，即将标记失效'; return `<span class="status-pill warn" title="${hint}">🟡 失联 ${failed}/3</span>`; }
    return `<span class="status-pill valid" title="最近探活：${esc(time(item.last_ping_at))}">🟢 正常</span>`;
  }

  /** 联系方式单元格：内容截断，复制按钮通过事件绑定避免拼接脚本。 */
  function renderContactCell(item) {
    const contact = String(item.contact || item.contact_info || '').trim();
    if (!contact) return '<span class="contact-empty">—</span>';
    return `<div class="contact-cell" title="${esc(contact)}"><span class="contact-text">${esc(contact)}</span><button class="btn-copy-mini copy-contact" type="button" data-contact="${esc(contact)}" title="一键复制联系方式" aria-label="复制站长联系方式">📋</button></div>`;
  }

  function renderPartnerRow(item) {
    const approved = Number(item.is_approved) === 1, priority = Number(item.priority || 0);
    return `<tr data-id="${item.id}"><td class="site-cell"><a class="site-name-link" href="/go?id=${item.id}" target="_blank" rel="noopener" title="${esc(item.name)}">${esc(item.name)}</a><span class="site-domain" title="${esc(item.domain)}">${esc(item.domain)}</span></td><td><span class="category-pill" title="${esc(item.category || '未分类')}">${esc(item.category || '未分类')}</span></td><td>${renderContactCell(item)}</td><td>${inspectionStatus(item)}</td><td class="ping-cell">${renderPingStatusBadge(item)}</td><td class="col-traffic"><div class="traffic-row-primary"><span class="traffic-item item-24h">24h: <strong class="val-blue">${Number(item.score_24h || 0)}</strong></span><span class="traffic-divider">/</span><span class="traffic-item item-out">出: <strong class="val-dark">${Number(item.outflow_24h || 0)}</strong></span></div><div class="traffic-row-secondary"><span class="traffic-item item-total">总: <strong class="val-dark">${Number(item.total_score ?? item.score_total ?? 0)}</strong></span></div></td><td class="col-weight">${priority > 0 ? `<span class="badge-weight-num">${priority}</span>` : '<span class="priority-zero">0</span>'}</td><td><span class="compact-time" title="反链：${esc(time(item.last_checked_at))}">${esc(time(item.last_checked_at))}</span></td><td><div class="action-btn-group"><button class="btn-sm btn-action btn-check backlink-check" data-id="${item.id}" title="同时检查反链挂载状态和网站连通状态">查反链</button><button class="btn-sm btn-action btn-default monitor" data-id="${item.id}" title="查看流量与风控详情">📊 监控</button><button class="btn-sm btn-action btn-default reset-lost" data-id="${item.id}" title="重置反链巡检与连通状态">🔄 重置</button><button class="btn-sm btn-action btn-default edit" data-id="${item.id}">编辑</button><button class="btn-sm btn-action btn-default state" data-id="${item.id}" data-state="${approved ? 0 : 1}">${approved ? '禁用' : '通过'}</button><button class="btn-sm btn-action btn-reject delete" data-id="${item.id}">删除</button></div></td></tr>`;
  }

  function renderRows() {
    const body = document.querySelector('#partner-body'); if (!body) return;
    const direction = sort.direction === 'asc' ? 1 : -1;
    const data = [...rows].sort((a, b) => ((Number(a[sort.key] || 0) - Number(b[sort.key] || 0)) * direction) || Number(a.id) - Number(b.id));
    body.innerHTML = data.map(renderPartnerRow).join('') || '<tr><td class="empty-row" colspan="9">没有匹配的友链</td></tr>';
  }

  function replacePartnerRow(item) {
    const current = document.querySelector(`#partner-body tr[data-id="${Number(item.id)}"]`);
    if (!current) return renderRows();
    current.outerHTML = renderPartnerRow(item);
  }

  function installPartnerActionDelegation() {
    const body = document.querySelector('#partner-body');
    if (!body || body.dataset.actionsBound === '1') return;
    body.dataset.actionsBound = '1';
    body.addEventListener('click', event => {
      const button = event.target.closest('button[data-id]');
      if (!button || !body.contains(button)) return;
      if (button.classList.contains('backlink-check')) void checkOne(button);
      else if (button.classList.contains('monitor')) {
        if (typeof window.openPartnerMonitor === 'function') window.openPartnerMonitor(button.dataset.id);
        else toast('风控组件加载失败，请刷新页面后重试');
      } else if (button.classList.contains('reset-lost')) void resetCheckStatus(button);
      else if (button.classList.contains('state')) void changeState(button);
      else if (button.classList.contains('delete')) void removeLink(button);
      else if (button.classList.contains('copy-contact')) void copyContact(button);
    });
  }

  async function copyContact(button) { const value = button.dataset.contact || ''; try { if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(value); else { const input = document.createElement('input'); input.value = value; document.body.append(input); input.select(); document.execCommand('copy'); input.remove(); } const old = button.textContent; button.textContent = '✓'; setTimeout(() => { button.textContent = old; }, 1200); toast('联系方式已复制'); } catch { toast('复制失败，请手动复制'); } }

  async function loadPartners() { if (!token()) return; try { const query = document.querySelector('#partner-q')?.value || ''; rows = await request('/api/admin/partners?q=' + encodeURIComponent(query)); renderRows(); } catch (error) { toast(error.message); } }
  async function checkOne(button) {
    try {
      button.disabled = true;
      button.textContent = '检测中...';
      const updated = await request(`/api/admin/links/${button.dataset.id}/inspect`, { method: 'POST' });
      const item = rows.find(row => Number(row.id) === Number(button.dataset.id));
      if (item) {
        Object.assign(item, updated.backlink, updated.connectivity, {
          last_checked_at: updated.backlink?.exempted
            ? item.last_checked_at
            : (updated.backlink?.checked_at || updated.checked_at || item.last_checked_at),
          last_ping_at: updated.connectivity?.skipped
            ? item.last_ping_at
            : (updated.connectivity?.last_ping_at || updated.connectivity?.checked_at || item.last_ping_at)
        });
        replacePartnerRow(item);
      }
      toast(`反链：${updated.backlink?.result_text || '检测完成'}；连通：${updated.connectivity?.result_text || '检测完成'}`);
    } catch (error) {
      toast(error.message);
    } finally {
      if (button.isConnected) {
        button.disabled = false;
        button.textContent = '查反链';
      }
    }
  }
  async function resetCheckStatus(button) {
    if (!confirm('确定要重置该网站的巡检状态吗？')) return;
    const originalText = button.textContent;
    try {
      button.disabled = true;
      button.textContent = '重置中...';
      const updated = await request(`/api/admin/partners/${button.dataset.id}/reset-check`, { method: 'POST' });
      const item = rows.find(row => Number(row.id) === Number(button.dataset.id));
      if (item) {
        Object.assign(item, updated);
        replacePartnerRow(item);
      }
      toast('巡检状态已重置');
    } catch (error) {
      toast(error.message || '重置失败，请稍后重试');
    } finally {
      if (button.isConnected) {
        button.disabled = false;
        button.textContent = originalText;
      }
    }
  }
  async function changeState(button) { try { await request(`/api/admin/partners/${button.dataset.id}`, { method: 'PATCH', body: JSON.stringify({ is_approved: Number(button.dataset.state) }) }); toast(Number(button.dataset.state) ? '已审核通过' : '已禁用友链'); await loadPartners(); window.loadDashboardStats?.(); } catch (error) { toast(error.message); } }
  async function removeLink(button) { if (!confirm('确定删除这条友链及其入站记录吗？')) return; try { await request(`/api/admin/partners/${button.dataset.id}`, { method: 'DELETE' }); toast('友链已删除'); await loadPartners(); window.loadDashboardStats?.(); } catch (error) { toast(error.message); } }
  function installSort() { document.querySelectorAll('#partners .sort-header').forEach(header => header.onclick = () => { const key = header.dataset.sort; sort = { key, direction: sort.key === key && sort.direction === 'desc' ? 'asc' : 'desc' }; document.querySelectorAll('#partners .sort-header').forEach(item => { item.classList.toggle('active', item === header); item.textContent = `${item.textContent.replace(/[↕↑↓]/g, '').trim()} ${item === header ? (sort.direction === 'desc' ? '↓' : '↑') : '↕'}`; }); renderRows(); }); }
  async function startInspectionJob(button, taskName, startUrl, type) {
    if (button.dataset.running === '1') return;
    const batchButtons = [...document.querySelectorAll('#partners .batch-check-group button')];
    const originalText = button.textContent;
    try {
      button.dataset.running = '1';
      batchButtons.forEach(item => { item.disabled = true; });
      let job = await request(startUrl, { method: 'POST' });
      while (job.status === 'running') {
        const suffix = type === 'backlink' ? `，流量跳过${Number(job.trafficSkipped || 0)}` : '';
        button.textContent = `${taskName}（${Number(job.completed || 0)}/${Number(job.targetTotal || 0)}${suffix}）...`;
        await new Promise(resolve => setTimeout(resolve, 900));
        job = await request(`/api/admin/inspection-jobs/${encodeURIComponent(job.jobId)}`);
      }
      if (job.status === 'failed') throw new Error(job.error || `${taskName}失败`);
      const summary = job.summary || {};
      if (type === 'backlink') {
        const abnormal = Number(summary.network_checked || 0) - Number(summary.normal || 0) - Number(summary.recovered || 0);
        toast(`${taskName}完成：纳入${Number(summary.target_total || 0)}，流量跳过${Number(summary.traffic_skipped || 0)}，实际检测${Number(summary.network_checked || 0)}，异常${Math.max(0, abnormal)}，恢复${Number(summary.recovered || 0)}`);
      } else {
        const abnormal = Number(summary.first_failure || 0) + Number(summary.ongoing_failure || 0) + Number(summary.reached_dead || 0) + Number(summary.task_errors || 0);
        toast(`${taskName}完成：探活${Number(summary.target_total || 0)}，正常${Number(summary.normal || 0)}，异常${abnormal}，恢复${Number(summary.recovered || 0)}`);
      }
      await loadPartners();
    } catch (error) {
      toast(error.message || `${taskName}失败`);
    } finally {
      delete button.dataset.running;
      batchButtons.forEach(item => { item.disabled = false; });
      button.textContent = originalText;
      button.title = taskName === '反链全查'
        ? '一键批量检查所有友链是否仍挂载本站链接'
        : '一键批量检测所有友链的网站存活状态';
    }
  }

  function installToolbar() {
    const toolbar = document.querySelector('#partners .toolbar');
    if (!toolbar) return;
    let group = toolbar.querySelector('.batch-check-group');
    if (!group) {
      group = document.createElement('div');
      group.className = 'batch-check-group';
      toolbar.prepend(group);
    }
    let backlinkButton = document.querySelector('#check-all-backlinks');
    if (!backlinkButton) {
      backlinkButton = document.createElement('button');
      backlinkButton.id = 'check-all-backlinks';
      backlinkButton.type = 'button';
      backlinkButton.className = 'button ghost';
      group.append(backlinkButton);
    }
    let healthButton = document.querySelector('#batch-check-health-btn');
    if (!healthButton) {
      healthButton = document.createElement('button');
      healthButton.id = 'batch-check-health-btn';
      healthButton.type = 'button';
      healthButton.className = 'button ghost';
      group.append(healthButton);
    }
    if (backlinkButton.parentElement !== group) group.prepend(backlinkButton);
    if (healthButton.parentElement !== group) group.append(healthButton);

    backlinkButton.textContent = '🔍 反链全查';
    backlinkButton.title = '一键批量检查所有友链是否仍挂载本站链接';
    backlinkButton.onclick = () => startInspectionJob(backlinkButton, '反链全查', '/api/admin/links/check-all', 'backlink');
    healthButton.textContent = '⚡ 链群健康体检';
    healthButton.title = '一键批量检测所有友链的网站存活状态';
    healthButton.onclick = () => startInspectionJob(healthButton, '链群健康体检', '/api/admin/links/ping-all', 'ping');
  }
  function installCreateExemptionField() {
    const form = document.querySelector('#add-form');
    const grid = form?.querySelector('.form-grid');
    if (!form || !grid || form.elements.is_exempt) return;
    const label = document.createElement('label');
    label.className = 'full exemption-option';
    label.innerHTML = '<input name="is_exempt" type="hidden" value="0"><input name="is_exempt" type="checkbox" value="1"><span>🛡️ 设为免检（不进行反链巡检）</span>';
    grid.append(label);
  }
  function installCreatePingExemptionField() {
    const form = document.querySelector('#add-form');
    const grid = form?.querySelector('.form-grid');
    if (!form || !grid || form.elements.ping_exempt) return;
    const label = document.createElement('label');
    label.className = 'full exemption-option';
    label.innerHTML = '<input name="ping_exempt" type="hidden" value="0"><input name="ping_exempt" type="checkbox" value="1"><span>🛡️ 连通性免检（不进行 HEAD/GET 探活，适用于 OpenAI、GitHub 等）</span>';
    grid.append(label);
  }
  function installEditExemptionField() {
    document.addEventListener('click', event => {
      const button = event.target.closest('#partner-body .edit[data-id]');
      if (!button) return;
      const partner = rows.find(row => Number(row.id) === Number(button.dataset.id));
      setTimeout(() => {
        const form = document.querySelector('#edit-partner-form');
        const grid = form?.querySelector('.form-grid');
        if (!form || !grid) return;
        let label = form.querySelector('.exemption-option');
        if (!label) {
          label = document.createElement('label');
          label.className = 'full exemption-option';
          label.innerHTML = '<input name="is_exempt" type="hidden" value="0"><input name="is_exempt" type="checkbox" value="1"><span>🛡️ 设为免检（不进行反链巡检）</span>';
          grid.append(label);
        }
        label.querySelector('input[type="checkbox"]').checked = Number(partner?.is_exempt) === 1;
        let pingLabel = form.querySelector('.ping-exemption-option');
        if (!pingLabel) {
          pingLabel = document.createElement('label');
          pingLabel.className = 'full exemption-option ping-exemption-option';
          pingLabel.innerHTML = '<input name="ping_exempt" type="hidden" value="0"><input name="ping_exempt" type="checkbox" value="1"><span>🛡️ 连通性免检（不进行 HEAD/GET 探活）</span>';
          grid.append(pingLabel);
        }
        pingLabel.querySelector('input[type="checkbox"]').checked = Number(partner?.ping_exempt) === 1;
      }, 0);
    }, true);
  }
  function ensureTableStructure() { const table = document.querySelector('#partners table'); if (!table) return; table.className = 'admin-table partner-table'; table.querySelector('colgroup')?.remove(); table.insertAdjacentHTML('afterbegin', '<colgroup><col class="partner-col-site"><col class="partner-col-category"><col class="partner-col-contact"><col class="partner-col-backlink"><col class="partner-col-ping"><col class="partner-col-traffic"><col class="partner-col-priority"><col class="partner-col-checked"><col class="partner-col-actions"></colgroup>'); table.querySelector('thead').innerHTML = '<tr><th>网站 / 域名</th><th>分类</th><th class="contact-header">站长联系方式</th><th>巡检状态</th><th class="ping-header">连通状态</th><th class="sort-header" data-sort="score_24h">带量 ↕</th><th class="sort-header" data-sort="priority">权重 ↕</th><th>最近巡检</th><th>操作</th></tr>'; }
  function loadStyles() { if (!document.querySelector('link[href^="/admin/tables.css"]')) { const link = document.createElement('link'); link.rel = 'stylesheet'; link.href = '/admin/tables.css?v=20260831-1'; document.head.append(link); } if (!document.querySelector('link[href^="/admin/table-fixes.css"]')) { const fixes = document.createElement('link'); fixes.rel = 'stylesheet'; fixes.href = '/admin/table-fixes.css?v=20260831-1'; document.head.append(fixes); } if (!document.querySelector('link[href^="/admin/traffic-cell.css"]')) { const traffic = document.createElement('link'); traffic.rel = 'stylesheet'; traffic.href = '/admin/traffic-cell.css?v=20260911-ip-profile'; document.head.append(traffic); } }
  loadStyles(); ensureTableStructure(); installSort(); installToolbar(); installPartnerActionDelegation(); installCreateExemptionField(); installCreatePingExemptionField(); installEditExemptionField(); window.loadPartners = loadPartners;
  const partnerSearch = document.querySelector('#partner-q');
  if (partnerSearch) {
    partnerSearch.oninput = null;
    partnerSearch.addEventListener('input', () => { clearTimeout(window.__partnerSearchTimer); window.__partnerSearchTimer = setTimeout(loadPartners, 180); });
  }
})();

/** CSV 全站矩阵：只负责设置页交互，同步按友链→广告→节点严格串行执行。 */
(() => {
  const token = () => localStorage.getItem('webring_admin_token') || '';
  const form = () => document.querySelector('#matrix-url-form');
  const logBox = () => document.querySelector('#matrix-sync-log');
  const matrixToast = message => {
    if (typeof window.toast === 'function') return window.toast(message);
    const element = document.querySelector('#toast');
    if (!element) return;
    element.textContent = message;
    element.classList.add('show');
    setTimeout(() => element.classList.remove('show'), 3000);
  };

  async function matrixApi(url, options = {}) {
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token()}`,
        ...(options.headers || {})
      }
    });
    const result = await response.json();
    if (!response.ok || result.code !== 200) throw new Error(result.msg || '请求失败');
    return result.data;
  }

  function setLog(message, state = '') {
    const element = logBox();
    if (!element) return;
    element.textContent = message;
    element.className = `matrix-sync-log ${state}`.trim();
  }

  function lockControls(locked) {
    document.querySelectorAll('[data-matrix-action]').forEach(button => { button.disabled = locked; });
  }

  async function loadMatrixSettings() {
    if (!form() || !token()) return;
    try {
      const data = await matrixApi('/api/admin/settings');
      ['csv_url_partners', 'csv_url_ads', 'csv_url_mirrors'].forEach(key => {
        if (form().elements[key]) form().elements[key].value = data[key] || '';
      });
    } catch (error) {
      setLog(error.message, 'error');
    }
  }

  async function saveMatrixSettings(event) {
    event.preventDefault();
    const payload = {};
    ['csv_url_partners', 'csv_url_ads', 'csv_url_mirrors'].forEach(key => {
      if (form().elements[key]) payload[key] = form().elements[key].value.trim();
    });
    try {
      lockControls(true);
      setLog('正在保存 CSV 数据源…', 'running');
      await matrixApi('/api/admin/settings', { method: 'POST', body: JSON.stringify(payload) });
      setLog('CSV 数据源已保存；尚未执行同步。', 'success');
      matrixToast('CSV 矩阵配置已保存');
    } catch (error) {
      setLog(`[失败] ${error.message}`, 'error');
      matrixToast(error.message);
    } finally {
      lockControls(false);
    }
  }

  function syncSummary(type, result) {
    if (type === 'partners') return `友链新增${result.inserted || 0}条，更新${result.updated || 0}条`;
    if (type === 'ads') return `广告全覆盖${result.total || 0}条`;
    const excluded = Number(result.excluded || 0);
    return `节点全覆盖${result.total || 0}条${excluded ? `，排除本站${excluded}条` : ''}`;
  }

  async function runMatrixSync(types, trigger) {
    const labels = { partners: '友链', ads: '广告', mirrors: '节点' };
    const originalText = trigger?.textContent || '';
    const results = [];
    try {
      lockControls(true);
      for (let index = 0; index < types.length; index += 1) {
        const type = types[index];
        const progress = `正在拉取${labels[type]} (${index + 1}/${types.length})...`;
        if (trigger) trigger.textContent = progress;
        setLog(progress, 'running');
        const result = await matrixApi(`/api/admin/sync/${type}`, { method: 'POST' });
        results.push(syncSummary(type, result));
      }
      const summary = `[成功] ${results.join('；')}`;
      setLog(summary, 'success');
      matrixToast(summary);
      window.loadPartners?.();
      window.loadAdminAds?.();
      window.loadAdminMirrors?.();
    } catch (error) {
      const completed = results.length ? `${results.join('；')}；` : '';
      const summary = `[失败] ${completed}${error.message}`;
      setLog(summary, 'error');
      matrixToast(summary);
    } finally {
      lockControls(false);
      if (trigger) trigger.textContent = originalText;
      document.querySelectorAll('.matrix-menu[open]').forEach(menu => menu.removeAttribute('open'));
    }
  }

  function downloadFileName(response, fallback) {
    const disposition = response.headers.get('content-disposition') || '';
    const encoded = disposition.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
    if (encoded) {
      try { return decodeURIComponent(encoded); } catch { return fallback; }
    }
    return disposition.match(/filename="([^"]+)"/i)?.[1] || fallback;
  }

  async function downloadMatrix(type, trigger) {
    try {
      lockControls(true);
      setLog(`正在生成${type === 'all' ? '全部' : type}备份…`, 'running');
      const response = await fetch(`/api/admin/export/${type}`, {
        headers: { Authorization: `Bearer ${token()}` }
      });
      if (!response.ok) {
        const error = await response.json().catch(() => ({}));
        throw new Error(error.msg || '下载失败');
      }
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = href;
      anchor.download = downloadFileName(response, type === 'all' ? 'matrix-backup.zip' : `${type}.csv`);
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(href);
      setLog('备份文件已生成并开始下载。', 'success');
    } catch (error) {
      setLog(`[失败] ${error.message}`, 'error');
      matrixToast(error.message);
    } finally {
      lockControls(false);
      document.querySelectorAll('.matrix-menu[open]').forEach(menu => menu.removeAttribute('open'));
    }
  }

  function installMatrixControls() {
    if (!form() || form().dataset.bound === '1') return;
    form().dataset.bound = '1';
    form().addEventListener('submit', saveMatrixSettings);
    document.querySelector('#sync-matrix-all')?.addEventListener('click', event => {
      runMatrixSync(window.controlCenterManaged ? ['partners', 'ads'] : ['partners', 'ads', 'mirrors'], event.currentTarget);
    });
    form().addEventListener('click', event => {
      const syncButton = event.target.closest('[data-sync-type]');
      if (syncButton) {
        const type = syncButton.dataset.syncType;
        runMatrixSync(type === 'all'
          ? (window.controlCenterManaged ? ['partners', 'ads'] : ['partners', 'ads', 'mirrors'])
          : [type], syncButton);
        return;
      }
      const exportButton = event.target.closest('[data-export-type]');
      if (exportButton) downloadMatrix(exportButton.dataset.exportType, exportButton);
    });
  }

  window.loadMatrixSettings = loadMatrixSettings;
  installMatrixControls();
})();
