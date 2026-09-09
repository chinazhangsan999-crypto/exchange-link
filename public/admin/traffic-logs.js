/** 后台有效带量与未入站用户明细。 */
(() => {
  const token = () => localStorage.getItem('webring_admin_token') || '';
  const esc = value => String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[character]));
  const request = async url => {
    const response = await fetch(url, { headers: { Authorization: `Bearer ${token()}` } });
    const result = await response.json();
    if (result.code !== 200) throw Error(result.msg || '请求失败');
    return result.data;
  };
  const time = value => window.formatAdminTime?.(value) || value || '—';
  const debounce = (handler, wait = 250) => {
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
  async function loadLogs() {
    const body = document.querySelector('#log-body');
    const input = document.querySelector('#log-q');
    if (!body || !token()) return;
    try {
      const rows = await request(`/api/admin/logs?q=${encodeURIComponent(input?.value || '')}`);
      body.innerHTML = rows.map(item => `<tr>
        <td>${esc(time(item.timestamp))}</td>
        <td><b>${esc(item.partner_name)}</b><span class="domain">${esc(item.domain)}</span></td>
        <td>${esc(attributionLabels[item.attribution_method] || item.attribution_method || '未知')}</td>
        <td>${esc(item.ip)}</td>
        <td><span class="tag"${Number(item.newly_counted) ? '' : ' style="background:#f3f4f6;color:#64748b"'}>${Number(item.newly_counted) ? '新增 1 UV' : '24h 重复，仅 PV'}</span></td>
        <td title="${esc(item.user_agent)}">${esc(compactClient(item.user_agent))}</td>
      </tr>`).join('') || '<tr><td colspan="6" class="hint">暂无有效带量明细</td></tr>';
    } catch (error) {
      body.innerHTML = `<tr><td colspan="6" class="hint">${esc(error.message)}</td></tr>`;
    }
  }
  async function loadRejectedLogs() {
    const body = document.querySelector('#rejected-log-body');
    const input = document.querySelector('#rejected-log-q');
    if (!body || !token()) return;
    try {
      const rows = await request(`/api/admin/rejected-inbound-logs?q=${encodeURIComponent(input?.value || '')}`);
      body.innerHTML = rows.map(item => `<tr>
        <td>${esc(time(item.timestamp))}</td>
        <td><span class="tag ${item.visitor_type === 'ordinary_direct' ? '' : 'off'}">${item.visitor_type === 'ordinary_direct' ? '普通直访' : '入站校验未通过'}</span></td>
        <td>${sourceText(item)}</td>
        <td>${esc(item.ip)}</td>
        <td><b>${esc(stageLabels[item.stage] || item.stage || '未知阶段')}</b><span class="domain">${esc(item.reason_text || item.reason_code || '未通过入站校验')}</span></td>
        <td title="${esc(item.user_agent)}">${esc(compactClient(item.user_agent))}<span class="domain">近10分钟合并：${Number(item.occurrence_count || 1)} 次</span></td>
      </tr>`).join('') || '<tr><td colspan="6" class="hint">暂无未入站用户记录</td></tr>';
    } catch (error) {
      body.innerHTML = `<tr><td colspan="6" class="hint">${esc(error.message)}</td></tr>`;
    }
  }
  window.loadLogs = loadLogs;
  window.loadRejectedLogs = loadRejectedLogs;
  const logSearch = document.querySelector('#log-q');
  if (logSearch) logSearch.oninput = null;
  logSearch?.addEventListener('input', debounce(loadLogs));
  document.querySelector('#rejected-log-q')?.addEventListener('input', debounce(loadRejectedLogs));
})();
