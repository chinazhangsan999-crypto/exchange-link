/** 后台增长看板、全站访客趋势、疑似刷量列表与友链分类快速筛选。 */
(() => {
  const STATS_INTERVAL_MS = 60 * 1000;
  const CHART_INTERVAL_MS = 5 * 60 * 1000;
  const RANGE_KEY = 'webring_site_traffic_range';
  const METRICS = [
    { key: 'total_ip', label: '独立 IP', color: '#2563eb' },
    { key: 'total_uv', label: '访客 UV', color: '#10b981' },
    { key: 'total_pv', label: '页面 PV', color: '#f97316' }
  ];

  const state = {
    range: ['24h', '7d', '30d'].includes(localStorage.getItem(RANGE_KEY))
      ? localStorage.getItem(RANGE_KEY) : '7d',
    hiddenMetrics: new Set(),
    statsTimer: null,
    chartTimer: null,
    chartRequest: 0
  };

  const esc = value => String(value ?? '').replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[character]));
  const number = value => Math.max(0, Number(value) || 0);

  async function request(url, options = {}) {
    const response = await fetch(url, {
      ...options,
      credentials: 'same-origin',
      headers: { ...(options.headers || {}) }
    });
    const result = await response.json().catch(() => null);
    if (!response.ok || result?.code !== 200) {
      const error = Error(result?.msg || `请求失败（HTTP ${response.status}）`);
      error.status = response.status;
      throw error;
    }
    return result.data;
  }

  function notify(text) {
    const element = document.querySelector('#toast');
    if (!element) return alert(text);
    element.textContent = text;
    element.classList.add('show');
    setTimeout(() => element.classList.remove('show'), 2400);
  }

  function loadStyles() {
    if (document.querySelector('#dashboard-extra-style')) return;
    const link = document.createElement('link');
    link.id = 'dashboard-extra-style';
    link.rel = 'stylesheet';
    link.href = '/admin/dashboard.css?v=20260910-site-traffic';
    document.head.append(link);
  }

  function createDashboard() {
    loadStyles();
    const anchor = document.querySelector('#dashboard .kpis');
    if (!anchor) return;

    let status = document.querySelector('#dashboard-load-status');
    if (!status) {
      status = document.createElement('p');
      status.id = 'dashboard-load-status';
      status.className = 'hint';
      status.hidden = true;
      anchor.parentElement?.insertBefore(status, anchor);
    }

    const trafficCard = anchor.querySelector('.kpi:first-child');
    if (trafficCard && !document.querySelector('#today-exchange')) {
      trafficCard.innerHTML = '<i class="kpi-icon">⇄</i><p>今日流量交换</p><strong id="today-exchange">— / —</strong><span class="domain"><i class="inflow-dot"></i>入站 <b id="today-inbound-ip">—</b> IP　<i class="outflow-dot"></i>出量 <b id="today-outbound-ip">—</b> IP</span>';
    }

    let growth = document.querySelector('#growth-kpis');
    if (!growth) {
      growth = document.createElement('div');
      growth.id = 'growth-kpis';
      growth.className = 'kpis';
      growth.innerHTML = '<article class="kpi"><i class="kpi-icon">＋</i><p>24小时新增站点</p><strong id="new-24h">—</strong><span class="domain">带来 <b id="new-24h-uv">—</b> 个 UV</span></article><article class="kpi"><i class="kpi-icon">◷</i><p>7日新增站点</p><strong id="new-7d">—</strong><span class="domain">7日带来 <b id="new-7d-uv">—</b> 个 UV</span></article><article class="kpi visitor-kpi"><i class="kpi-icon">⌁</i><p>今日网站访客</p><strong id="today-site-ip">—</strong><span class="domain visitor-breakdown"><b>IP <em id="today-site-ip-small">—</em></b><b>UV <em id="today-site-uv">—</em></b><b>PV <em id="today-site-pv">—</em></b></span></article>';
      anchor.insertAdjacentElement('afterend', growth);
    }

    let chart = document.querySelector('#site-traffic-chart-box');
    if (!chart) {
      chart = document.createElement('div');
      chart.id = 'site-traffic-chart-box';
      chart.className = 'box site-traffic-box';
      chart.innerHTML = '<div class="box-head site-traffic-head"><div><h2>全站访客趋势</h2><p id="site-traffic-subtitle" class="hint">统计成功打开的公开 HTML 页面，不参与友链积分。</p></div><div class="site-traffic-controls" aria-label="访客趋势时间范围"><button type="button" data-range="24h">24小时</button><button type="button" data-range="7d">7天</button><button type="button" data-range="30d">30天</button></div></div><div id="site-traffic-legend" class="site-traffic-legend" aria-label="访客趋势指标"></div><div id="site-traffic-frame" class="site-traffic-frame"><svg id="site-traffic-svg" viewBox="0 0 1000 350" role="img" aria-label="全站访客趋势图"></svg><div id="site-traffic-tooltip" class="site-traffic-tooltip" hidden></div><div id="site-traffic-empty" class="site-traffic-empty" hidden>暂无访客数据</div></div>';
      growth.insertAdjacentElement('afterend', chart);
      chart.querySelectorAll('[data-range]').forEach(button => {
        button.onclick = () => {
          state.range = button.dataset.range;
          localStorage.setItem(RANGE_KEY, state.range);
          updateRangeButtons();
          loadSiteTrafficTrend();
        };
      });
      const legend = chart.querySelector('#site-traffic-legend');
      METRICS.forEach(metric => {
        const button = document.createElement('button');
        button.type = 'button';
        button.dataset.metric = metric.key;
        button.innerHTML = `<i></i>${metric.label}`;
        button.onclick = () => {
          if (state.hiddenMetrics.has(metric.key)) state.hiddenMetrics.delete(metric.key);
          else if (state.hiddenMetrics.size < METRICS.length - 1) state.hiddenMetrics.add(metric.key);
          loadSiteTrafficTrend();
        };
        legend.append(button);
      });
      updateRangeButtons();
    }

    if (!document.querySelector('#suspicious-box')) {
      const box = document.createElement('div');
      box.id = 'suspicious-box';
      box.className = 'box';
      box.innerHTML = '<div class="box-head"><div><h2>疑似刷量预警</h2><p class="hint">采用高、中风险分层；样本不足仅展示监控，不发送告警。</p></div></div><div class="table-wrap"><table><thead><tr><th>站点</th><th>24小时 UV</th><th>24小时 PV</th><th>风险原因</th><th>快捷操作</th></tr></thead><tbody id="suspicious-body"></tbody></table></div>';
      chart.insertAdjacentElement('afterend', box);
    }
  }

  function updateRangeButtons() {
    document.querySelectorAll('#site-traffic-chart-box [data-range]').forEach(button => {
      button.classList.toggle('active', button.dataset.range === state.range);
      button.setAttribute('aria-pressed', button.dataset.range === state.range ? 'true' : 'false');
    });
    document.querySelectorAll('#site-traffic-legend [data-metric]').forEach(button => {
      const hidden = state.hiddenMetrics.has(button.dataset.metric);
      button.classList.toggle('muted', hidden);
      button.setAttribute('aria-pressed', hidden ? 'false' : 'true');
    });
  }

  function pointLabel(iso, range) {
    const date = new Date(iso);
    const options = range === '24h'
      ? { hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Shanghai' }
      : range === '7d'
        ? { month: '2-digit', day: '2-digit', hour: '2-digit', hour12: false, timeZone: 'Asia/Shanghai' }
        : { month: '2-digit', day: '2-digit', timeZone: 'Asia/Shanghai' };
    return new Intl.DateTimeFormat('zh-CN', options).format(date).replaceAll('/', '-');
  }

  function fullTime(iso) {
    return new Intl.DateTimeFormat('zh-CN', {
      month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
      hour12: false, timeZone: 'Asia/Shanghai'
    }).format(new Date(iso)).replaceAll('/', '-');
  }

  function renderSiteTrafficChart(data) {
    const svg = document.querySelector('#site-traffic-svg');
    const empty = document.querySelector('#site-traffic-empty');
    const tooltip = document.querySelector('#site-traffic-tooltip');
    if (!svg || !empty || !tooltip) return;
    updateRangeButtons();

    const points = Array.isArray(data?.series) ? data.series : [];
    const visible = METRICS.filter(metric => !state.hiddenMetrics.has(metric.key));
    const width = 1000;
    const height = 350;
    const plot = { left: 64, right: 28, top: 24, bottom: 52 };
    const plotWidth = width - plot.left - plot.right;
    const plotHeight = height - plot.top - plot.bottom;
    const primaryMetrics = visible.filter(metric => metric.key !== 'total_pv');
    const pvVisible = visible.some(metric => metric.key === 'total_pv');
    const primaryMax = Math.max(1, ...points.flatMap(point => primaryMetrics.map(metric => number(point[metric.key]))));
    const pvMax = Math.max(1, ...points.map(point => number(point.total_pv)));
    const usePvAxis = pvVisible && primaryMetrics.length > 0 && pvMax > primaryMax * 1.5;
    const leftMax = usePvAxis
      ? primaryMax
      : Math.max(1, ...points.flatMap(point => visible.map(metric => number(point[metric.key]))));
    const rightMax = usePvAxis ? pvMax : leftMax;
    const x = index => plot.left + (points.length <= 1 ? 0 : index * plotWidth / (points.length - 1));
    const y = (value, maxValue = leftMax) => plot.top + plotHeight - number(value) * plotHeight / maxValue;
    const parts = [];

    for (let index = 0; index <= 4; index += 1) {
      const value = Math.round(leftMax * (4 - index) / 4);
      const lineY = plot.top + plotHeight * index / 4;
      parts.push(`<line class="traffic-grid" x1="${plot.left}" y1="${lineY}" x2="${width - plot.right}" y2="${lineY}"></line>`);
      parts.push(`<text class="traffic-axis-text" x="${plot.left - 12}" y="${lineY + 4}" text-anchor="end">${value}</text>`);
      if (usePvAxis) {
        parts.push(`<text class="traffic-axis-text traffic-pv-axis" x="${width - plot.right + 10}" y="${lineY + 4}" text-anchor="start">${Math.round(rightMax * (4 - index) / 4)}</text>`);
      }
    }

    const labelIndexes = new Set([0, points.length - 1]);
    const labelCount = Math.min(6, points.length);
    for (let index = 1; index < labelCount - 1; index += 1) {
      labelIndexes.add(Math.round(index * (points.length - 1) / (labelCount - 1)));
    }
    [...labelIndexes].sort((a, b) => a - b).forEach(index => {
      if (!points[index]) return;
      parts.push(`<text class="traffic-axis-text" x="${x(index)}" y="${height - 18}" text-anchor="middle">${esc(pointLabel(points[index].time, data.range))}</text>`);
    });

    visible.forEach(metric => {
      const metricMax = usePvAxis && metric.key === 'total_pv' ? rightMax : leftMax;
      const path = points.map((point, index) => `${index ? 'L' : 'M'} ${x(index).toFixed(2)} ${y(point[metric.key], metricMax).toFixed(2)}`).join(' ');
      if (path) parts.push(`<path class="traffic-line" stroke="${metric.color}" d="${path}"></path>`);
      points.forEach((point, index) => parts.push(`<circle class="traffic-point" fill="${metric.color}" cx="${x(index)}" cy="${y(point[metric.key], metricMax)}" r="3"></circle>`));
    });

    points.forEach((point, index) => {
      const cellWidth = plotWidth / Math.max(1, points.length - 1);
      const hitX = Math.max(plot.left, x(index) - cellWidth / 2);
      parts.push(`<rect class="traffic-hit" data-index="${index}" x="${hitX}" y="${plot.top}" width="${Math.min(cellWidth, width - plot.right - hitX)}" height="${plotHeight}"></rect>`);
    });
    svg.innerHTML = parts.join('');

    const hasData = points.some(point => METRICS.some(metric => number(point[metric.key]) > 0));
    empty.hidden = hasData;
    svg.classList.toggle('no-data', !hasData);
    svg.querySelectorAll('.traffic-hit').forEach(hit => {
      hit.onmouseenter = () => {
        const point = points[Number(hit.dataset.index)];
        tooltip.innerHTML = `<b>${esc(fullTime(point.time))}</b><span>独立 IP：${number(point.total_ip)}</span><span>访客 UV：${number(point.total_uv)}</span><span>页面 PV：${number(point.total_pv)}</span>`;
        tooltip.hidden = false;
      };
      hit.onmouseleave = () => { tooltip.hidden = true; };
    });
  }

  async function loadSiteTrafficTrend() {
    if (window.adminSessionActive !== true || !isDashboardVisible()) return;
    const requestId = ++state.chartRequest;
    try {
      const data = await request(`/api/admin/dashboard/site-traffic?range=${encodeURIComponent(state.range)}`);
      if (requestId !== state.chartRequest) return;
      const subtitle = document.querySelector('#site-traffic-subtitle');
      if (subtitle) subtitle.textContent = data.range === '7d'
        ? '每 3 小时取样，展示该时间点向前 24 小时的独立 IP、UV 与 PV。'
        : data.range === '24h'
          ? '按北京时间展示每小时独立 IP、UV 与 PV。'
          : '按北京时间自然日展示最近 30 天独立 IP、UV 与 PV。';
      renderSiteTrafficChart(data);
    } catch (error) {
      console.error(error);
      const empty = document.querySelector('#site-traffic-empty');
      if (empty) { empty.textContent = '访客趋势加载失败，稍后将自动重试'; empty.hidden = false; }
    }
  }

  async function loadDashboardStats() {
    if (window.adminSessionActive !== true) return;
    try {
      createDashboard();
      const data = await request('/api/admin/dashboard/stats');
      const status = document.querySelector('#dashboard-load-status');
      if (status) status.hidden = true;
      const inbound = number(data.todayInbound ?? data.today_inflow_uv);
      const outbound = number(data.todayOutbound ?? data.today_outflow_uv);
      const traffic = data.today_site_traffic || {};
      document.querySelector('#today-exchange').textContent = `${inbound} / ${outbound}`;
      document.querySelector('#today-inbound-ip').textContent = inbound;
      document.querySelector('#today-outbound-ip').textContent = outbound;
      document.querySelector('#new-24h').textContent = number(data.new_partners_24h);
      document.querySelector('#new-24h-uv').textContent = number(data.new_partners_24h_today_uv);
      document.querySelector('#new-7d').textContent = number(data.new_partners_7d);
      document.querySelector('#new-7d-uv').textContent = number(data.new_partners_7d_total_uv);
      document.querySelector('#today-site-ip').textContent = number(traffic.total_ip);
      document.querySelector('#today-site-ip-small').textContent = number(traffic.total_ip);
      document.querySelector('#today-site-uv').textContent = number(traffic.total_uv);
      document.querySelector('#today-site-pv').textContent = number(traffic.total_pv);
      const activeCount = document.querySelector('#active-count');
      if (activeCount) activeCount.textContent = number(data.active_partners);
      const leader = document.querySelector('#leader');
      if (leader) leader.textContent = data.today_leader
        ? `${data.today_leader.name} · ${number(data.today_leader.uv)} UV` : '今日暂无有效带量';

      const body = document.querySelector('#suspicious-body');
      if (!body) return;
      body.innerHTML = (data.suspicious_partners || []).map(item => `<tr><td><b>${esc(item.name)}</b><span class="domain">${esc(item.domain)}</span></td><td>${number(item.score_24h)}</td><td>${number(item.pv_24h)}</td><td>${item.risk_reasons.map(reason => `<span class="tag ${item.risk_level === 'high' ? 'off' : 'warn'} risk-reason-tag">${item.risk_level === 'high' ? '高风险：' : '中风险：'}${esc(reason)}</span>`).join('')}</td><td><div class="actions"><button class="action see-risk" data-id="${item.id}">查看风控</button><button class="action disable-risk" data-id="${item.id}">禁用</button></div></td></tr>`).join('') || '<tr><td colspan="5" class="hint">暂未发现达到告警条件的站点</td></tr>';
      body.querySelectorAll('.see-risk').forEach(button => {
        button.onclick = () => typeof window.openPartnerMonitor === 'function'
          ? window.openPartnerMonitor(button.dataset.id)
          : notify('风控组件加载失败，请刷新页面后重试');
      });
      body.querySelectorAll('.disable-risk').forEach(button => {
        button.onclick = async () => {
          if (!confirm('确定禁用该疑似刷量站点吗？')) return;
          try {
            await request(`/api/admin/partners/${button.dataset.id}`, {
              method: 'PATCH', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ is_approved: 0 })
            });
            notify('已禁用友链');
            loadDashboardStats();
          } catch (error) { notify(error.message); }
        };
      });
    } catch (error) {
      console.error('加载仪表盘统计失败：', error);
      const status = document.querySelector('#dashboard-load-status');
      if (status) {
        status.hidden = false;
        status.textContent = error.status === 401 || error.status === 403
          ? '后台会话已失效，请返回总后台重新进入本站后台。'
          : `仪表盘数据加载失败：${error.message || '请稍后重试'}`;
      }
      if (error.status === 401 || error.status === 403) {
        window.adminSessionActive = false;
        notify('后台会话无效，请返回总后台重新进入');
      }
    }
  }

  function isDashboardVisible() {
    return document.visibilityState !== 'hidden' && document.querySelector('#dashboard')?.classList.contains('active');
  }

  function startRefreshTimers() {
    if (state.statsTimer) clearInterval(state.statsTimer);
    if (state.chartTimer) clearInterval(state.chartTimer);
    state.statsTimer = setInterval(() => { if (isDashboardVisible()) loadDashboardStats(); }, STATS_INTERVAL_MS);
    state.chartTimer = setInterval(() => { if (isDashboardVisible()) loadSiteTrafficTrend(); }, CHART_INTERVAL_MS);
  }

  async function initDashboard() {
    createDashboard();
    startRefreshTimers();
    await Promise.allSettled([loadDashboardStats(), loadSiteTrafficTrend()]);
  }

  document.addEventListener('visibilitychange', () => {
    if (isDashboardVisible()) Promise.allSettled([loadDashboardStats(), loadSiteTrafficTrend()]);
  });

  async function setupCategoryFilter() {
    if (window.adminSessionActive !== true) return;
    const toolbar = document.querySelector('#partners .toolbar');
    if (!toolbar) return;
    const existing = toolbar.querySelector('#partner-category-filter');
    toolbar.querySelectorAll('select,.category-filter-button,.category-quick-filter').forEach(item => { if (item !== existing) item.remove(); });
    if (existing) { existing.onchange = filterPartnerRows; return; }
    try {
      const categories = await request('/api/admin/categories');
      const select = document.createElement('select');
      select.id = 'partner-category-filter';
      select.className = 'input category-filter-input';
      select.setAttribute('aria-label', '按分类筛选友链');
      select.innerHTML = `<option value="">全部分类</option>${categories.map(item => `<option value="${esc(item.name)}">${esc(item.name)}</option>`).join('')}`;
      toolbar.prepend(select);
      select.onchange = filterPartnerRows;
    } catch (error) { console.error(error); }
  }

  function filterPartnerRows() {
    const category = document.querySelector('#partner-category-filter')?.value || '';
    document.querySelectorAll('#partner-body tr').forEach(row => {
      if (row.children.length >= 2) row.hidden = Boolean(category && row.children[1].textContent.trim() !== category);
    });
  }

  window.loadDashboardStats = loadDashboardStats;
  window.loadSiteTrafficTrend = loadSiteTrafficTrend;
  window.loadFraudAlerts = loadDashboardStats;
  window.initDashboard = initDashboard;
  window.setupPartnerCategoryFilter = setupCategoryFilter;
})();
