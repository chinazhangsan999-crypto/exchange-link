/** 后台增长看板、疑似刷量列表与友链分类快速筛选。 */
(() => {
  const trafficStyle=document.createElement('style');trafficStyle.textContent='.inflow-dot,.outflow-dot{display:inline-block;width:7px;height:7px;border-radius:50%;vertical-align:1px}.inflow-dot{background:#3b82f6}.outflow-dot{background:#10b981}';document.head.append(trafficStyle);
  const token = () => localStorage.getItem('webring_admin_token') || '';
  const esc = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
  async function request(url, options = {}) { const response = await fetch(url, { ...options, headers: { Authorization: `Bearer ${token()}`, ...(options.headers || {}) } }); const result = await response.json(); if (result.code !== 200) throw Error(result.msg); return result.data; }
  function notify(text) { const el = document.querySelector('#toast'); if (!el) return alert(text); el.textContent = text; el.classList.add('show'); setTimeout(() => el.classList.remove('show'), 2400); }
  function createDashboard() { const anchor = document.querySelector('#dashboard .kpis'); if (!anchor || document.querySelector('#growth-kpis')) return; const trafficCard = anchor.querySelector('.kpi:first-child'); if (trafficCard) trafficCard.innerHTML = '<i class="kpi-icon">⇄</i><p>今日流量交换</p><strong id="today-exchange">— / —</strong><span class="domain"><i class="inflow-dot"></i>入站 <b id="today-inbound-ip">—</b> IP　<i class="outflow-dot"></i>出量 <b id="today-outbound-ip">—</b> IP</span>'; const growth = document.createElement('div'); growth.id = 'growth-kpis'; growth.className = 'kpis'; growth.innerHTML = '<article class="kpi"><i class="kpi-icon">＋</i><p>24小时新增站点</p><strong id="new-24h">—</strong><span class="domain">带来 <b id="new-24h-uv">—</b> 个 UV</span></article><article class="kpi"><i class="kpi-icon">◷</i><p>7日新增站点</p><strong id="new-7d">—</strong><span class="domain">7日带来 <b id="new-7d-uv">—</b> 个 UV</span></article>'; anchor.insertAdjacentElement('afterend', growth); const box = document.createElement('div'); box.id = 'suspicious-box'; box.className = 'box'; box.innerHTML = '<div class="box-head"><div><h2>疑似刷量预警</h2><p class="hint">采用高、中风险分层；样本不足仅展示监控，不发送告警。</p></div></div><div class="table-wrap"><table><thead><tr><th>站点</th><th>24小时 UV</th><th>24小时 PV</th><th>风险原因</th><th>快捷操作</th></tr></thead><tbody id="suspicious-body"></tbody></table></div>'; growth.insertAdjacentElement('afterend', box); }
  async function loadDashboardStats() {
    try {
      createDashboard();
      const data = await request('/api/admin/dashboard/stats');
      const inbound = Number(data.todayInbound ?? data.today_inflow_uv ?? 0);
      const outbound = Number(data.todayOutbound ?? data.today_outflow_uv ?? 0);
      document.getElementById('today-exchange').textContent = `${inbound} / ${outbound}`;
      document.getElementById('today-inbound-ip').textContent = inbound;
      document.getElementById('today-outbound-ip').textContent = outbound;
      document.querySelector('#new-24h').textContent = data.new_partners_24h;
      document.querySelector('#new-24h-uv').textContent = data.new_partners_24h_today_uv;
      document.querySelector('#new-7d').textContent = data.new_partners_7d;
      document.querySelector('#new-7d-uv').textContent = data.new_partners_7d_total_uv;

      const body = document.querySelector('#suspicious-body');
      body.innerHTML = data.suspicious_partners.map(item => `<tr><td><b>${esc(item.name)}</b><span class="domain">${esc(item.domain)}</span></td><td>${item.score_24h}</td><td>${item.pv_24h}</td><td>${item.risk_reasons.map(reason => `<span class="tag ${item.risk_level === 'high' ? 'off' : 'warn'} risk-reason-tag">${item.risk_level === 'high' ? '高风险：' : '中风险：'}${esc(reason)}</span>`).join('')}</td><td><div class="actions"><button class="action see-risk" data-id="${item.id}">查看风控</button><button class="action disable-risk" data-id="${item.id}">禁用</button></div></td></tr>`).join('') || '<tr><td colspan="5" class="hint">暂未发现达到告警条件的站点</td></tr>';

      body.querySelectorAll('.see-risk').forEach(button => {
        button.onclick = () => {
          if (typeof window.openPartnerMonitor === 'function') {
            window.openPartnerMonitor(button.dataset.id);
            return;
          }
          notify('风控组件加载失败，请刷新页面后重试');
        };
      });
      body.querySelectorAll('.disable-risk').forEach(button => {
        button.onclick = async () => {
          if (!confirm('确定禁用该疑似刷量站点吗？')) return;
          try {
            await request(`/api/admin/partners/${button.dataset.id}`, {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ is_approved: 0 })
            });
            notify('已禁用友链');
            loadDashboardStats();
          } catch (error) {
            notify(error.message);
          }
        };
      });
    } catch (error) {
      console.error(error);
    }
  }
  async function setupCategoryFilter() { if (!token()) return; const toolbar = document.querySelector('#partners .toolbar'); if (!toolbar) return; const existing = toolbar.querySelector('#partner-category-filter'); toolbar.querySelectorAll('select,.category-filter-button,.category-quick-filter').forEach(item => { if (item !== existing) item.remove(); }); if (existing) { existing.onchange = () => filterPartnerRows(); return; } try { const categories = await request('/api/admin/categories'); const select = document.createElement('select'); select.id = 'partner-category-filter'; select.className = 'input category-filter-input'; select.setAttribute('aria-label','按分类筛选友链'); select.innerHTML = `<option value="">全部分类</option>${categories.map(item => `<option value="${esc(item.name)}">${esc(item.name)}</option>`).join('')}`; toolbar.prepend(select); select.onchange = () => filterPartnerRows(); } catch (error) { console.error(error); } }
  function filterPartnerRows() { const category = document.querySelector('#partner-category-filter')?.value || ''; document.querySelectorAll('#partner-body tr').forEach(row => { if (row.children.length < 2) return; row.hidden = Boolean(category && row.children[1].textContent.trim() !== category); }); }
  const observer = new MutationObserver(() => { if (!token()) return; setupCategoryFilter(); filterPartnerRows(); }); observer.observe(document.body, { childList: true, subtree: true });
  // 对外暴露统一初始化入口，供登录成功与切回概览 Tab 时主动刷新。
  window.loadDashboardStats = loadDashboardStats;
  window.loadFraudAlerts = loadDashboardStats;
  window.initDashboard = async () => { await Promise.all([loadDashboardStats(), setupCategoryFilter()]); };
  window.addEventListener('admin:authenticated', () => { window.initDashboard().catch(error => console.error('登录后初始化仪表盘失败：', error)); });
  setTimeout(() => { if (token()) window.initDashboard().catch(error => console.error('仪表盘初始化失败：', error)); }, 300);
})();
