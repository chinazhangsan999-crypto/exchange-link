/** 友链审核与系统设置：使用固定列宽表格，避免申请文本撑破布局。 */
(() => {
  const token = () => localStorage.getItem('webring_admin_token') || '';
  const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
  const toast = text => { const el = document.querySelector('#toast'); if (!el) return; el.textContent = text; el.classList.add('show'); setTimeout(() => el.classList.remove('show'), 2400); };
  const api = async (url, options = {}) => { const response = await fetch(url, { ...options, headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token()}`, ...(options.headers || {}) } }); const result = await response.json(); if (result.code !== 200) throw Error(result.msg || '请求失败'); return result.data; };
  const time = value => window.formatAdminTime?.(value) || '—';

  function switchTo(id, button) { document.querySelectorAll('.tabs button,.panel').forEach(el => el.classList.remove('active')); button.classList.add('active'); document.querySelector('#' + id)?.classList.add('active'); }
  function installRiskControlFields() {
    const form = document.querySelector('#settings-form');
    if (!form || form.querySelector('#risk-control-settings')) return;
    const fieldset = document.createElement('fieldset');
    fieldset.id = 'risk-control-settings';
    fieldset.innerHTML = `<legend>站点风控监控参数</legend>
      <label>死水交互率阈值（近24h数据）
        <input name="min_interaction_rate" type="number" min="0" max="1" step="0.001" required value="0.02">
        <small>按近 24h 入站 IP 的后续出站行为观察；仅用于人工审核，不自动处置。</small>
      </label>
      <label>1h 时间并发峰值占比
        <input name="max_hourly_burst_ratio" type="number" min="0" max="1" step="0.01" required value="0.6">
        <small>输入 0～1 的小数；单小时占比超过该值时提示集中访问。</small>
      </label>
      <label>空 Referer 预警阈值
        <input name="empty_referer_threshold" type="number" min="0" max="1" step="0.01" required value="0.5">
        <small>空值、NULL 与纯空白 Referer 都会纳入统计。</small>
      </label>
      <label>可归因站内互动率阈值（30min）
        <input name="min_attributed_interaction_rate" type="number" min="0" max="1" step="0.001" required value="0.005">
        <small>仅统计同一已验证访问会话在 30 分钟内的后续出站，缺少会话数据时不判定。</small>
      </label>
      <label>PV/UV 异常比值阈值
        <input name="pv_uv_ratio_threshold" type="number" min="0.1" max="100000" step="0.1" required value="100.0">
        <small>超过该比值时提示异常刷新行为，仍需人工复核。</small>
      </label>`;
    const actions = form.querySelector('.settings-actions');
    form.insertBefore(fieldset, actions || null);
  }
  function setLogoPreview(value) {
    const preview = document.querySelector('#site-logo-preview');
    const raw = String(value || '').trim();
    if (!preview) return;
    if (!/^https?:\/\//i.test(raw) && !/^\/uploads\/logo\/[a-zA-Z0-9._-]+$/.test(raw)) { preview.hidden = true; preview.removeAttribute('src'); return; }
    preview.hidden = false; preview.src = raw;
  }
  function installLogoSettings() {
    const form = document.querySelector('#settings-form');
    if (!form || form.querySelector('#site-logo-settings')) return;
    const fieldset = document.createElement('fieldset');
    fieldset.id = 'site-logo-settings';
    fieldset.innerHTML = `<legend>全站 Logo</legend>
      <label>Logo 地址（选填）<input name="site_logo_url" type="text" inputmode="url" placeholder="https://example.com/logo.png"><small>可粘贴 PNG、JPG 或 WebP 图片地址；保存系统设置后全站生效。</small></label>
      <label>上传 Logo（PNG/JPG/WebP，最大 2MB）<input id="site-logo-file" type="file" accept="image/png,image/jpeg,image/webp"><small>上传成功后会自动写入上方 Logo 地址。</small></label>
      <div class="logo-setting-actions"><button id="upload-site-logo" class="button ghost" type="button">上传并使用 Logo</button><button id="clear-site-logo" class="button ghost" type="button">恢复默认星标</button></div>
      <img id="site-logo-preview" class="site-logo-preview" alt="Logo 预览" hidden>`;
    const actions = form.querySelector('.settings-actions');
    form.insertBefore(fieldset, actions || null);
    const urlInput = form.elements.site_logo_url;
    urlInput.addEventListener('input', () => setLogoPreview(urlInput.value));
    document.querySelector('#clear-site-logo').onclick = async () => {
      try {
        const response = await fetch('/api/admin/settings', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token()}` }, body: JSON.stringify({ site_logo_url: '' }) });
        const result = await response.json(); if (result.code !== 200) throw Error(result.msg || '恢复默认 Logo 失败');
        urlInput.value = ''; setLogoPreview(''); await window.loadAdminBrand?.(); toast('已恢复默认星标');
      } catch (error) { toast(error.message || '恢复默认 Logo 失败'); }
    };
    document.querySelector('#upload-site-logo').onclick = async () => {
      const file = document.querySelector('#site-logo-file').files?.[0];
      if (!file) { toast('请先选择一个 Logo 图片'); return; }
      const button = document.querySelector('#upload-site-logo');
      const body = new FormData(); body.append('logo', file);
      try {
        button.disabled = true; button.textContent = '上传中…';
        const response = await fetch('/api/admin/settings/logo', { method: 'POST', headers: { Authorization: `Bearer ${token()}` }, body });
        const result = await response.json();
        if (result.code !== 200) throw Error(result.msg || 'Logo 上传失败');
        urlInput.value = result.data.site_logo_url; setLogoPreview(urlInput.value);
        await window.loadAdminBrand?.(); toast('Logo 上传成功，已应用到全站');
      } catch (error) { toast(error.message || 'Logo 上传失败'); }
      finally { button.disabled = false; button.textContent = '上传并使用 Logo'; }
    };
  }
  function install() {
    if (document.querySelector('#review-tab')) return;
    const tabs = document.querySelector('.tabs');
    const reviewButton = document.createElement('button'); reviewButton.id = 'review-tab'; reviewButton.innerHTML = '友链审核 <b id="review-count" class="review-badge">0</b>';
    const settingsButton = document.createElement('button'); settingsButton.id = 'settings-tab'; settingsButton.textContent = '系统设置'; tabs.append(reviewButton, settingsButton);
    const review = document.createElement('section'); review.id = 'review'; review.className = 'panel'; review.innerHTML = `<div class="box"><div class="box-head"><div><h2>友链审核</h2><p class="hint">待审核站点累计有效独立 IP 达到自动通过阈值后将自动上线。</p></div><button id="refresh-review" class="button ghost">刷新列表</button></div><div class="table-card"><div class="table-wrap"><table class="admin-table review-table"><colgroup><col class="review-col-site"><col class="review-col-url"><col class="review-col-description"><col class="review-col-contact"><col class="review-col-score"><col class="review-col-progress"><col class="review-col-time"><col class="review-col-actions"></colgroup><thead><tr><th>站点 / 分类</th><th>友链地址</th><th>一句话描述</th><th>申请人联系方式</th><th>24h 积分</th><th>入站进度</th><th>申请时间</th><th>操作</th></tr></thead><tbody id="review-body"></tbody></table></div></div></div>`;
    const settings = document.createElement('section'); settings.id = 'settings'; settings.className = 'panel'; settings.innerHTML = `<div class="box settings-box"><div class="box-head"><div><h2>系统设置</h2><p class="hint">配置站点资料、发布页信息、自动审核规则与管理员告警。</p></div></div><form id="settings-form" class="settings-form"><label>站点名称<input name="site_name" required placeholder="例如：星环导航"></label><label>永久发布页地址<input name="publish_url" type="url" placeholder="https://pub.example.com"></label><label>防失联官方邮箱<input name="contact_email" type="email" placeholder="contact@yourdomain.com"><small>域名或发布页失效时，访客可向此邮箱获取最新地址。</small></label><label>其他联系方式<input name="contact_info" placeholder="@Telegram / QQ群 / 客服"><small>用于前台联系站长与统一引导弹窗展示。</small></label><label>管理员告警 Webhook 地址<input name="webhook_url" type="url" placeholder="Telegram Bot API 或企业微信机器人 Webhook 地址"><small>作为主告警通道；所有通知会自动带上当前站点名称。</small></label><fieldset id="bark-fallback-settings"><legend>Bark 备用告警</legend><label class="switch-setting"><span>启用 Bark 备用通道</span><input name="bark_enabled" type="checkbox" value="1"><small>仅当 Telegram / 企业微信主通道最终发送失败时接管，不重复推送。</small></label><label>Bark 服务地址<input name="bark_server_url" type="url" placeholder="https://api.day.app"><small>支持 HTTPS 自建 Bark 服务。</small></label><label>Bark Device Key<input name="bark_device_key" type="password" autocomplete="new-password" placeholder="留空表示不修改已保存密钥"><small id="bark-key-state">密钥仅保存于服务端，不会回显。</small></label><label>Bark 推送分组<input name="bark_group" maxlength="80" placeholder="星环导航告警"></label></fieldset><section id="webhook-health-card" class="webhook-health-card" aria-live="polite"><div class="webhook-health-head"><strong>告警投递健康</strong><button id="refresh-webhook-health" type="button" class="button ghost">↻ 刷新状态</button></div><p class="webhook-health-empty">正在读取通道状态…</p></section><label class="switch-setting"><span>每日首次引导弹窗</span><input name="publish_modal_enabled" type="checkbox" value="1"><small>开启后，访客每天首次访问会看到发布页与防失联指南。</small></label><label>自动通过阈值 N<input name="auto_approve_threshold" type="number" min="1" required><small>申请友链累计达到 N 个独立 IP 时自动转为审核通过。</small></label><label>本站专属友链地址<input name="site_url" type="url" required placeholder="https://your-site.example"></label><div class="settings-actions"><button class="button">保存系统设置</button><button id="test-webhook" class="button ghost" type="button">🔔 测试主通道</button><button id="test-bark" class="button ghost" type="button">📱 测试 Bark</button></div></form></div>`;
    const analytics = document.createElement('section'); analytics.id = 'analytics-settings'; analytics.className = 'analytics-settings-card'; analytics.innerHTML = `<div class="box analytics-box"><div class="box-head"><div><h2>第三方统计设置</h2><p class="hint">按需独立启用 Umami 与 Cloudflare Web Analytics；探针异步加载，不阻塞页面。</p></div></div><form id="analytics-settings-form" class="settings-form"><fieldset><legend>Umami</legend><label class="switch-setting"><span>启用 Umami 统计</span><input name="umami_enabled" type="checkbox" value="1"><small>启用后需填写 Website ID。</small></label><label>Umami Script URL<input name="umami_script_url" type="url" placeholder="https://cloud.umami.is/script.js"></label><label>Umami Website ID<input name="umami_website_id" placeholder="请输入 Umami Website ID"></label></fieldset><fieldset><legend>Cloudflare Web Analytics</legend><label class="switch-setting"><span>启用 Cloudflare Web Analytics</span><input name="cf_analytics_enabled" type="checkbox" value="1"><small>可与 Umami 同时启用。</small></label><label>Cloudflare Beacon Token<input name="cf_beacon_token" placeholder="请输入 Beacon Token"></label></fieldset><div class="settings-actions"><button id="save-analytics-settings" class="button" type="submit">保存第三方统计设置</button></div></form></div>`;
    const analyticsForm = analytics.querySelector('#analytics-settings-form'); const genericSettings = document.createElement('fieldset'); genericSettings.innerHTML = `<legend>自定义统计代码</legend><label class="switch-setting"><span>启用自定义统计代码</span><input name="generic_analytics_enabled" type="checkbox" value="1"><small>仅限管理员粘贴统计服务提供的完整 &lt;script&gt; 代码。</small></label><label>完整统计代码<textarea name="generic_analytics_code" rows="8" maxlength="12288" spellcheck="false" placeholder="&lt;script async src=&quot;https://example.com/tracker.js&quot;&gt;&lt;/script&gt;&#10;&lt;script&gt;/* 初始化代码 */&lt;/script&gt;"></textarea><small>仅允许 &lt;script&gt; 标签；不允许 iframe、document.write 或其他 HTML。</small></label>`; analyticsForm.insertBefore(genericSettings, analyticsForm.querySelector('.settings-actions'));
    const matrix = document.createElement('section'); matrix.id = 'matrix-sync-settings'; matrix.className = 'analytics-settings-card matrix-sync-card'; matrix.innerHTML = `<div class="box"><div class="box-head"><div><h2>CSV 全站矩阵</h2><p class="hint">Google Sheets 发布为 CSV 后，在这里配置数据源并按需同步或下载备份。</p></div></div><form id="matrix-url-form" class="settings-form matrix-url-form"><label>友链管理表 CSV 直链<input name="csv_url_partners" type="url" placeholder="https://docs.google.com/spreadsheets/.../pub?output=csv"></label><label>广告矩阵表 CSV 直链<input name="csv_url_ads" type="url" placeholder="https://docs.google.com/spreadsheets/.../pub?output=csv"></label><label>备用节点表 CSV 直链<input name="csv_url_mirrors" type="url" placeholder="https://docs.google.com/spreadsheets/.../pub?output=csv"></label><div class="matrix-control-row"><button id="save-matrix-urls" class="button ghost" type="submit" data-matrix-action>保存配置</button><button id="sync-matrix-all" class="button" type="button" data-matrix-action>⚡ 一键同步全站矩阵</button><details class="matrix-menu"><summary class="button ghost">⚡ 一键同步</summary><div class="matrix-menu-pop"><button type="button" data-sync-type="partners" data-matrix-action>同步友链</button><button type="button" data-sync-type="ads" data-matrix-action>同步广告</button><button type="button" data-sync-type="mirrors" data-matrix-action>同步节点</button><button type="button" data-sync-type="all" data-matrix-action>同步全部</button></div></details><details class="matrix-menu"><summary class="button ghost">⬇️ 下载备份</summary><div class="matrix-menu-pop"><button type="button" data-export-type="partners" data-matrix-action>下载友链</button><button type="button" data-export-type="ads" data-matrix-action>下载广告</button><button type="button" data-export-type="mirrors" data-matrix-action>下载节点</button><button type="button" data-export-type="all" data-matrix-action>下载全部 ZIP</button></div></details></div><div id="matrix-sync-log" class="matrix-sync-log" role="status" aria-live="polite">等待操作</div></form></div>`;
    settings.append(analytics, matrix); document.querySelector('.shell').append(review, settings); installLogoSettings(); installRiskControlFields();
    reviewButton.onclick = () => { switchTo('review', reviewButton); loadReview(); }; settingsButton.onclick = () => { switchTo('settings', settingsButton); loadAllSettings(); };
    document.querySelector('#refresh-review').onclick = loadReview; document.querySelector('#settings-form').onsubmit = saveSettings; document.querySelector('#analytics-settings-form').addEventListener('submit', saveAnalyticsConfig); document.querySelector('#test-webhook').onclick = testWebhook; document.querySelector('#test-bark').onclick = testBark; document.querySelector('#refresh-webhook-health').onclick = loadWebhookHealth;
  }

  async function loadReview() {
    if (!token()) return;
    try {
      const data = await api('/api/admin/review'); document.querySelector('#review-count').textContent = data.count;
      document.querySelector('#review-body').innerHTML = data.partners.map(item => `<tr><td class="site-cell"><b class="text-ellipsis" title="${esc(item.name)}">${esc(item.name)}</b><span class="site-domain" title="${esc(item.category || '未分类')}">${esc(item.category || '未分类')}</span></td><td><a href="${esc(item.url)}" target="_blank" rel="noopener" class="review-url text-ellipsis" title="${esc(item.url)}">${esc(item.url)}</a></td><td><span class="text-ellipsis review-description" title="${esc(item.description || '—')}">${esc(item.description || '—')}</span></td><td><span class="text-ellipsis review-contact" title="${esc(item.contact || '—')}">${esc(item.contact || '—')}</span></td><td class="score-center">${Number(item.score_24h || 0)}</td><td><span class="progress-pill">${Number(item.total_uv || 0)} / ${data.threshold}</span></td><td><span class="compact-time" title="${esc(item.created_at)}">${esc(time(item.created_at))}</span></td><td><div class="action-btn-group"><button class="btn-sm btn-action btn-pass approve-review" data-id="${item.id}">通过</button><button class="btn-sm btn-action btn-reject reject-review" data-id="${item.id}">拒绝</button></div></td></tr>`).join('') || '<tr><td class="empty-row" colspan="8">暂无待审核友链</td></tr>';
      document.querySelectorAll('.approve-review').forEach(button => button.onclick = () => reviewAction(button.dataset.id, 1)); document.querySelectorAll('.reject-review').forEach(button => button.onclick = () => reviewAction(button.dataset.id, 2));
    } catch (error) { toast(error.message); }
  }
  async function reviewAction(id, status) { if (status === 2 && !confirm('确定拒绝该申请吗？')) return; try { await api('/api/admin/partners/' + id, { method: 'PATCH', body: JSON.stringify({ is_approved: status }) }); toast(status === 1 ? '已手动审核通过' : '已拒绝申请'); loadReview(); window.loadPartners?.(); } catch (error) { toast(error.message); } }
  async function loadSettings() { try { const data = await api('/api/admin/settings'), form = document.querySelector('#settings-form'); Object.entries(data).forEach(([key, value]) => { if (!form.elements[key]) return; if (form.elements[key].type === 'checkbox') form.elements[key].checked = String(value) === '1'; else form.elements[key].value = value; }); const keyState = document.querySelector('#bark-key-state'); if (keyState) keyState.textContent = data.bark_device_key_configured ? '已保存 Device Key；留空表示不修改。' : '尚未保存 Device Key。'; setLogoPreview(form.elements.site_logo_url?.value); await loadWebhookHealth(); } catch (error) { toast(error.message); } }
  async function saveSettings(event) { event.preventDefault(); try { const form = event.currentTarget, payload = Object.fromEntries(new FormData(form)); payload.publish_modal_enabled = form.elements.publish_modal_enabled.checked ? '1' : '0'; payload.bark_enabled = form.elements.bark_enabled.checked ? '1' : '0'; if (!String(payload.bark_device_key || '').trim()) delete payload.bark_device_key; await api('/api/admin/settings', { method: 'POST', body: JSON.stringify(payload) }); await window.loadAdminBrand?.(); await loadSettings(); toast('系统设置已保存'); } catch (error) { toast(error.message); } }
  async function loadAnalyticsConfig() { try { const data = await api('/api/admin/analytics/config'), form = document.querySelector('#analytics-settings-form'); Object.entries(data).forEach(([key, value]) => { if (!form.elements[key]) return; if (form.elements[key].type === 'checkbox') form.elements[key].checked = String(value) === '1'; else form.elements[key].value = value; }); } catch (error) { toast(error.message); } }
  async function loadAllSettings() { return Promise.all([loadSettings(), loadAnalyticsConfig(), window.loadMatrixSettings?.()]); }
  async function saveAnalyticsConfig(event) { event.preventDefault(); const form = event.currentTarget, button = form.querySelector('#save-analytics-settings'); try { const payload = Object.fromEntries(new FormData(form)); ['umami_enabled', 'cf_analytics_enabled', 'generic_analytics_enabled'].forEach(key => { payload[key] = form.elements[key].checked ? '1' : '0'; }); if (payload.umami_enabled === '1' && !String(payload.umami_website_id || '').trim()) throw Error('启用 Umami 前请填写 Website ID'); if (payload.cf_analytics_enabled === '1' && !String(payload.cf_beacon_token || '').trim()) throw Error('启用 Cloudflare Web Analytics 前请填写 Beacon Token'); if (payload.generic_analytics_enabled === '1' && !String(payload.generic_analytics_code || '').trim()) throw Error('启用自定义统计代码前请粘贴完整的 <script> 代码'); if (button) { button.disabled = true; button.textContent = '保存中…'; } const data = await api('/api/admin/analytics/config', { method: 'POST', body: JSON.stringify(payload) }); Object.entries(data || {}).forEach(([key, value]) => { if (!form.elements[key]) return; if (form.elements[key].type === 'checkbox') form.elements[key].checked = String(value) === '1'; else form.elements[key].value = value; }); toast('第三方统计设置已保存，公开页面将在下次加载时生效'); } catch (error) { toast(error.message || '保存第三方统计设置失败'); } finally { if (button) { button.disabled = false; button.textContent = '保存第三方统计设置'; } } }
  function healthLabel(status) { return ({ healthy: '🟢 正常', degraded: '🟡 不稳定', offline: '🔴 故障', auth_error: '🔴 鉴权异常', unconfigured: '⚪ 未配置', untested: '⚪ 尚未投递' })[status] || '⚪ 未知'; }
  async function loadWebhookDeliveries() { const area = document.querySelector('#webhook-delivery-list'); if (!area) return; area.hidden = false; area.textContent = '正在读取最近投递记录…'; try { const data = await api('/api/admin/webhook/deliveries?limit=30'); const rows = data.deliveries || []; area.innerHTML = `<div class="webhook-delivery-table"><table><thead><tr><th>北京时间</th><th>事件</th><th>通道</th><th>结果</th><th>次数</th><th>耗时</th><th>原因</th></tr></thead><tbody>${rows.map(item => `<tr><td>${esc(time(item.created_at))}</td><td>${esc(item.event_type)}</td><td>${esc(item.provider)}${Number(item.is_fallback) ? '（备用）' : ''}</td><td>${Number(item.success) ? '🟢 成功' : '🔴 失败'}</td><td>${Number(item.attempt_count || 0)}</td><td>${item.duration_ms == null ? '—' : `${Number(item.duration_ms)}ms`}</td><td>${esc(item.error_message || (item.status_code ? `HTTP ${item.status_code}` : '—'))}</td></tr>`).join('') || '<tr><td colspan="7">暂无投递记录</td></tr>'}</tbody></table></div>`; } catch (error) { area.textContent = `读取失败：${error.message}`; } }
  async function loadWebhookHealth() { const card = document.querySelector('#webhook-health-card'); if (!card) return; try { const data = await api('/api/admin/webhook/health'); const primary = data.primary || {}, backup = data.backup || {}; card.innerHTML = `<div class="webhook-health-head"><strong>告警投递健康</strong><span><button id="refresh-webhook-health" type="button" class="button ghost">↻ 刷新状态</button><button id="show-webhook-deliveries" type="button" class="button ghost">查看最近投递</button></span></div><div class="webhook-health-grid"><p>主通道：${esc(primary.provider || 'none')} <b>${healthLabel(primary.status)}</b></p><p>备用通道：Bark <b>${healthLabel(backup.status)}</b></p><p>主通道连续失败：<b>${Number(primary.consecutiveFailures || 0)} 次</b></p><p>主通道近24h：成功 ${Number(primary.success24h || 0)} / 失败 ${Number(primary.failed24h || 0)} / ${Number(primary.successRate24h || 0).toFixed(1)}%</p><p>最近主通道成功：${esc(time(primary.lastSuccessAt))}</p><p>最近失败原因：${esc(primary.lastFailureReason || '—')}</p><p>最近 Bark 成功：${esc(time(backup.lastSuccessAt))}</p><p>最近故障转移：${esc(time(data.lastFallbackAt))}</p></div><div id="webhook-delivery-list" hidden></div>`; card.querySelector('#refresh-webhook-health')?.addEventListener('click', loadWebhookHealth); card.querySelector('#show-webhook-deliveries')?.addEventListener('click', loadWebhookDeliveries); } catch (error) { card.innerHTML = `<p class="webhook-health-empty">状态读取失败：${esc(error.message)}</p>`; } }
  async function testWebhook() { const button = document.querySelector('#test-webhook'); try { button.disabled = true; button.textContent = '发送中…'; const data = await api('/api/admin/settings/test-webhook', { method: 'POST' }); await loadWebhookHealth(); toast(data.result?.provider ? `主通道测试消息已通过 ${data.result.provider} 发送` : '主通道测试消息已发送'); } catch (error) { await loadWebhookHealth(); toast(error.message); } finally { button.disabled = false; button.textContent = '🔔 测试主通道'; } }
  async function testBark() { const button = document.querySelector('#test-bark'); try { button.disabled = true; button.textContent = '发送中…'; await api('/api/admin/settings/test-bark', { method: 'POST' }); await loadWebhookHealth(); toast('Bark 测试消息已发送'); } catch (error) { await loadWebhookHealth(); toast(error.message); } finally { button.disabled = false; button.textContent = '📱 测试 Bark'; } }
  const style = document.createElement('link'); style.rel = 'stylesheet'; style.href = '/admin/review.css?v=20260831-1'; document.head.append(style); const logoStyle = document.createElement('link'); logoStyle.rel = 'stylesheet'; logoStyle.href = '/admin/logo-settings.css?v=20260908-1'; document.head.append(logoStyle); install(); window.fetchPendingCount = loadReview; window.loadAdminSettings = loadAllSettings;
})();
