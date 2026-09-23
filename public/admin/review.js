/** 友链审核、Cloudflare 管理与系统设置：使用固定列宽表格，避免申请文本撑破布局。 */
(() => {
  const hasSession = () => window.adminSessionActive === true;
  const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
  const toast = text => { const el = document.querySelector('#toast'); if (!el) return; el.textContent = text; el.classList.add('show'); setTimeout(() => el.classList.remove('show'), 2400); };
  const api = async (url, options = {}) => { const response = await fetch(url, { ...options, credentials: 'same-origin', headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } }); const result = await response.json(); if (result.code !== 200) throw Error(result.msg || '请求失败'); return result.data; };
  const time = value => window.formatAdminTime?.(value) || '—';

  function localPublishLinkRow(item = {}) {
    const row = document.createElement('div'); row.className = 'local-publish-link-row';
    row.innerHTML = `<label>名称<input data-publish-label maxlength="80" value="${esc(item.label || '')}" placeholder="例如：备用网址"></label><label>地址<input data-publish-url type="url" value="${esc(item.url || '')}" placeholder="https://publish.example.com"></label><label>排序权重<input data-publish-weight type="number" min="-1000000" max="1000000" step="1" value="${Number(item.sort_weight || 0)}"></label><label class="publish-link-enabled"><input data-publish-enabled type="checkbox" ${item.enabled === 0 ? '' : 'checked'}>启用</label><button class="button ghost" type="button" data-remove-publish-link>删除</button>`;
    row.querySelector('[data-remove-publish-link]').onclick = () => row.remove();
    return row;
  }

  function renderPublishLinks(links = []) {
    const central = document.querySelector('#central-publish-links'), local = document.querySelector('#local-publish-links');
    if (!central || !local) return;
    const centralLinks = links.filter(item => item.source === 'control_center');
    central.innerHTML = centralLinks.length ? centralLinks.map(item => `<div class="central-publish-link"><strong>${esc(item.label)}</strong><a href="${esc(item.url)}" target="_blank" rel="noopener">${esc(item.url)}</a><span>权重 ${Number(item.sort_weight || 0)} · 总后台同步</span></div>`).join('') : '<p class="hint">总后台暂未下发永久发布页。</p>';
    local.innerHTML = '';
    links.filter(item => item.source === 'local').forEach(item => local.append(localPublishLinkRow(item)));
  }

  function collectLocalPublishLinks() {
    return [...document.querySelectorAll('#local-publish-links .local-publish-link-row')].map((row, index) => ({
      label: row.querySelector('[data-publish-label]').value.trim() || `自定义发布页 ${index + 1}`,
      url: row.querySelector('[data-publish-url]').value.trim(),
      enabled: row.querySelector('[data-publish-enabled]').checked,
      sort_weight: Number(row.querySelector('[data-publish-weight]').value || 0),
      sort_order: index
    })).filter(item => item.url);
  }

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
        const response = await fetch('/api/admin/settings', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ site_logo_url: '' }) });
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
        const response = await fetch('/api/admin/settings/logo', { method: 'POST', credentials: 'same-origin', body });
        const result = await response.json();
        if (result.code !== 200) throw Error(result.msg || 'Logo 上传失败');
        urlInput.value = result.data.site_logo_url; setLogoPreview(urlInput.value);
        await window.loadAdminBrand?.(); toast('Logo 上传成功，已应用到全站');
      } catch (error) { toast(error.message || 'Logo 上传失败'); }
      finally { button.disabled = false; button.textContent = '上传并使用 Logo'; }
    };
  }
  function installPublishLinkSettings() {
    const legacyInput = document.querySelector('#settings-form input[name="publish_url"]');
    if (!legacyInput) return;
    const fieldset = document.createElement('fieldset'); fieldset.id = 'publish-links-settings';
    fieldset.innerHTML = `<legend>永久发布页</legend><small>总后台发布页自动同步且只能在总后台修改；本站仍可添加自己的发布页。所有记录按权重从大到小显示，同权重时本站记录优先。</small><div id="central-publish-links"><p class="hint">正在读取总后台发布页…</p></div><div id="local-publish-links"></div><button id="add-local-publish-link" class="button ghost" type="button">＋ 新增本站发布页</button>`;
    legacyInput.closest('label').replaceWith(fieldset);
    fieldset.querySelector('#add-local-publish-link').onclick = () => fieldset.querySelector('#local-publish-links').append(localPublishLinkRow());
  }
  function install() {
    if (document.querySelector('#review-tab')) return;
    const tabs = document.querySelector('.tabs');
    const reviewButton = document.createElement('button'); reviewButton.id = 'review-tab'; reviewButton.innerHTML = '友链审核 <b id="review-count" class="review-badge" aria-live="polite">…</b>';
    const cloudflareButton = document.createElement('button'); cloudflareButton.id = 'cloudflare-tab'; cloudflareButton.textContent = 'Cloudflare 管理';
    const settingsButton = document.createElement('button'); settingsButton.id = 'settings-tab'; settingsButton.textContent = '系统设置'; tabs.append(reviewButton, cloudflareButton, settingsButton);
    const review = document.createElement('section'); review.id = 'review'; review.className = 'panel'; review.innerHTML = `<div class="box"><div class="box-head"><div><h2>友链审核</h2><p class="hint">待审核站点累计有效独立 IP 达到自动通过阈值后将自动上线。</p></div><button id="refresh-review" class="button ghost">刷新列表</button></div><div class="table-card"><div class="table-wrap"><table class="admin-table review-table"><colgroup><col class="review-col-site"><col class="review-col-url"><col class="review-col-description"><col class="review-col-contact"><col class="review-col-score"><col class="review-col-progress"><col class="review-col-time"><col class="review-col-actions"></colgroup><thead><tr><th>站点 / 分类</th><th>友链地址</th><th>一句话描述</th><th>申请人联系方式</th><th>24h 积分</th><th>入站进度</th><th>申请时间</th><th>操作</th></tr></thead><tbody id="review-body"></tbody></table></div></div></div>`;
    const cloudflare = document.createElement('section'); cloudflare.id = 'cloudflare'; cloudflare.className = 'panel'; cloudflare.innerHTML = `<div class="box cloudflare-overview"><div class="box-head"><div><h2>Cloudflare 管理</h2><p class="hint">首次建站信息由系统自动接管。这里展示真实运行状态，并集中维护中央线路、公共前台账号、独立 Worker 与可信前端域名。</p></div><button id="refresh-cloudflare" class="button ghost" type="button">刷新状态</button></div><div id="cloudflare-central-summary" class="cf-summary-grid" aria-live="polite"><p class="hint">正在读取中央线路…</p></div><div class="settings-actions cf-central-actions"><button class="button ghost" type="button" data-cf-central="verify">验证连接</button><button class="button ghost" type="button" data-cf-central="sync">同步全部前台白名单</button><button class="button ghost" type="button" data-cf-central="api">重新部署 API Worker</button><button class="button ghost" type="button" data-cf-central="admin">重新部署后台 Worker</button></div></div>`;
    const settings = document.createElement('section'); settings.id = 'settings'; settings.className = 'panel'; settings.innerHTML = `<div class="box settings-box"><div class="box-head"><div><h2>系统设置</h2><p class="hint">配置站点资料、发布页信息、自动审核规则与管理员告警。</p></div></div><form id="settings-form" class="settings-form"><label>站点名称<input name="site_name" required placeholder="例如：星环导航"></label><label>永久发布页地址<input name="publish_url" type="url" placeholder="https://pub.example.com"></label><label>防失联官方邮箱<input name="contact_email" type="email" placeholder="contact@yourdomain.com"><small>域名或发布页失效时，访客可向此邮箱获取最新地址。</small></label><label>其他联系方式<input name="contact_info" placeholder="@Telegram / QQ群 / 客服"><small>用于前台联系站长与统一引导弹窗展示。</small></label><label>管理员告警 Webhook 地址<input name="webhook_url" type="url" placeholder="Telegram Bot API 或企业微信机器人 Webhook 地址"><small>作为主告警通道；所有通知会自动带上当前站点名称。</small></label><fieldset id="bark-fallback-settings"><legend>Bark 备用告警</legend><label class="switch-setting"><span>启用 Bark 备用通道</span><input name="bark_enabled" type="checkbox" value="1"><small>仅当 Telegram / 企业微信主通道最终发送失败时接管，不重复推送。</small></label><label>Bark 服务地址<input name="bark_server_url" type="url" placeholder="https://api.day.app"><small>支持 HTTPS 自建 Bark 服务。</small></label><label>Bark Device Key<input name="bark_device_key" type="password" autocomplete="new-password" placeholder="留空表示不修改已保存密钥"><small id="bark-key-state">密钥仅保存于服务端，不会回显。</small></label><label>Bark 推送分组<input name="bark_group" maxlength="80" placeholder="星环导航告警"></label></fieldset><section id="webhook-health-card" class="webhook-health-card" aria-live="polite"><div class="webhook-health-head"><strong>告警投递健康</strong><button id="refresh-webhook-health" type="button" class="button ghost">↻ 刷新状态</button></div><p class="webhook-health-empty">正在读取通道状态…</p></section><label class="switch-setting"><span>每日首次引导弹窗</span><input name="publish_modal_enabled" type="checkbox" value="1"><small>开启后，访客每天首次访问会看到发布页与防失联指南。</small></label><label>自动通过阈值 N<input name="auto_approve_threshold" type="number" min="1" required><small>申请友链累计达到 N 个独立 IP 时自动转为审核通过。</small></label><label>本站专属友链地址<input name="site_url" type="url" required placeholder="https://your-site.example"></label><div class="settings-actions"><button class="button">保存系统设置</button><button id="test-webhook" class="button ghost" type="button">🔔 测试主通道</button><button id="test-bark" class="button ghost" type="button">📱 测试 Bark</button></div></form></div>`;
    const analytics = document.createElement('section'); analytics.id = 'analytics-settings'; analytics.className = 'analytics-settings-card'; analytics.innerHTML = `<div class="box analytics-box"><div class="box-head"><div><h2>第三方统计设置</h2><p class="hint">按需独立启用 Umami 与 Cloudflare Web Analytics；探针异步加载，不阻塞页面。</p></div></div><form id="analytics-settings-form" class="settings-form"><fieldset><legend>Umami</legend><label class="switch-setting"><span>启用 Umami 统计</span><input name="umami_enabled" type="checkbox" value="1"><small>启用后需填写 Website ID。</small></label><label>Umami Script URL<input name="umami_script_url" type="url" placeholder="https://cloud.umami.is/script.js"></label><label>Umami Website ID<input name="umami_website_id" placeholder="请输入 Umami Website ID"></label></fieldset><fieldset><legend>Cloudflare Web Analytics</legend><label class="switch-setting"><span>启用 Cloudflare Web Analytics</span><input name="cf_analytics_enabled" type="checkbox" value="1"><small>可与 Umami 同时启用。</small></label><label>Cloudflare Beacon Token<input name="cf_beacon_token" placeholder="请输入 Beacon Token"></label></fieldset><div class="settings-actions"><button id="save-analytics-settings" class="button" type="submit">保存第三方统计设置</button></div></form></div>`;
    const analyticsForm = analytics.querySelector('#analytics-settings-form'); const genericSettings = document.createElement('fieldset'); genericSettings.innerHTML = `<legend>自定义统计代码</legend><label class="switch-setting"><span>启用自定义统计代码</span><input name="generic_analytics_enabled" type="checkbox" value="1"><small>仅限管理员粘贴统计服务提供的完整 &lt;script&gt; 代码。</small></label><label>完整统计代码<textarea name="generic_analytics_code" rows="8" maxlength="12288" spellcheck="false" placeholder="&lt;script async src=&quot;https://example.com/tracker.js&quot;&gt;&lt;/script&gt;&#10;&lt;script&gt;/* 初始化代码 */&lt;/script&gt;"></textarea><small>仅允许 &lt;script&gt; 标签；不允许 iframe、document.write 或其他 HTML。</small></label>`; analyticsForm.insertBefore(genericSettings, analyticsForm.querySelector('.settings-actions'));
    const matrix = document.createElement('section'); matrix.id = 'matrix-sync-settings'; matrix.className = 'analytics-settings-card matrix-sync-card'; matrix.innerHTML = `<div class="box"><div class="box-head"><div><h2>友链 CSV 同步</h2><p class="hint">广告与节点已由总后台统一管理；导航站仅保留友链 CSV 数据源、同步和备份。</p></div></div><form id="matrix-url-form" class="settings-form matrix-url-form"><label>友链管理表 CSV 直链<input name="csv_url_partners" type="url" placeholder="https://docs.google.com/spreadsheets/.../pub?output=csv"></label><div class="matrix-control-row"><button id="save-matrix-urls" class="button ghost" type="submit" data-matrix-action>保存配置</button><button id="sync-matrix-partners" class="button" type="button" data-matrix-action>同步友链</button><button id="download-matrix-partners" class="button ghost" type="button" data-matrix-action>下载友链</button></div><div id="matrix-sync-log" class="matrix-sync-log" role="status" aria-live="polite">等待操作</div></form></div>`;
    const frontendOrigins = document.createElement('section'); frontendOrigins.id = 'frontend-origin-settings'; frontendOrigins.className = 'analytics-settings-card'; frontendOrigins.innerHTML = `<div class="box"><div class="box-head"><div><h2>公共前端域名</h2><p class="hint">仅允许这些前端 Origin 通过可信边缘代理访问公开业务接口；签名密钥不会回显到浏览器。</p></div></div><form id="frontend-origin-form" class="settings-form"><label>前端 Origin 白名单<textarea name="origins" rows="6" spellcheck="false" placeholder="https://www.example.com | 1 | 2026-12-31T16:00:00Z"></textarea><small>每行格式：Origin | 启用(1/0) | 过期时间(选填)。必须填写完整 Origin，不支持通配符。</small></label><p id="frontend-origin-state" class="hint" role="status" aria-live="polite">正在读取代理状态…</p><div class="settings-actions"><button id="save-frontend-origins" class="button" type="submit">保存前端域名</button></div></form></div>`;
    const apiEdge = document.createElement('section'); apiEdge.id = 'api-edge-sync-settings'; apiEdge.className = 'analytics-settings-card'; apiEdge.innerHTML = `<div class="box"><div class="box-head"><div><h2>中央线路与公共前台</h2><p class="hint">中央线路只保留一个凭据入口；公共前台账号独立管理。所有 Token 仅保存于服务端受限凭据文件中，永不回显。</p></div></div><form id="cloudflare-central-access-form" class="settings-form"><fieldset><legend id="cloudflare-central-access-legend">接管现有中央线路</legend><p id="cloudflare-central-access-help" class="hint">系统只验证并接管已经运行的 API 与后台 Worker，不会重新部署或覆盖它们。</p><label>Cloudflare Account ID<input name="accountId" autocomplete="off" inputmode="text" placeholder="32 位 Account ID" required></label><label>Cloudflare API Token<input name="apiToken" type="password" autocomplete="new-password" placeholder="首次接管必须填写" required><small id="cloudflare-central-token-state">Token 仅保存在服务器；验证成功后不会回显。</small></label><div class="cf-readonly-grid" aria-label="现有中央线路配置"><label>源站地址<input name="originUrl" type="url" readonly></label><label>API 域名<input name="apiDomain" readonly></label><label>API Worker<input name="apiWorkerName" readonly></label><label>后台域名<input name="adminDomain" readonly></label><label>后台 Worker<input name="adminWorkerName" readonly></label></div><p id="cloudflare-central-access-state" class="hint" role="status" aria-live="polite">正在读取中央线路状态…</p><div class="settings-actions"><button id="save-cloudflare-central-access" class="button" type="submit">验证并接管现有线路</button></div></fieldset></form><form id="public-frontend-profile-form" class="settings-form"><fieldset><legend>公共前台 Cloudflare 账号</legend><label class="switch-setting"><span>复用中央账号凭据</span><input name="reuseCentralCredential" type="checkbox" value="1"><small>仅当公共前台与中央线路位于同一 Cloudflare 账号时启用，避免重复输入 Token。</small></label><label>配置标识<input name="id" autocomplete="off" pattern="[a-z0-9][a-z0-9_-]{0,31}" placeholder="例如：cf-main" required><small>用于后续修改该账号配置，只能使用小写字母、数字、连字符或下划线。</small></label><label>显示名称<input name="label" autocomplete="off" placeholder="例如：主账号" required></label><label>Cloudflare Account ID<input name="accountId" autocomplete="off" placeholder="该前台域名所在账号的 32 位 Account ID" required></label><label>新前台 Worker 前缀<input name="workerPrefix" autocomplete="off" placeholder="例如：webring-public"><small>保存新账号时自动部署首个 Worker；之后每个新前台域名都会获得独立 Worker。</small></label><label>Cloudflare API Token<input name="apiToken" type="password" autocomplete="new-password" placeholder="首次填写；更新时留空表示不修改" required><small>无需填写根域名。系统自动查询此账号全部 Active Zone。</small></label><div class="settings-actions"><button id="save-public-frontend-profile" class="button ghost" type="submit">验证、保存并初始化 Worker</button></div><p id="public-frontend-profile-state" class="hint" role="status" aria-live="polite">尚未配置公共前台账号。</p></fieldset></form><form id="create-public-frontend-form" class="settings-form"><fieldset><legend>一键生成独立前台</legend><label>新前台域名<input name="hostname" type="text" inputmode="url" autocomplete="off" placeholder="例如：qiantai2.chinazhangsan.ccwu.cc" required><small>系统自动识别账号与 Active Zone，部署全新独立 Worker、绑定域名、同步两层白名单并进行健康检查。</small><small><strong>免费版提醒：</strong>首次使用某个根域前，请在 Cloudflare「安全性 → 设置 → 机器人流量」中手动开启 Bot Fight 模式；同一根域只需开启一次。</small></label><div class="settings-actions"><button id="create-public-frontend" class="button" type="submit">生成独立前台</button></div><p id="create-public-frontend-state" class="hint" role="status" aria-live="polite">请先配置至少一个公共前台 Cloudflare 账号。</p></fieldset></form></div>`;
    const inventory = document.createElement('section'); inventory.id = 'cloudflare-inventory'; inventory.className = 'analytics-settings-card'; inventory.innerHTML = `<div class="box"><div class="box-head"><div><h2>Cloudflare 资源清单</h2><p class="hint">Account ID 在创建 Worker 后自动锁定；更换账号请新增配置，旧资源默认保留。</p></div></div><h3>公共前台账号</h3><div class="table-wrap"><table class="admin-table"><thead><tr><th>配置</th><th>Account ID</th><th>Token</th><th>Active Zone</th><th>Worker</th><th>分配状态</th><th>操作</th></tr></thead><tbody id="cloudflare-account-body"><tr><td colspan="7">正在加载…</td></tr></tbody></table></div><h3>前台域名与 Worker</h3><div class="table-wrap"><table class="admin-table"><thead><tr><th>前台域名</th><th>恢复方案</th><th>所属账号</th><th>Worker</th><th>Domain ID</th><th>健康状态</th><th>最近检测</th><th>操作</th></tr></thead><tbody id="cloudflare-worker-body"><tr><td colspan="8">正在加载…</td></tr></tbody></table></div></div>`;
    const migrationBox = document.createElement('div'); migrationBox.className = 'cf-migration-box'; migrationBox.innerHTML = `<h3>同域名跨账号迁移</h3><p class="hint">先在目标账号准备新 Worker；完成 Nameserver 切换且目标 Zone 变为 Active 后，再执行正式切换。旧 Worker 默认保留。</p><form id="cloudflare-migration-form" class="settings-form cf-migration-form"><label>需要迁移的前台<select name="hostname" required><option value="">请选择前台域名</option></select></label><label>目标 Cloudflare 账号<select name="targetAccountProfileId" required><option value="">请选择目标账号</option></select></label><div class="settings-actions"><button class="button" type="submit">准备迁移 Worker</button></div></form><div id="cloudflare-migration-progress" class="cf-migration-progress" hidden><p>迁移任务 <strong data-field="id">—</strong>：<span data-field="state">—</span></p><div class="settings-actions"><button class="button" type="button" data-cf-migration="cutover">正式切换</button><button class="button ghost" type="button" data-cf-migration="rollback">回滚准备任务</button><button class="button ghost" type="button" data-cf-migration="complete">确认完成</button></div></div>`; inventory.querySelector('.box').append(migrationBox);
    const deleteDialog = document.createElement('dialog'); deleteDialog.id = 'cloudflare-delete-dialog'; deleteDialog.className = 'cf-danger-dialog'; deleteDialog.innerHTML = `<form id="cloudflare-delete-form" class="settings-form"><h3>删除远端 Cloudflare 资源</h3><p class="hint">该操作会删除 Custom Domain 和 Worker 脚本，本地审计记录仍保留。请输入完整域名和管理员密码确认。</p><input name="workerId" type="hidden"><label>完整前台域名<input name="confirmHostname" autocomplete="off" required></label><label>管理员密码<input name="password" type="password" autocomplete="current-password" required></label><div class="settings-actions"><button class="button danger" type="submit">确认删除远端资源</button><button class="button ghost" type="button" data-close-cf-dialog>取消</button></div></form>`; inventory.querySelector('.box').append(deleteDialog);
    settings.append(analytics, matrix); cloudflare.append(apiEdge, inventory, frontendOrigins); document.querySelector('.shell').append(review, cloudflare, settings);
    const frontendRecoveryLabel = document.createElement('label'); frontendRecoveryLabel.className = 'frontend-recovery-profile'; frontendRecoveryLabel.innerHTML = `随站发布的恢复方案<select name="recoveryProfileId" required><option value="">正在读取恢复方案…</option></select><small>每个独立前台必须绑定一套已启用且已发布的恢复方案；发布后该前台只接收该方案的备用域名和 DNS/TXT 查询线路。</small>`;
    document.querySelector('#create-public-frontend-form fieldset')?.insertBefore(frontendRecoveryLabel, document.querySelector('#create-public-frontend-form .settings-actions'));
    installLogoSettings(); installRiskControlFields(); installPublishLinkSettings();
    reviewButton.onclick = () => { switchTo('review', reviewButton); loadReview(); }; cloudflareButton.onclick = () => { switchTo('cloudflare', cloudflareButton); loadCloudflareSettings(); }; settingsButton.onclick = () => { switchTo('settings', settingsButton); loadAllSettings(); };
    document.querySelector('#refresh-review').onclick = loadReview; document.querySelector('#settings-form').onsubmit = saveSettings; document.querySelector('#analytics-settings-form').addEventListener('submit', saveAnalyticsConfig); document.querySelector('#frontend-origin-form').addEventListener('submit', saveFrontendOrigins); document.querySelector('#cloudflare-central-access-form').addEventListener('submit', saveCloudflareCentralAccess); document.querySelector('#public-frontend-profile-form').addEventListener('submit', savePublicFrontendProfile); document.querySelector('#public-frontend-profile-form').elements.reuseCentralCredential.addEventListener('change', syncCentralCredentialChoice); document.querySelector('#create-public-frontend-form').addEventListener('submit', createPublicFrontend); document.querySelector('#cloudflare-migration-form').addEventListener('submit', prepareCloudflareMigration); document.querySelector('#cloudflare-delete-form').addEventListener('submit', deleteCloudflareRemote); document.querySelector('[data-close-cf-dialog]').onclick = () => document.querySelector('#cloudflare-delete-dialog').close(); document.querySelector('#refresh-cloudflare').onclick = loadCloudflareSettings; document.querySelector('#cloudflare').addEventListener('click', handleCloudflareAction); document.querySelector('#test-webhook').onclick = testWebhook; document.querySelector('#test-bark').onclick = testBark; document.querySelector('#refresh-webhook-health').onclick = loadWebhookHealth;
  }

  async function loadReview() {
    if (!hasSession()) return;
    try {
      const data = await api('/api/admin/review'); setReviewCount(data.count);
      document.querySelector('#review-body').innerHTML = data.partners.map(item => `<tr><td class="site-cell"><b class="text-ellipsis" title="${esc(item.name)}">${esc(item.name)}</b><span class="site-domain" title="${esc(item.category || '未分类')}">${esc(item.category || '未分类')}</span></td><td><a href="${esc(item.url)}" target="_blank" rel="noopener" class="review-url text-ellipsis" title="${esc(item.url)}">${esc(item.url)}</a></td><td><span class="text-ellipsis review-description" title="${esc(item.description || '—')}">${esc(item.description || '—')}</span></td><td><span class="text-ellipsis review-contact" title="${esc(item.contact || '—')}">${esc(item.contact || '—')}</span></td><td class="score-center">${Number(item.score_24h || 0)}</td><td><span class="progress-pill">${Number(item.total_uv || 0)} / ${data.threshold}</span></td><td><span class="compact-time" title="${esc(item.created_at)}">${esc(time(item.created_at))}</span></td><td><div class="action-btn-group"><button class="btn-sm btn-action btn-pass approve-review" data-id="${item.id}">通过</button><button class="btn-sm btn-action btn-reject reject-review" data-id="${item.id}">拒绝</button></div></td></tr>`).join('') || '<tr><td class="empty-row" colspan="8">暂无待审核友链</td></tr>';
      document.querySelectorAll('.approve-review').forEach(button => button.onclick = () => reviewAction(button.dataset.id, 1)); document.querySelectorAll('.reject-review').forEach(button => button.onclick = () => reviewAction(button.dataset.id, 2));
    } catch (error) { toast(error.message); }
  }

  function setReviewCount(value) {
    const badge = document.querySelector('#review-count');
    if (badge) badge.textContent = String(Number(value || 0));
  }

  async function refreshReviewCount() {
    if (!hasSession()) return;
    try {
      const data = await api('/api/admin/review/count');
      setReviewCount(data.count);
    } catch {
      const badge = document.querySelector('#review-count');
      if (badge) { badge.textContent = '—'; badge.title = '待审核数量加载失败'; }
    }
  }
  async function reviewAction(id, status) { if (status === 2 && !confirm('确定拒绝该申请吗？')) return; try { await api('/api/admin/partners/' + id, { method: 'PATCH', body: JSON.stringify({ is_approved: status }) }); toast(status === 1 ? '已手动审核通过' : '已拒绝申请'); loadReview(); window.loadPartners?.(); } catch (error) { toast(error.message); } }
  async function loadSettings() { try { const data = await api('/api/admin/settings'), form = document.querySelector('#settings-form'); Object.entries(data).forEach(([key, value]) => { if (!form.elements[key]) return; if (form.elements[key].type === 'checkbox') form.elements[key].checked = String(value) === '1'; else form.elements[key].value = value; }); setLogoPreview(form.elements.site_logo_url?.value); } catch (error) { toast(error.message); } }
  async function loadPublishLinks() { try { const data = await api('/api/admin/publish-links'); renderPublishLinks(data.links || []); } catch (error) { toast(error.message); } }
  async function saveSettings(event) { event.preventDefault(); try { const form = event.currentTarget, payload = Object.fromEntries(new FormData(form)); payload.publish_modal_enabled = form.elements.publish_modal_enabled.checked ? '1' : '0'; await api('/api/admin/publish-links/local', { method: 'PUT', body: JSON.stringify({ links: collectLocalPublishLinks() }) }); await api('/api/admin/settings', { method: 'POST', body: JSON.stringify(payload) }); await window.loadAdminBrand?.(); await Promise.all([loadSettings(), loadPublishLinks()]); toast('系统设置已保存'); } catch (error) { toast(error.message); } }
  async function loadAnalyticsConfig() { try { const data = await api('/api/admin/analytics/config'), form = document.querySelector('#analytics-settings-form'); Object.entries(data).forEach(([key, value]) => { if (!form.elements[key]) return; if (form.elements[key].type === 'checkbox') form.elements[key].checked = String(value) === '1'; else form.elements[key].value = value; }); } catch (error) { toast(error.message); } }
  async function loadFrontendOrigins() { try { const data = await api('/api/admin/frontend-origins'), form = document.querySelector('#frontend-origin-form'), state = document.querySelector('#frontend-origin-state'); if (!form) return; form.elements.origins.value = (data.origins || []).map(item => [item.origin, item.enabled ? '1' : '0', item.expiresAt || ''].join(' | ').replace(/\s+\|\s*$/, '')).join('\n'); if (state) state.textContent = `代理签名：${data.frontendProxyConfigured ? '已配置' : '未配置'}；API Edge：${data.edgeSync?.configured ? '自动同步已配置' : '尚未配置自动同步'}`; } catch (error) { toast(error.message); } }
  async function loadCloudflareCentralAccess() {
    try {
      const data = await api('/api/admin/integrations/cloudflare-bootstrap'), form = document.querySelector('#cloudflare-central-access-form');
      if (!form) return;
      ['accountId', 'originUrl', 'apiDomain', 'apiWorkerName', 'adminDomain', 'adminWorkerName'].forEach(key => { form.elements[key].value = data[key] || ''; });
      form.elements.apiToken.value = '';
      form.dataset.configured = data.configured ? '1' : '0';
      form.elements.accountId.readOnly = Boolean(data.configured);
      form.elements.apiToken.required = !data.apiTokenConfigured;
      const reuseControl = document.querySelector('#public-frontend-profile-form')?.elements.reuseCentralCredential;
      if (reuseControl) { reuseControl.disabled = !data.configured; if (!data.configured) reuseControl.checked = false; }
      document.querySelector('#cloudflare-central-access-legend').textContent = data.configured ? '中央线路凭据' : '接管现有中央线路';
      document.querySelector('#cloudflare-central-access-help').textContent = data.configured ? '中央线路已经接管。这里只用于轮换 Token；域名、源站和 Worker 名称由运行配置锁定。' : '系统只验证并接管已经运行的 API 与后台 Worker，不会重新部署或覆盖它们。';
      document.querySelector('#cloudflare-central-token-state').textContent = data.apiTokenConfigured ? '已保存 Token；留空表示保持不变。' : '尚未保存 Token；接管时必须填写。';
      document.querySelector('#cloudflare-central-access-state').textContent = data.configured ? '中央 API、后台 Worker 与白名单同步已统一接管。' : '尚未接管；请填写账号和 Token 完成一次验证。';
      document.querySelector('#save-cloudflare-central-access').textContent = data.configured ? '验证并更新 Token' : '验证并接管现有线路';
      syncCentralCredentialChoice();
    } catch (error) { toast(error.message || '读取中央线路状态失败'); }
  }
  async function saveCloudflareCentralAccess(event) {
    event.preventDefault();
    const form = event.currentTarget, button = form.querySelector('#save-cloudflare-central-access'), state = form.querySelector('#cloudflare-central-access-state'), configured = form.dataset.configured === '1';
    try {
      button.disabled = true; button.textContent = configured ? '正在验证新 Token…' : '正在核对现有 Worker…';
      const payload = { accountId: form.elements.accountId.value, apiToken: form.elements.apiToken.value };
      if (configured) {
        payload.workerName = form.elements.apiWorkerName.value;
        await api('/api/admin/integrations/cloudflare-api-edge', { method: 'PUT', body: JSON.stringify(payload) });
      } else {
        Object.assign(payload, { originUrl: form.elements.originUrl.value, apiDomain: form.elements.apiDomain.value, apiWorkerName: form.elements.apiWorkerName.value, adminDomain: form.elements.adminDomain.value, adminWorkerName: form.elements.adminWorkerName.value });
        await api('/api/admin/integrations/cloudflare-bootstrap/adopt', { method: 'POST', body: JSON.stringify(payload) });
      }
      form.elements.apiToken.value = '';
      state.textContent = configured ? '新 Token 已验证并更新。' : '现有中央线路已验证并接管，没有重新部署 Worker。';
      await Promise.all([loadCloudflareCentralAccess(), loadCloudflareOverview(), loadFrontendOrigins()]);
      toast(configured ? '中央 Token 已安全更新' : '现有中央线路已接管');
    } catch (error) { state.textContent = `操作未完成：${error.message}`; toast(error.message || '中央线路操作失败'); }
    finally { button.disabled = false; button.textContent = configured ? '验证并更新 Token' : '验证并接管现有线路'; }
  }
  function syncCentralCredentialChoice() {
    const form = document.querySelector('#public-frontend-profile-form'), centralForm = document.querySelector('#cloudflare-central-access-form');
    if (!form || !centralForm) return;
    const reuse = form.elements.reuseCentralCredential.checked;
    form.elements.accountId.readOnly = reuse;
    form.elements.apiToken.disabled = reuse;
    form.elements.apiToken.required = !reuse && !form.elements.id.value;
    if (reuse) { form.elements.accountId.value = centralForm.elements.accountId.value; form.elements.apiToken.value = ''; }
  }
  async function loadPublicFrontendProfiles() { try { const [data, recoveryProfiles] = await Promise.all([api('/api/admin/integrations/cloudflare-public-frontends'), api('/api/admin/recovery/profiles')]), button = document.querySelector('#create-public-frontend'), state = document.querySelector('#create-public-frontend-state'), profileState = document.querySelector('#public-frontend-profile-state'), form = document.querySelector('#public-frontend-profile-form'), createForm = document.querySelector('#create-public-frontend-form'); const profiles = data.profiles || [], readyRecovery = (recoveryProfiles || []).filter(profile => Number(profile.enabled) === 1 && profile.status === 'active' && Number(profile.current_generation) > 0); if (form) { form.elements.apiToken.required = profiles.length === 0 && !form.elements.reuseCentralCredential.checked; syncCentralCredentialChoice(); } if (createForm?.elements.recoveryProfileId) createForm.elements.recoveryProfileId.innerHTML = `<option value="">请选择恢复方案</option>${readyRecovery.map(profile => `<option value="${Number(profile.id)}">${esc(profile.name)} · generation ${Number(profile.current_generation)}</option>`).join('')}`; if (button) button.disabled = profiles.length === 0 || readyRecovery.length === 0; if (state) state.textContent = !profiles.length ? '请先配置至少一个公共前台 Cloudflare 账号。' : !readyRecovery.length ? '请先在“恢复系统”中启用并发布至少一套正式恢复方案。' : `已配置 ${profiles.length} 个账号，可选择 ${readyRecovery.length} 套已发布恢复方案。`; if (profileState) profileState.textContent = profiles.length ? `已配置：${profiles.map(profile => `${profile.label}（前缀：${profile.workerPrefix}；初始化：${profile.initialized ? '完成' : '待处理'}；已记录 Worker：${(profile.workers || []).length}）`).join('；')}` : '尚未配置公共前台账号。'; } catch (error) { toast(error.message); } }
  async function savePublicFrontendProfile(event) { event.preventDefault(); const form = event.currentTarget, button = form.querySelector('#save-public-frontend-profile'); try { button.disabled = true; button.textContent = '验证并初始化中…'; const result = await api(`/api/admin/integrations/cloudflare-public-frontends/${encodeURIComponent(form.elements.id.value.trim())}`, { method: 'PUT', body: JSON.stringify({ label: form.elements.label.value, accountId: form.elements.accountId.value, workerPrefix: form.elements.workerPrefix.value, apiToken: form.elements.apiToken.value, reuseCentralCredential: form.elements.reuseCentralCredential.checked }) }); form.elements.apiToken.value = ''; await loadPublicFrontendProfiles(); toast(result.profile?.initialization?.error ? `账号已保存，但首个 Worker 未创建：${result.profile.initialization.error}` : '公共前台账号已验证并初始化首个 Worker'); } catch (error) { toast(error.message || '保存公共前台账号失败'); } finally { button.disabled = false; button.textContent = '验证、保存并初始化 Worker'; } }
  async function createPublicFrontend(event) { event.preventDefault(); const form = event.currentTarget, button = form.querySelector('#create-public-frontend'), hostname = String(form.elements.hostname.value || '').trim(), recoveryProfileId = Number(form.elements.recoveryProfileId.value); if (!recoveryProfileId) return toast('请选择要随该前台发布的恢复方案'); if (!confirm(`确定创建并启用独立前台 ${hostname} 吗？该域名会部署一个全新的 Worker，并绑定所选恢复方案。\n\n免费版提醒：请确认该根域已在 Cloudflare 控制台手动开启 Bot Fight 模式。`)) return; try { button.disabled = true; button.textContent = '部署独立 Worker 中…'; const result = await api('/api/admin/public-frontends', { method: 'POST', body: JSON.stringify({ hostname, recoveryProfileId }) }); const state = document.querySelector('#create-public-frontend-state'), status = result.health?.healthy ? `已创建独立 Worker ${esc(result.service)}：<a href="${esc(result.url)}" target="_blank" rel="noopener">${esc(result.url)}</a>，健康检查通过。` : `已创建独立 Worker ${esc(result.service)} 与 ${esc(result.url)}，Cloudflare 正在配置证书或路由，请稍后刷新验证。`; if (state) state.innerHTML = `${status}<br><strong>已绑定恢复方案：${esc(result.recoveryProfile?.name || '—')}。请确认该根域的 Cloudflare 免费版 Bot Fight 模式已经手动开启。</strong>`; form.elements.hostname.value = ''; await Promise.all([loadFrontendOrigins(), loadCloudflareCentralAccess(), loadPublicFrontendProfiles()]); alert(`独立前台生成流程已完成。\n\n已绑定恢复方案：${result.recoveryProfile?.name || '—'}。\n请确认该根域已手动开启 Bot Fight 模式。`); toast(result.health?.healthy ? '新独立前台已创建并可访问' : '新独立前台已创建，等待 Cloudflare 生效'); } catch (error) { toast(error.message || '创建新独立前台失败'); } finally { button.disabled = false; button.textContent = '生成独立前台'; } }
  async function saveFrontendOrigins(event) { event.preventDefault(); const form = event.currentTarget, button = form.querySelector('#save-frontend-origins'); try { const origins = String(form.elements.origins.value || '').split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => { const [origin, enabled = '1', expiresAt = ''] = line.split('|').map(value => value.trim()); return { origin, enabled, expiresAt: expiresAt || null }; }); button.disabled = true; button.textContent = '保存中…'; const result = await api('/api/admin/frontend-origins', { method: 'PUT', body: JSON.stringify({ origins }) }); await loadFrontendOrigins(); toast(result.edgeSync?.synchronized ? '前端域名已保存并同步 API Edge' : '前端域名已保存；API Edge 自动同步尚未配置'); } catch (error) { toast(error.message || '保存公共前端域名失败'); } finally { button.disabled = false; button.textContent = '保存前端域名'; } }
  const cfState = value => ({ valid: '正常', invalid: '失效或权限不足', unverified: '待验证', missing: '未配置', ready: '正常', failed: '异常', creating: '创建中' })[value] || value || '未知';
  const cfHealth = value => value?.healthy || value?.reachable ? '正常' : value ? '异常' : '未检测';
  async function loadCloudflareOverview() {
    const summary = document.querySelector('#cloudflare-central-summary'), accountBody = document.querySelector('#cloudflare-account-body'), workerBody = document.querySelector('#cloudflare-worker-body');
    if (!summary || !accountBody || !workerBody) return;
    try {
      const data = await api('/api/admin/cloudflare/overview'), central = data.central || {}, accounts = data.accounts || [], workers = data.workers || [];
      summary.innerHTML = `<div><small>中央账号</small><strong>${esc(central.accountId || '未配置')}</strong></div><div><small>API 线路</small><strong>${esc(central.apiDomain || '—')}</strong><span>${esc(central.apiWorkerName || '—')} · ${cfHealth(central.apiHealth)}</span></div><div><small>后台线路</small><strong>${esc(central.adminDomain || '—')}</strong><span>${esc(central.adminWorkerName || '—')} · ${cfHealth(central.adminHealth)}</span></div><div><small>源站</small><strong>${esc(central.originUrl || '—')}</strong></div><div><small>Token</small><strong>${esc(cfState(central.tokenStatus))}${central.tokenFingerprint ? ` · …${esc(central.tokenFingerprint)}` : ''}</strong><span>最近验证：${esc(time(central.lastVerifiedAt))}</span></div><div><small>最近部署</small><strong>${esc(time(central.lastDeployedAt))}</strong></div>`;
      accountBody.innerHTML = accounts.map(item => `<tr><td><strong>${esc(item.label)}</strong><br><small>${esc(item.id)}</small></td><td class="mono-cell">${esc(item.accountId)}</td><td><span class="tag ${item.tokenStatus === 'valid' ? 'on' : item.tokenStatus === 'invalid' ? 'off' : 'warn'}">${esc(cfState(item.tokenStatus))}</span>${item.tokenFingerprint ? `<br><small>…${esc(item.tokenFingerprint)}</small>` : ''}</td><td>${(item.activeZones || []).map(zone => `<span class="tag">${esc(zone)}</span>`).join(' ') || '—'}</td><td>${Number((item.workers || []).length)}</td><td>${item.allocationEnabled ? '<span class="tag on">允许新建</span>' : '<span class="tag warn">已停止分配</span>'}</td><td><div class="action-btn-group"><button class="button ghost" type="button" data-cf-account="edit" data-id="${esc(item.id)}">更新 Token</button><button class="button ghost" type="button" data-cf-account="verify" data-id="${esc(item.id)}">验证</button><button class="button ghost" type="button" data-cf-account="reconcile" data-id="${esc(item.id)}">对账</button><button class="button ghost" type="button" data-cf-account="toggle" data-id="${esc(item.id)}" data-enabled="${item.allocationEnabled ? '0' : '1'}">${item.allocationEnabled ? '停止分配' : '恢复分配'}</button></div></td></tr>`).join('') || '<tr><td colspan="7">尚未配置公共前台账号</td></tr>';
      workerBody.innerHTML = workers.filter(item => item.hostname).map(item => `<tr><td><a href="https://${esc(item.hostname)}" target="_blank" rel="noopener">${esc(item.hostname)}</a></td><td><strong>${esc(item.recoveryProfileName || '未绑定')}</strong><br><small>方案 #${Number(item.recoveryProfileId || 0) || '—'}</small></td><td>${esc(item.accountLabel)}<br><small>${esc(item.accountProfileId)}</small></td><td class="mono-cell">${esc(item.workerName)}</td><td class="mono-cell">${esc(item.domainId || '—')}</td><td><span class="tag ${item.health?.healthy ? 'on' : item.state === 'failed' ? 'off' : 'warn'}">${esc(item.health?.healthy ? '正常' : cfState(item.state))}</span></td><td>${esc(time(item.lastHealthAt))}</td><td><div class="action-btn-group"><button class="button ghost" type="button" data-cf-worker="health" data-id="${Number(item.id)}">健康检查</button><button class="button ghost" type="button" data-cf-worker="redeploy" data-id="${Number(item.id)}">重新部署</button><button class="button ghost" type="button" data-cf-worker="delete" data-id="${Number(item.id)}" data-hostname="${esc(item.hostname)}">删除远端</button></div></td></tr>`).join('') || '<tr><td colspan="8">尚未创建已绑定域名的前台 Worker</td></tr>';
      const migrationForm = document.querySelector('#cloudflare-migration-form');
      if (migrationForm) {
        const currentHost = migrationForm.elements.hostname.value, currentTarget = migrationForm.elements.targetAccountProfileId.value;
        migrationForm.elements.hostname.innerHTML = `<option value="">请选择前台域名</option>${workers.filter(item => item.hostname).map(item => `<option value="${esc(item.hostname)}">${esc(item.hostname)} · ${esc(item.accountLabel)}</option>`).join('')}`;
        migrationForm.elements.targetAccountProfileId.innerHTML = `<option value="">请选择目标账号</option>${accounts.filter(item => item.allocationEnabled).map(item => `<option value="${esc(item.id)}">${esc(item.label)} · ${esc(item.accountId)}</option>`).join('')}`;
        migrationForm.elements.hostname.value = currentHost; migrationForm.elements.targetAccountProfileId.value = currentTarget;
      }
      const activeMigration = (data.migrations || []).find(item => !['completed', 'rolled_back'].includes(item.state)), progress = document.querySelector('#cloudflare-migration-progress');
      if (progress && activeMigration) { progress.hidden = false; progress.dataset.migrationId = activeMigration.id; progress.querySelector('[data-field="id"]').textContent = activeMigration.id; progress.querySelector('[data-field="state"]').textContent = `${activeMigration.hostname} · ${activeMigration.state}${activeMigration.error_message ? ` · ${activeMigration.error_message}` : ''}`; }
      else if (progress) { progress.hidden = true; delete progress.dataset.migrationId; }
    } catch (error) { summary.innerHTML = `<p class="hint">读取失败：${esc(error.message)}</p>`; toast(error.message); }
  }
  async function handleCloudflareAction(event) {
    const centralButton = event.target.closest('[data-cf-central]'), accountButton = event.target.closest('[data-cf-account]'), workerButton = event.target.closest('[data-cf-worker]'), migrationButton = event.target.closest('[data-cf-migration]');
    const button = centralButton || accountButton || workerButton || migrationButton; if (!button) return;
    const original = button.textContent;
    try {
      button.disabled = true; button.textContent = '处理中…';
      if (centralButton) {
        const action = centralButton.dataset.cfCentral;
        if ((action === 'api' || action === 'admin') && !confirm(`确定重新部署${action === 'api' ? ' API' : '后台'} Worker 吗？`)) return;
        const path = action === 'verify' ? '/api/admin/cloudflare/central/verify' : action === 'sync' ? '/api/admin/cloudflare/central/sync-origins' : `/api/admin/cloudflare/central/redeploy/${action}`;
        await api(path, { method: 'POST', body: '{}' });
      } else if (accountButton) {
        const action = accountButton.dataset.cfAccount, id = encodeURIComponent(accountButton.dataset.id);
        if (action === 'edit') {
          const data = await api('/api/admin/cloudflare/overview'), item = (data.accounts || []).find(account => account.id === accountButton.dataset.id), form = document.querySelector('#public-frontend-profile-form');
          if (!item || !form) throw Error('账号配置不存在');
          form.elements.reuseCentralCredential.checked = false; form.elements.id.value = item.id; form.elements.label.value = item.label; form.elements.accountId.value = item.accountId; form.elements.workerPrefix.value = item.workerPrefix; form.elements.apiToken.value = ''; syncCentralCredentialChoice();
          form.elements.apiToken.focus(); form.scrollIntoView({ behavior: 'smooth', block: 'center' }); toast('请填写新 Token 后保存；Account ID 已锁定'); return;
        } else if (action === 'toggle') await api(`/api/admin/cloudflare/accounts/${id}/allocation`, { method: 'PATCH', body: JSON.stringify({ enabled: accountButton.dataset.enabled === '1' }) });
        else await api(`/api/admin/cloudflare/accounts/${id}/${action}`, { method: 'POST', body: '{}' });
      } else if (workerButton) {
        const action = workerButton.dataset.cfWorker, id = Number(workerButton.dataset.id);
        if (action === 'delete') { const dialog = document.querySelector('#cloudflare-delete-dialog'), form = dialog.querySelector('form'); form.reset(); form.elements.workerId.value = id; form.elements.confirmHostname.placeholder = workerButton.dataset.hostname; dialog.showModal(); form.elements.confirmHostname.focus(); return; }
        if (action === 'redeploy' && !confirm('确定重新部署这个前台 Worker 吗？')) return;
        await api(`/api/admin/cloudflare/frontends/${id}/${action}`, { method: 'POST', body: '{}' });
      } else {
        const progress = document.querySelector('#cloudflare-migration-progress'), id = Number(progress?.dataset.migrationId), action = migrationButton.dataset.cfMigration;
        if (!id) throw Error('请先准备迁移任务');
        if (action === 'cutover' && !confirm('确认已完成 Nameserver 切换，且目标账号 Zone 已变为 Active 吗？')) return;
        const result = await api(`/api/admin/cloudflare/migrations/${id}/${action}`, { method: 'POST', body: '{}' });
        progress.querySelector('[data-field="state"]').textContent = result.state;
      }
      toast('Cloudflare 操作已完成'); await Promise.all([loadCloudflareOverview(), loadPublicFrontendProfiles(), loadFrontendOrigins()]);
    } catch (error) { toast(error.message || 'Cloudflare 操作失败'); }
    finally { button.disabled = false; button.textContent = original; }
  }
  async function prepareCloudflareMigration(event) {
    event.preventDefault(); const form = event.currentTarget, button = form.querySelector('button[type="submit"]'), hostname = form.elements.hostname.value, targetAccountProfileId = form.elements.targetAccountProfileId.value;
    if (!confirm(`确定为 ${hostname} 在目标账号准备新的 Worker 吗？此步骤不会切换域名，也不会删除旧资源。`)) return;
    try {
      button.disabled = true; button.textContent = '准备 Worker 中…';
      const result = await api('/api/admin/cloudflare/migrations/prepare', { method: 'POST', body: JSON.stringify({ hostname, targetAccountProfileId }) });
      const progress = document.querySelector('#cloudflare-migration-progress'); progress.hidden = false; progress.dataset.migrationId = result.migrationId;
      progress.querySelector('[data-field="id"]').textContent = result.migrationId; progress.querySelector('[data-field="state"]').textContent = '目标 Worker 已准备，等待 Nameserver 切换';
      toast('迁移 Worker 已准备，旧站保持不变'); await loadCloudflareOverview();
    } catch (error) { toast(error.message || '准备迁移失败'); }
    finally { button.disabled = false; button.textContent = '准备迁移 Worker'; }
  }
  async function deleteCloudflareRemote(event) {
    event.preventDefault(); const form = event.currentTarget, button = form.querySelector('button[type="submit"]'), id = Number(form.elements.workerId.value);
    try {
      button.disabled = true; button.textContent = '正在删除…';
      await api(`/api/admin/cloudflare/frontends/${id}/remote`, { method: 'DELETE', body: JSON.stringify({ confirmHostname: form.elements.confirmHostname.value, password: form.elements.password.value }) });
      form.closest('dialog').close(); form.reset(); toast('远端 Worker 已删除，本地审计记录已保留'); await loadCloudflareOverview();
    } catch (error) { toast(error.message || '删除远端 Worker 失败'); }
    finally { button.disabled = false; button.textContent = '确认删除远端资源'; }
  }
  async function loadCloudflareSettings() { return Promise.all([loadFrontendOrigins(), loadCloudflareCentralAccess(), loadPublicFrontendProfiles(), loadCloudflareOverview()]); }
  async function loadAllSettings() { return Promise.all([loadSettings(), loadPublishLinks(), loadAnalyticsConfig(), window.loadMatrixSettings?.()]); }
  async function saveAnalyticsConfig(event) { event.preventDefault(); const form = event.currentTarget, button = form.querySelector('#save-analytics-settings'); try { const payload = Object.fromEntries(new FormData(form)); ['umami_enabled', 'cf_analytics_enabled', 'generic_analytics_enabled'].forEach(key => { payload[key] = form.elements[key].checked ? '1' : '0'; }); if (payload.umami_enabled === '1' && !String(payload.umami_website_id || '').trim()) throw Error('启用 Umami 前请填写 Website ID'); if (payload.cf_analytics_enabled === '1' && !String(payload.cf_beacon_token || '').trim()) throw Error('启用 Cloudflare Web Analytics 前请填写 Beacon Token'); if (payload.generic_analytics_enabled === '1' && !String(payload.generic_analytics_code || '').trim()) throw Error('启用自定义统计代码前请粘贴完整的 <script> 代码'); if (button) { button.disabled = true; button.textContent = '保存中…'; } const data = await api('/api/admin/analytics/config', { method: 'POST', body: JSON.stringify(payload) }); Object.entries(data || {}).forEach(([key, value]) => { if (!form.elements[key]) return; if (form.elements[key].type === 'checkbox') form.elements[key].checked = String(value) === '1'; else form.elements[key].value = value; }); toast('第三方统计设置已保存，公开页面将在下次加载时生效'); } catch (error) { toast(error.message || '保存第三方统计设置失败'); } finally { if (button) { button.disabled = false; button.textContent = '保存第三方统计设置'; } } }
  function healthLabel(status) { return ({ healthy: '🟢 正常', degraded: '🟡 不稳定', offline: '🔴 故障', auth_error: '🔴 鉴权异常', unconfigured: '⚪ 未配置', untested: '⚪ 尚未投递' })[status] || '⚪ 未知'; }
  async function loadWebhookDeliveries() { const area = document.querySelector('#webhook-delivery-list'); if (!area) return; area.hidden = false; area.textContent = '正在读取最近投递记录…'; try { const data = await api('/api/admin/webhook/deliveries?limit=30'); const rows = data.deliveries || []; area.innerHTML = `<div class="webhook-delivery-table"><table><thead><tr><th>北京时间</th><th>事件</th><th>通道</th><th>结果</th><th>次数</th><th>耗时</th><th>原因</th></tr></thead><tbody>${rows.map(item => `<tr><td>${esc(time(item.created_at))}</td><td>${esc(item.event_type)}</td><td>${esc(item.provider)}${Number(item.is_fallback) ? '（备用）' : ''}</td><td>${Number(item.success) ? '🟢 成功' : '🔴 失败'}</td><td>${Number(item.attempt_count || 0)}</td><td>${item.duration_ms == null ? '—' : `${Number(item.duration_ms)}ms`}</td><td>${esc(item.error_message || (item.status_code ? `HTTP ${item.status_code}` : '—'))}</td></tr>`).join('') || '<tr><td colspan="7">暂无投递记录</td></tr>'}</tbody></table></div>`; } catch (error) { area.textContent = `读取失败：${error.message}`; } }
  async function loadWebhookHealth() { const card = document.querySelector('#webhook-health-card'); if (!card) return; try { const data = await api('/api/admin/webhook/health'); const primary = data.primary || {}, backup = data.backup || {}; card.innerHTML = `<div class="webhook-health-head"><strong>告警投递健康</strong><span><button id="refresh-webhook-health" type="button" class="button ghost">↻ 刷新状态</button><button id="show-webhook-deliveries" type="button" class="button ghost">查看最近投递</button></span></div><div class="webhook-health-grid"><p>主通道：${esc(primary.provider || 'none')} <b>${healthLabel(primary.status)}</b></p><p>备用通道：Bark <b>${healthLabel(backup.status)}</b></p><p>主通道连续失败：<b>${Number(primary.consecutiveFailures || 0)} 次</b></p><p>主通道近24h：成功 ${Number(primary.success24h || 0)} / 失败 ${Number(primary.failed24h || 0)} / ${Number(primary.successRate24h || 0).toFixed(1)}%</p><p>最近主通道成功：${esc(time(primary.lastSuccessAt))}</p><p>最近失败原因：${esc(primary.lastFailureReason || '—')}</p><p>最近 Bark 成功：${esc(time(backup.lastSuccessAt))}</p><p>最近故障转移：${esc(time(data.lastFallbackAt))}</p></div><div id="webhook-delivery-list" hidden></div>`; card.querySelector('#refresh-webhook-health')?.addEventListener('click', loadWebhookHealth); card.querySelector('#show-webhook-deliveries')?.addEventListener('click', loadWebhookDeliveries); } catch (error) { card.innerHTML = `<p class="webhook-health-empty">状态读取失败：${esc(error.message)}</p>`; } }
  async function testWebhook() { const button = document.querySelector('#test-webhook'); try { button.disabled = true; button.textContent = '发送中…'; const data = await api('/api/admin/settings/test-webhook', { method: 'POST' }); await loadWebhookHealth(); toast(data.result?.provider ? `主通道测试消息已通过 ${data.result.provider} 发送` : '主通道测试消息已发送'); } catch (error) { await loadWebhookHealth(); toast(error.message); } finally { button.disabled = false; button.textContent = '🔔 测试主通道'; } }
  async function testBark() { const button = document.querySelector('#test-bark'); try { button.disabled = true; button.textContent = '发送中…'; await api('/api/admin/settings/test-bark', { method: 'POST' }); await loadWebhookHealth(); toast('Bark 测试消息已发送'); } catch (error) { await loadWebhookHealth(); toast(error.message); } finally { button.disabled = false; button.textContent = '📱 测试 Bark'; } }
  const style = document.createElement('link'); style.rel = 'stylesheet'; style.href = '/admin/review.css?v=20260923-publish-pages-sync'; document.head.append(style); const logoStyle = document.createElement('link'); logoStyle.rel = 'stylesheet'; logoStyle.href = '/admin/logo-settings.css?v=20260908-1'; document.head.append(logoStyle); install(); window.fetchPendingCount = loadReview; window.refreshReviewCount = refreshReviewCount; window.loadCloudflareSettings = loadCloudflareSettings; window.loadAdminSettings = loadAllSettings;
})();
