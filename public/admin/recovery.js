/** 独立老用户恢复系统后台。与首页防失联弹窗、镜像节点完全隔离。 */
(() => {
  const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
  const formatTime = value => window.formatAdminTime?.(value) || value || '—';
  const notify = message => typeof window.toast === 'function' ? window.toast(message) : (() => {
    const el = document.querySelector('#toast'); if (!el) return; el.textContent = message; el.classList.add('show'); setTimeout(() => el.classList.remove('show'), 3000);
  })();
  let state = null;
  let currentProfileId = 1;
  let currentRoutePlan = null;

  async function request(url, options = {}) {
    if (url.startsWith('/api/admin/recovery') && !url.startsWith('/api/admin/recovery/profiles')) {
      const separator = url.includes('?') ? '&' : '?';
      url = `${url}${separator}profileId=${encodeURIComponent(currentProfileId)}`;
    }
    const response = await fetch(url, {
      ...options,
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', ...(options.headers || {}) }
    });
    const payload = await response.json().catch(() => null);
    if (!response.ok || payload?.code !== 200) throw new Error(payload?.msg || `请求失败（HTTP ${response.status}）`);
    return payload.data;
  }

  function installPanel() {
    if (document.querySelector('#recovery')) return;
    const tab = document.createElement('button');
    tab.id = 'recovery-tab'; tab.type = 'button'; tab.dataset.tab = 'recovery'; tab.textContent = '恢复系统';
    document.querySelector('.tabs')?.append(tab);

    const panel = document.createElement('section');
    panel.id = 'recovery'; panel.className = 'panel'; panel.innerHTML = `
      <div class="box">
        <div class="box-head"><div><h2>老用户恢复系统</h2><p class="hint">可维护多套彼此隔离的恢复方案；独立前台发布时必须选择其中一套。不会读取首页弹窗、节点管理或现有防失联设置。</p></div><button class="button ghost" type="button" data-recovery-action="reload">刷新状态</button></div>
        <div class="recovery-profile-bar"><label>当前恢复方案<select id="recovery-profile-select" aria-label="当前恢复方案"></select></label><button class="button ghost" type="button" data-recovery-action="create-profile">新增恢复方案</button><span class="hint">切换方案后，下方域名、TXT、密钥与版本都会独立切换。</span></div>
        <div id="recovery-status-grid" class="recovery-status-grid" aria-live="polite"><div class="recovery-empty">正在读取恢复系统状态…</div></div>
        <div class="recovery-actions">
          <button class="button ghost" type="button" data-recovery-action="probe-all">检测全部线路</button>
          <button class="button ghost" type="button" data-recovery-action="create-draft">生成新版本草稿</button>
          <button class="button" type="button" data-recovery-action="publish-latest">发布最新草稿</button>
          <a id="recovery-preview-link" class="button ghost" href="#" target="_blank" rel="noopener" aria-disabled="true">预览恢复页面</a>
        </div>
      </div>
      <div class="recovery-grid">
        <div class="recovery-stack">
          <div class="box"><div class="box-head"><div><h2>恢复专用配置</h2><p class="hint">这些字段只进入恢复清单，不与现有站点配置联动。</p></div></div>
            <form id="recovery-settings-form" class="recovery-form">
              <label class="recovery-switch"><input name="enabled" type="checkbox" value="1"><span><strong>启用恢复系统</strong><small class="hint">仅存在已发布签名版本时，公开端才会保存恢复清单。</small></span></label>
              <label>恢复专用邮箱<input name="recovery_email" type="email" autocomplete="off"></label>
              <label>恢复专用独立发布页<input name="recovery_publish_url" type="url" placeholder="https://recovery.example"></label>
              <label class="full">恢复专用联系方式<input name="recovery_contact" maxlength="300"></label>
              <label class="full">全部失败时说明<textarea name="recovery_message" maxlength="1000"></textarea></label>
              <label class="full">发现最新地址后的说明<textarea name="found_message" maxlength="500"></textarea></label>
              <label>清单有效天数<input name="manifest_valid_days" type="number" min="7" max="365" required></label>
              <label>直接恢复线路上限<input name="max_domains" type="number" min="1" max="10" required></label>
              <label>单次测活超时（毫秒）<input name="probe_timeout_ms" type="number" min="1000" max="10000" step="100" required></label>
              <label>测活并发数<input name="probe_concurrency" type="number" min="1" max="3" required></label>
              <div class="recovery-form-actions"><button class="button" type="submit">保存恢复设置</button></div>
            </form>
          </div>
          <div class="box"><div class="box-head"><div><h2>直接恢复线路（浏览器本地保存）</h2><p class="hint">随主签名清单下发并保存在访客浏览器中；不写入 DNS TXT，也不与 DNS 发布组合自动同步。仅接受 HTTPS Origin，测活固定使用 /.well-known/route-health.gif。</p></div><button class="button" type="button" data-recovery-action="open-domain">新增直接线路</button></div>
            <div class="table-wrap"><table class="recovery-table"><thead><tr><th>名称</th><th>直接恢复地址</th><th>优先级</th><th>状态</th><th>动态图片检测</th><th>最近检测</th><th>操作</th></tr></thead><tbody id="recovery-domain-body"></tbody></table></div>
          </div>
          <div class="box"><div class="box-head"><div><h2>DNS 发布组合</h2><p class="hint">每个组合维护自己的 TXT 候选域名；这些域名只通过 DoH 查询获得，不读取上方直接恢复线路。A、B、R1 可分别发布到一个或多个自动或手动目标。</p></div><div class="recovery-actions"><button class="button ghost" type="button" data-recovery-action="open-bootstrap">高级单条配置</button><button class="button" type="button" data-recovery-action="open-bootstrap-group">新建发布组合</button></div></div>
            <div id="recovery-bootstrap-groups" class="recovery-publish-groups"></div>
            <details class="recovery-legacy-records"><summary>历史独立配置</summary><div class="table-wrap"><table class="recovery-table"><thead><tr><th>名称</th><th>权威 DNS</th><th>TXT 记录</th><th>分片</th><th>单条限制</th><th>发布状态</th><th>当前代</th><th>操作</th></tr></thead><tbody id="recovery-bootstrap-body"></tbody></table></div></details>
            <div id="recovery-doh-results" class="recovery-result-list" aria-live="polite"></div>
          </div>
          <div class="box"><div class="box-head"><div><h2>DNS / Bootstrap 查询线路</h2><p class="hint">每一行精确指定“哪个 DNS 服务商查询哪一条 TXT”。同一方案可让不同 DNS 查询不同的 Bootstrap TXT；按 P1 → P4 分组容灾，同组并发。</p></div></div>
            <form id="recovery-route-form" class="recovery-route-form"><label>DNS 服务商<select name="resolverId" required></select></label><label>Bootstrap TXT<select name="bootstrapId" required></select></label><label>优先组<select name="priorityGroup"><option value="1">P1 · 首选</option><option value="2">P2 · 主力备用</option><option value="3">P3 · 扩展容灾</option><option value="4">P4 · 最终备用</option></select></label><label>超时（毫秒）<input name="timeoutMs" type="number" min="800" max="10000" value="2500" required></label><button class="button" type="submit">添加查询线路</button></form>
            <div class="table-wrap"><table class="recovery-table"><thead><tr><th>优先组</th><th>DNS 服务商</th><th>查询 TXT</th><th>超时</th><th>操作</th></tr></thead><tbody id="recovery-route-body"></tbody></table></div>
          </div>
          <div class="box"><div class="box-head"><div><h2>版本发布</h2><p class="hint">回滚会把历史内容重新签为更高 generation，绝不降低客户端防回滚版本。</p></div></div>
            <div class="table-wrap"><table class="recovery-table"><thead><tr><th>版本</th><th>状态</th><th>Key ID</th><th>签发时间</th><th>过期时间</th><th>哈希</th><th>操作</th></tr></thead><tbody id="recovery-release-body"></tbody></table></div>
          </div>
        </div>
        <div class="recovery-stack">
          <div class="box"><div class="box-head"><div><h2>签名密钥</h2><p class="hint">私钥只保存在服务器权限 600 的凭据文件，永不写入 SQLite 或回显。</p></div></div>
            <div id="recovery-key-state" class="recovery-key-state"></div>
            <div class="recovery-actions recovery-key-actions"><button class="button ghost" type="button" data-recovery-action="ensure-key">确保当前密钥</button><button class="button ghost" type="button" data-recovery-action="next-key">生成下一代密钥</button><button class="button danger" type="button" data-recovery-action="promote-key">提升下一代密钥</button></div>
          </div>
          <div class="box"><div class="box-head"><div><h2>DNS API 通道</h2><p class="hint">同一服务商可保存多个独立账号；密钥只留在服务器，浏览器不会回显。</p></div><button class="button" type="button" data-recovery-action="open-channel">新增通道</button></div>
            <div class="table-wrap"><table class="recovery-table"><thead><tr><th>通道</th><th>服务商</th><th>账号</th><th>配置</th><th>最近验证</th><th>操作</th></tr></thead><tbody id="recovery-channel-body"></tbody></table></div>
          </div>
          <div class="box"><div class="box-head"><div><h2>安全边界</h2></div></div><div class="recovery-note">主域名正常时不测活、不查询备用线路、不访问 DoH。只有真实导航或核心接口失败后，才检查主域动态图片并进入恢复流程；找到地址后也只展示“立即前往”，不会自动跳转。</div></div>
          <div class="box"><div class="box-head"><div><h2>操作审计</h2><p class="hint">保留最近 100 条配置、检测、密钥和发布记录。</p></div></div><div id="recovery-audit" class="recovery-audit"></div></div>
        </div>
      </div>
      <div id="recovery-domain-modal" class="modal recovery-modal" role="dialog" aria-modal="true" aria-labelledby="recovery-domain-title"><form id="recovery-domain-form" class="dialog"><h3 id="recovery-domain-title">新增直接恢复线路</h3><input name="id" type="hidden"><div class="form-grid"><label>线路名称<input name="title" maxlength="80" placeholder="例如：本地备用前台 1" required></label><label>优先级<input name="priority" type="number" value="0" required><small class="hint">数值越大越优先。</small></label><label class="full">完整 HTTPS Origin<input name="url" type="url" placeholder="https://recovery.example.com" required><small class="hint">不能包含路径、参数、认证信息或非标准端口。</small></label><label class="full exemption-option"><input name="status" type="checkbox" value="1" checked><span>启用并写入下一份直接恢复清单</span></label></div><div class="dialog-foot"><button class="button ghost" type="button" data-close-recovery-modal>取消</button><button class="button" type="submit">保存直接线路</button></div></form></div>
      <div id="recovery-bootstrap-group-modal" class="modal recovery-modal" role="dialog" aria-modal="true" aria-labelledby="recovery-bootstrap-group-title"><form id="recovery-bootstrap-group-form" class="dialog recovery-group-dialog"><h3 id="recovery-bootstrap-group-title">新建 DNS 发布组合</h3><div id="recovery-group-error" class="recovery-inline-error" role="alert" hidden></div><div class="form-grid"><label>组合名称<input name="label" maxlength="80" value="主恢复发布组合" required></label><label>兼容方案<select name="compatibilityMode" required><option value="AB_R1">A + B + R1（推荐）</option><option value="AB">仅 A + B</option><option value="R1">仅 R1 旧版</option><option value="CUSTOM">自定义</option></select></label></div><section class="recovery-group-summary"><div class="recovery-group-summary-head"><div><strong>DNS TXT 候选域名</strong><p class="hint">只写入当前组合的 DNS 签名清单，不会进入浏览器直接恢复列表。最多 10 条，至少启用 1 条。</p></div><button class="button ghost" type="button" data-recovery-action="add-group-domain">添加 TXT 候选域名</button></div><div id="recovery-group-domain-list" class="recovery-group-domain-list"></div></section><p id="recovery-group-byte-policy" class="recovery-byte-policy"></p><div id="recovery-group-roles" class="recovery-role-stack"></div><div class="dialog-foot"><button class="button ghost" type="button" data-close-recovery-modal>取消</button><button class="button" type="submit">创建发布组合</button></div></form></div>
      <div id="recovery-route-plan-modal" class="modal recovery-modal" role="dialog" aria-modal="true" aria-labelledby="recovery-route-plan-title"><form id="recovery-route-plan-form" class="dialog recovery-route-plan-dialog"><h3 id="recovery-route-plan-title">自动配置三层查询线路</h3><input name="groupId" type="hidden"><div class="recovery-route-architecture" aria-label="固定三层查询架构"><div><strong>P1 · 中国大陆主力</strong><span>AliDNS、DNSPod · 2500 ms</span></div><div><strong>P2 · 全球主力</strong><span>Cloudflare、Google、Quad9 · 3000 ms</span></div><div><strong>P3 · 扩展容灾</strong><span>AdGuard、Control D、Mullvad · 4000 ms</span></div></div><fieldset class="recovery-apply-mode"><legend>现有线路处理</legend><label><input type="radio" name="applyMode" value="fill_missing" checked><span><strong>仅补充缺失线路（推荐）</strong><small>保留手动线路；若同一 DNS/TXT 的优先级或超时冲突，会要求先确认同步。</small></span></label><label><input type="radio" name="applyMode" value="sync_template"><span><strong>同步为三层标准</strong><small>把当前组合的冲突线路修正为标准优先级与超时，并移除不属于标准架构的组合线路。</small></span></label></fieldset><div id="recovery-route-plan-error" class="recovery-inline-error" role="alert" tabindex="-1" hidden></div><div id="recovery-route-plan-preview" class="recovery-route-plan-preview" aria-live="polite"><div class="recovery-empty">请选择处理方式并生成预览。</div></div><div class="dialog-foot"><button class="button ghost" type="button" data-close-recovery-modal>取消</button><button class="button ghost" type="button" data-recovery-action="preview-route-plan">重新预览</button><button class="button" type="submit" disabled>确认应用</button></div></form></div>
      <div id="recovery-bootstrap-modal" class="modal recovery-modal" role="dialog" aria-modal="true" aria-labelledby="recovery-bootstrap-title"><form id="recovery-bootstrap-form" class="dialog"><h3 id="recovery-bootstrap-title">高级单条 DNS 配置</h3><input name="id" type="hidden"><input name="isPrimary" type="hidden" value="0"><input name="providerZoneId" type="hidden"><div class="form-grid"><label>显示名称<input name="label" maxlength="80" required></label><label>排序<input name="sortOrder" type="number" value="0" required></label><label>权威 DNS 托管商<select name="providerId" required></select></label><label>分片角色<select name="shareRole" required><option value="A">A 分片</option><option value="B">B 分片</option><option value="LEGACY">旧版 r1 兼容</option></select></label><label>发布方式<select name="publishMode" required><option value="automatic">API 自动发布</option><option value="manual">手动发布并 DoH 验证</option></select></label><label id="recovery-bootstrap-channel-field">API 通道<select name="dnsChannelId"></select></label><p id="recovery-bootstrap-publish-hint" class="hint full"></p><label class="full">TXT 记录名<input name="recordName" placeholder="_recovery-a.bootstrap.example" required></label><label class="full">权威 DNS Zone<span class="recovery-zone-picker"><input name="zoneName" list="recovery-zone-options" placeholder="bootstrap.example" required><button class="button ghost" type="button" data-recovery-action="load-channel-zones">读取账号 Zone</button></span><datalist id="recovery-zone-options"></datalist></label><p class="hint full">每条 TXT 使用系统与托管商两者中更小的字节上限；自动发布只清理本系统旧代分片，不会删除同名的其他 TXT。</p><label class="exemption-option full"><input name="status" type="checkbox" value="1" checked><span>启用</span></label></div><div class="dialog-foot"><button class="button ghost" type="button" data-close-recovery-modal>取消</button><button class="button" type="submit">保存 DNS</button></div></form></div>
      <div id="recovery-channel-modal" class="modal recovery-modal" role="dialog" aria-modal="true" aria-labelledby="recovery-channel-title"><form id="recovery-channel-form" class="dialog"><h3 id="recovery-channel-title">DNS API 通道</h3><input name="id" type="hidden"><div class="form-grid"><label>通道名称<input name="label" maxlength="80" placeholder="例如：Cloudflare 主账号" required></label><label>DNS 服务商<select name="providerId" required></select></label><div id="recovery-channel-credentials" class="recovery-credential-fields full"></div><p class="hint full">敏感字段留空表示保持原值。保存后只显示脱敏账号标识，不回显密钥。</p><label class="exemption-option full"><input name="status" type="checkbox" value="1" checked><span>启用该 API 通道</span></label></div><div class="dialog-foot"><button class="button ghost" type="button" data-close-recovery-modal>取消</button><button class="button" type="submit">保存通道</button></div></form></div>
    `;
    document.querySelector('.shell')?.append(panel);
    bindPanel(panel);
  }

  function statusTag(value, labels = {}) {
    const map = { published: ['已发布', ''], pending: ['等待 DNS 传播', 'warn'], draft: ['草稿', 'warn'], failed: ['失败', 'off'], superseded: ['已替代', 'neutral'], verified: ['已验证', ''], pending_verification: ['等待传播', 'warn'], manual_required: ['待手动写入', 'warn'], unpublished: ['未发布', 'neutral'], healthy: ['正常', ''], untested: ['未检测', 'neutral'] };
    const [text, tone] = map[value] || [labels[value] || value || '未知', 'off'];
    return `<span class="tag ${tone}">${escapeHtml(text)}</span>`;
  }

  function routeHealthLabel(value) {
    if (value === 'complete') return ['三层完整', ''];
    if (value === 'degraded') return ['容灾不足', 'warn'];
    return ['配置不完整', 'off'];
  }

  function renderRoutePlan(plan) {
    currentRoutePlan = plan;
    const form = document.querySelector('#recovery-route-plan-form');
    const errorBox = document.querySelector('#recovery-route-plan-error');
    const preview = document.querySelector('#recovery-route-plan-preview');
    const submit = form.querySelector('button[type="submit"]');
    const tierRows = plan.tiers.map(tier => `<div class="recovery-route-tier" data-complete="${tier.complete ? '1' : '0'}"><span><strong>P${tier.priorityGroup} · ${escapeHtml(tier.label)}</strong><small>${escapeHtml(tier.resolverIds.join('、'))} · ${Number(tier.timeoutMs)} ms</small></span><b>${tier.configured}/${tier.expected}</b><em>${tier.complete ? '完整' : '待补充'}</em></div>`).join('');
    preview.innerHTML = `<div class="recovery-route-plan-summary"><div><span>计划总线路</span><strong>${Number(plan.summary.total)}</strong></div><div><span>新增</span><strong>${Number(plan.summary.create)}</strong></div><div><span>修正</span><strong>${Number(plan.summary.update)}</strong></div><div><span>保留</span><strong>${Number(plan.summary.keep)}</strong></div><div><span>移除</span><strong>${Number(plan.summary.remove)}</strong></div></div><div class="recovery-route-tier-list">${tierRows}</div>`;
    if (plan.validation.valid) {
      errorBox.hidden = true;
      errorBox.textContent = '';
      submit.disabled = false;
    } else {
      errorBox.hidden = false;
      errorBox.innerHTML = `<strong>当前预览不能应用</strong><ul>${plan.validation.errors.map(item => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`;
      submit.disabled = true;
    }
  }

  async function previewRoutePlan(button) {
    const form = document.querySelector('#recovery-route-plan-form');
    const groupId = Number(form.elements.groupId.value || 0);
    const applyMode = form.elements.applyMode.value;
    if (!groupId) throw new Error('发布组合不存在');
    document.querySelector('#recovery-route-plan-preview').innerHTML = '<div class="recovery-empty">正在计算三层查询线路…</div>';
    const plan = await busy(button, '预览中…', () => request(`/api/admin/recovery/bootstrap-groups/${groupId}/lookup-routes/preview`, { method: 'POST', body: JSON.stringify({ architecture: 'three_tier_full', applyMode }) }));
    renderRoutePlan(plan);
    return plan;
  }

  function renderOverview() {
    if (!state) return;
    const { settings, domains, bootstrapGroups = [], bootstrapGroupDomains = [], bootstraps, releases, keys, audit, profiles = [], resolvers = [], dnsProviders = [], dnsChannels = [], lookupRoutes = [], lookupRouteHealth = {} } = state;
    currentProfileId = Number(state.selectedProfileId || settings.id || currentProfileId);
    const profileSelect = document.querySelector('#recovery-profile-select');
    profileSelect.innerHTML = profiles.map(item => `<option value="${Number(item.id)}">${escapeHtml(item.name)} · ${escapeHtml(item.code)}${item.ready ? ' · 可发布' : ''}</option>`).join('');
    profileSelect.value = String(currentProfileId);
    const previewLink = document.querySelector('#recovery-preview-link');
    if (state.publicPreviewOrigin) {
      previewLink.href = `${state.publicPreviewOrigin}/recovery.html?preview=1`;
      previewLink.removeAttribute('aria-disabled');
    } else {
      previewLink.href = '#'; previewLink.setAttribute('aria-disabled', 'true');
    }
    const current = releases.find(item => item.status === 'published');
    const healthy = domains.filter(item => item.last_probe_status === 'healthy').length;
    const failed = domains.filter(item => item.last_probe_status === 'failed').length;
    document.querySelector('#recovery-status-grid').innerHTML = `
      <div class="recovery-status-card" data-tone="${Number(settings.enabled) === 1 ? 'ok' : 'off'}"><span>恢复系统</span><strong>${Number(settings.enabled) === 1 ? '已启用' : '已停用'}</strong></div>
      <div class="recovery-status-card" data-tone="${current ? 'ok' : 'warn'}"><span>当前正式版本</span><strong>${current ? `generation ${current.generation}` : '尚未发布'}</strong></div>
      <div class="recovery-status-card" data-tone="${failed ? 'warn' : healthy ? 'ok' : ''}"><span>恢复线路</span><strong>${healthy} 正常 · ${failed} 异常 · ${domains.length} 总数</strong></div>
      <div class="recovery-status-card" data-tone="${bootstraps.length >= 2 ? 'ok' : 'warn'}"><span>Bootstrap DNS</span><strong>${bootstraps.filter(item => Number(item.status) === 1).length} 个启用</strong></div>
      <div class="recovery-status-card" data-tone="${keys.currentPrivateKeyConfigured ? 'ok' : 'off'}"><span>签名密钥</span><strong>${escapeHtml(keys.currentKeyId || '尚未生成')}</strong></div>`;

    const settingsForm = document.querySelector('#recovery-settings-form');
    Object.entries(settings).forEach(([key, value]) => { const field = settingsForm.elements[key]; if (!field) return; if (field.type === 'checkbox') field.checked = Number(value) === 1; else field.value = value ?? ''; });
    document.querySelector('#recovery-domain-body').innerHTML = domains.map(item => `<tr><td><strong>${escapeHtml(item.title)}</strong></td><td class="recovery-url">${escapeHtml(item.url)}</td><td>${Number(item.priority)}</td><td>${Number(item.status) === 1 ? '<span class="tag">启用</span>' : '<span class="tag neutral">停用</span>'}</td><td>${statusTag(item.last_probe_status)}${item.last_probe_ms ? ` <span class="hint">${item.last_probe_ms}ms</span>` : ''}${item.last_probe_error ? `<span class="domain">${escapeHtml(item.last_probe_error)}</span>` : ''}</td><td>${formatTime(item.last_probe_at)}</td><td><div class="actions"><button class="action" data-recovery-action="probe-domain" data-id="${item.id}">检测</button><button class="action" data-recovery-action="edit-domain" data-id="${item.id}">编辑</button><button class="action danger" data-recovery-action="delete-domain" data-id="${item.id}">删除</button></div></td></tr>`).join('') || '<tr><td colspan="7" class="recovery-empty">尚未添加恢复专用线路</td></tr>';
    document.querySelector('#recovery-channel-body').innerHTML = dnsChannels.map(item => `<tr><td><strong>${escapeHtml(item.label)}</strong>${item.legacy ? '<span class="domain">兼容现有配置</span>' : ''}</td><td>${escapeHtml(item.provider_label || item.provider_id)}</td><td>${escapeHtml(item.account_hint || '—')}</td><td>${item.configured ? '<span class="tag">凭据已配置</span>' : '<span class="tag off">凭据不完整</span>'}${Number(item.status) === 1 ? '' : '<span class="domain">通道已停用</span>'}</td><td>${statusTag(item.last_test_status)}${item.last_test_error ? `<span class="domain">${escapeHtml(item.last_test_error)}</span>` : ''}${item.last_test_at ? `<span class="domain">${formatTime(item.last_test_at)}</span>` : ''}</td><td><div class="actions"><button class="action" data-recovery-action="test-channel" data-id="${item.id}">验证</button><button class="action" data-recovery-action="edit-channel" data-id="${item.id}">编辑</button><button class="action danger" data-recovery-action="delete-channel" data-id="${item.id}">删除</button></div></td></tr>`).join('') || '<tr><td colspan="6" class="recovery-empty">尚未配置 DNS API 通道；新增通道后即可自动发布 TXT。</td></tr>';
    document.querySelector('#recovery-bootstrap-groups').innerHTML = (bootstrapGroups || []).map(group => {
      const targets = bootstraps.filter(item => Number(item.group_id) === Number(group.id));
      const routeHealth = lookupRouteHealth[group.id] || { routeCount: 0, structuralStatus: 'incomplete', tiers: [] };
      const [healthText, healthTone] = routeHealthLabel(routeHealth.structuralStatus);
      const txtDomains = bootstrapGroupDomains.filter(item => Number(item.group_id) === Number(group.id));
      const enabledTxtDomains = txtDomains.filter(item => Number(item.status) === 1);
      const roleSummary = ['A', 'B', 'LEGACY'].map(role => {
        const roleTargets = targets.filter(item => item.share_role === role);
        const verified = roleTargets.filter(item => item.last_publish_status === 'verified').length;
        return `<span class="tag ${role === 'LEGACY' ? 'neutral' : ''}">${role === 'LEGACY' ? 'R1' : role} ${verified}/${roleTargets.length}</span>`;
      }).join('');
      const targetRows = targets.map(item => `<tr><td><span class="tag ${item.share_role === 'LEGACY' ? 'neutral' : ''}">${item.share_role === 'LEGACY' ? 'R1' : escapeHtml(item.share_role)}</span>${Number(item.required_target) === 1 ? '<span class="domain">必需</span>' : '<span class="domain">可选副本</span>'}</td><td><strong>${escapeHtml(item.provider_label || item.provider_id)}</strong><span class="domain">${item.publish_mode === 'automatic' ? `API · ${escapeHtml(item.channel_label || '未绑定')}` : '手动发布'}</span></td><td class="recovery-code">${escapeHtml(item.record_name)}<span class="domain">Zone：${escapeHtml(item.zone_name)}</span></td><td>${Math.min(Number(item.portable_record_bytes || 240), Number(state?.txtPolicy?.portableBytes || 240))} 字节</td><td>${statusTag(item.last_publish_status)}${item.last_publish_error ? `<span class="domain">${escapeHtml(item.last_publish_error)}</span>` : ''}</td><td><div class="actions"><button class="action" data-recovery-action="doh" data-id="${item.id}">DoH 回读</button><button class="action" data-recovery-action="edit-bootstrap" data-id="${item.id}">编辑</button></div></td></tr>`).join('');
      const domainRows = txtDomains.map(item => `<li><span><strong>${escapeHtml(item.title)}</strong><small>${escapeHtml(item.url)} · 优先级 ${Number(item.priority)}</small></span>${Number(item.status) === 1 ? '<span class="tag">启用</span>' : '<span class="tag neutral">停用</span>'}</li>`).join('') || '<li class="recovery-empty">该历史组合尚未配置独立的 TXT 候选域名，请删除并重新创建后再生成草稿。</li>';
      const tierSummary = (routeHealth.tiers || []).map(tier => `<span class="recovery-tier-pill" data-complete="${tier.complete ? '1' : '0'}">P${Number(tier.priorityGroup)} ${escapeHtml(tier.label)} ${Number(tier.configured)}/${Number(tier.expected)}</span>`).join('');
      return `<article class="recovery-publish-group"><div class="recovery-publish-group-head"><div><strong>${escapeHtml(group.label)}</strong><span>${escapeHtml(group.compatibility_mode)} · ${targets.length} 个发布目标 · TXT 候选域名 ${enabledTxtDomains.length} 启用 / ${txtDomains.length} 总数</span></div><div class="recovery-role-badges">${roleSummary}<span class="tag ${healthTone}">${healthText}</span></div></div><div class="recovery-route-health"><div><strong>三层查询线路</strong><span>${Number(routeHealth.routeCount)} 条已配置</span></div><div class="recovery-tier-pills">${tierSummary || '<span class="recovery-tier-pill" data-complete="0">尚未配置</span>'}</div></div><details><summary>查看 TXT 候选域名</summary><ul class="recovery-group-domain-summary">${domainRows}</ul></details><details><summary>查看发布目标</summary><div class="table-wrap"><table class="recovery-table recovery-target-table"><thead><tr><th>角色</th><th>发布通道</th><th>TXT记录</th><th>字节上限</th><th>状态</th><th>操作</th></tr></thead><tbody>${targetRows}</tbody></table></div></details><div class="recovery-group-actions"><button class="button ghost" data-recovery-action="configure-group-routes" data-id="${group.id}">自动配置全部线路</button><button class="button ghost" data-recovery-action="test-group-routes" data-id="${group.id}">检测全部线路</button><button class="action danger" data-recovery-action="delete-bootstrap-group" data-id="${group.id}">删除组合</button></div></article>`;
    }).join('') || '<div class="recovery-empty">尚未建立 DNS 发布组合。创建后可为 A、B、R1 分别配置一个或多个自动或手动目标。</div>';
    const legacyBootstraps = bootstraps.filter(item => !item.group_id);
    document.querySelector('#recovery-bootstrap-body').innerHTML = legacyBootstraps.map(item => `<tr><td><strong>${escapeHtml(item.label)}</strong></td><td><strong>${escapeHtml(item.provider_label || item.provider_id)}</strong><span class="domain">${item.publish_mode === 'automatic' ? `API 自动 · ${escapeHtml(item.channel_label || '未绑定通道')}` : '手动 + DoH 验证'}</span></td><td class="recovery-code">${escapeHtml(item.record_name)}<span class="domain">${escapeHtml(item.zone_name)}</span></td><td><span class="tag ${item.share_role === 'LEGACY' ? 'neutral' : ''}">${escapeHtml(item.share_role || 'LEGACY')}</span></td><td>${Math.min(Number(item.portable_record_bytes || 240), Number(state?.txtPolicy?.portableBytes || 240))} / ${Number(item.max_character_string_bytes || 255)} 字节</td><td>${statusTag(item.last_publish_status)}${item.last_publish_error ? `<span class="domain">${escapeHtml(item.last_publish_error)}</span>` : ''}</td><td>${Number(item.last_published_generation || 0) || '—'}</td><td><div class="actions"><button class="action" data-recovery-action="doh" data-id="${item.id}">DoH 回读</button><button class="action" data-recovery-action="edit-bootstrap" data-id="${item.id}">编辑</button><button class="action danger" data-recovery-action="delete-bootstrap" data-id="${item.id}">删除</button></div></td></tr>`).join('') || '<tr><td colspan="8" class="recovery-empty">没有历史独立配置</td></tr>';
    const bootstrapForm = document.querySelector('#recovery-bootstrap-form');
    bootstrapForm.elements.providerId.innerHTML = dnsProviders.map(item => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.label)} · ${Number(item.portable_record_bytes)} 字节安全上限</option>`).join('');
    const channelForm = document.querySelector('#recovery-channel-form');
    channelForm.elements.providerId.innerHTML = dnsProviders.filter(item => item.automatic_publish).map(item => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.label)}</option>`).join('');
    const routeForm = document.querySelector('#recovery-route-form');
    routeForm.elements.resolverId.innerHTML = `<option value="">请选择 DNS 服务商</option>${resolvers.map(item => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.label)} · ${escapeHtml(item.category)}</option>`).join('')}`;
    routeForm.elements.bootstrapId.innerHTML = `<option value="">请选择 Bootstrap TXT</option>${bootstraps.filter(item => Number(item.status) === 1).map(item => `<option value="${Number(item.id)}">${escapeHtml(item.label)} · ${escapeHtml(item.record_name)}</option>`).join('')}`;
    document.querySelector('#recovery-route-body').innerHTML = lookupRoutes.map(item => `<tr><td><span class="tag">P${Number(item.priority_group)}</span></td><td><strong>${escapeHtml(item.resolver_label)}</strong><span class="domain">${escapeHtml(item.endpoint)}</span></td><td>${escapeHtml(item.bootstrap_label)}<span class="domain">${escapeHtml(item.record_name)}</span></td><td>${Number(item.timeout_ms)} ms</td><td><button class="action danger" type="button" data-recovery-action="delete-route" data-id="${Number(item.id)}">删除</button></td></tr>`).join('') || '<tr><td colspan="5" class="recovery-empty">尚未编排查询线路。未配置时新版本不会主动查询 DoH。</td></tr>';
    document.querySelector('#recovery-release-body').innerHTML = releases.map(item => `<tr><td><strong>generation ${item.generation}</strong>${item.source_release_id ? `<span class="domain">来自历史版本 #${item.source_release_id}</span>` : ''}</td><td>${statusTag(item.status)}${item.publish_error ? `<span class="domain">${escapeHtml(item.publish_error)}</span>` : ''}</td><td class="recovery-code">${escapeHtml(item.key_id)}</td><td>${formatTime(item.issued_at)}</td><td>${formatTime(item.expires_at)}</td><td class="recovery-code">${escapeHtml(String(item.payload_hash || '').slice(0, 16))}…</td><td><div class="actions">${['draft', 'failed'].includes(item.status) ? `<button class="action" data-recovery-action="publish" data-id="${item.id}">发布</button>` : ''}<button class="action" data-recovery-action="preview-release" data-id="${item.id}">查看</button>${item.status !== 'draft' ? `<button class="action danger" data-recovery-action="rollback" data-id="${item.id}">回滚到此内容</button>` : ''}</div></td></tr>`).join('') || '<tr><td colspan="7" class="recovery-empty">尚未生成恢复清单版本</td></tr>';
    document.querySelector('#recovery-key-state').innerHTML = `<div class="recovery-key-row"><strong>${escapeHtml(keys.currentKeyId || '当前密钥尚未生成')}</strong><span>私钥：${keys.currentPrivateKeyConfigured ? '已安全配置' : '未配置'} · 公钥：${keys.currentPublicKey ? '已发布' : '未发布'}</span></div><div class="recovery-key-row"><strong>${escapeHtml(keys.nextKeyId || '下一代密钥尚未生成')}</strong><span>用于有过渡期的安全轮换；生成后应先发布给客户端，再执行提升。</span></div>`;
    document.querySelector('#recovery-audit').innerHTML = audit.map(item => `<div class="recovery-audit-item"><span>${formatTime(item.created_at)}</span><strong>${escapeHtml(item.action)}</strong><span>${Number(item.success) === 1 ? '成功' : `失败：${escapeHtml(item.error_message)}`}</span></div>`).join('') || '<div class="recovery-empty">暂无操作记录</div>';
  }

  async function load() {
    if (window.adminSessionActive !== true) return;
    const grid = document.querySelector('#recovery-status-grid');
    if (grid) grid.setAttribute('aria-busy', 'true');
    try { state = await request('/api/admin/recovery'); renderOverview(); }
    catch (error) { notify(error.message); if (grid) grid.innerHTML = `<div class="recovery-empty">${escapeHtml(error.message)}</div>`; }
    finally { grid?.removeAttribute('aria-busy'); }
  }

  async function busy(button, text, work) {
    const original = button?.textContent;
    if (button) { button.disabled = true; button.textContent = text; }
    try { return await work(); }
    finally { if (button) { button.disabled = false; button.textContent = original; } }
  }

  function openModal(id) { document.querySelector(id)?.classList.add('open'); document.querySelector(`${id} input:not([type="hidden"])`)?.focus(); }
  function closeModals() { document.querySelectorAll('#recovery .recovery-modal.open').forEach(item => item.classList.remove('open')); }
  function openDomainForm({ domain = null } = {}) {
    const form = document.querySelector('#recovery-domain-form');
    form.reset();
    form.elements.id.value = domain?.id || '';
    form.elements.title.value = domain?.title || '';
    form.elements.url.value = domain?.url || '';
    form.elements.priority.value = domain?.priority ?? 0;
    form.elements.status.checked = domain ? Number(domain.status) === 1 : true;
    document.querySelector('#recovery-domain-title').textContent = domain ? '编辑直接恢复线路' : '新增直接恢复线路';
    openModal('#recovery-domain-modal');
  }
  function domainById(id) { return state?.domains.find(item => Number(item.id) === Number(id)); }
  function bootstrapById(id) { return state?.bootstraps.find(item => Number(item.id) === Number(id)); }
  function channelById(id) { return state?.dnsChannels?.find(item => Number(item.id) === Number(id)); }
  function providerById(id) { return state?.dnsProviders?.find(item => item.id === id); }
  function releaseById(id) { return state?.releases.find(item => Number(item.id) === Number(id)); }
  const roleMeta = Object.freeze({
    A: { label: 'A 分片', prefix: '_recovery-a', help: '保存完整恢复清单的 A 份 XOR 分片。' },
    B: { label: 'B 分片', prefix: '_recovery-b', help: '保存完整恢复清单的 B 份 XOR 分片，需与 A 跨权威 DNS。' },
    LEGACY: { label: 'R1 旧版兼容', prefix: '_recovery', help: '保存包含全部候选域名的完整签名清单。' }
  });
  let targetSequence = 0;
  let groupDomainSequence = 0;

  function rolesForMode(mode) {
    if (mode === 'AB') return ['A', 'B'];
    if (mode === 'R1') return ['LEGACY'];
    return ['A', 'B', 'LEGACY'];
  }

  function targetRecordName(role, zoneName, ordinal = 1) {
    const zone = String(zoneName || '').trim().toLowerCase().replace(/^\.+|\.+$/g, '');
    if (!zone) return '';
    const suffix = ordinal > 1 ? `-${ordinal}` : '';
    return `${roleMeta[role].prefix}${suffix}.${zone}`;
  }

  function renderGroupRoleSections() {
    const channels = (state?.dnsChannels || []).filter(item => Number(item.status) === 1 && item.configured);
    const options = channels.map(item => `<option value="${Number(item.id)}">${escapeHtml(item.provider_label || item.provider_id)} · ${escapeHtml(item.label)}</option>`).join('');
    document.querySelector('#recovery-group-roles').innerHTML = Object.entries(roleMeta).map(([role, meta]) => `
      <section class="recovery-role-card" data-role-section="${role}">
        <div class="recovery-role-head"><div><strong>${meta.label}</strong><p>${meta.help}</p></div><span class="tag neutral" data-role-count="${role}">0 个目标</span></div>
        <div class="recovery-role-tools">
          <label>API 通道（可多选）<select multiple data-role-channel-select="${role}" aria-label="${meta.label} API 通道">${options || '<option disabled>尚无可用 API 通道</option>'}</select></label>
          <button class="button ghost" type="button" data-recovery-action="add-api-targets" data-role="${role}">添加所选 API 通道</button>
          <button class="button ghost" type="button" data-recovery-action="add-manual-target" data-role="${role}">添加手动目标</button>
        </div>
        <div class="recovery-target-list" data-target-list="${role}"><div class="recovery-empty" data-empty-targets>尚未添加${meta.label}发布目标</div></div>
      </section>`).join('');
    syncGroupMode();
  }

  function updateRoleCount(role) {
    const list = document.querySelector(`[data-target-list="${role}"]`);
    const count = list?.querySelectorAll('.recovery-target-card').length || 0;
    const badge = document.querySelector(`[data-role-count="${role}"]`);
    if (badge) badge.textContent = `${count} 个目标`;
    list?.querySelector('[data-empty-targets]')?.toggleAttribute('hidden', count > 0);
  }

  function appendTarget(role, mode, channelId = '') {
    const list = document.querySelector(`[data-target-list="${role}"]`);
    if (!list) return;
    const channel = mode === 'automatic' ? channelById(channelId) : null;
    if (channel && list.querySelector(`[data-channel-id="${Number(channel.id)}"]`)) return;
    const ordinal = list.querySelectorAll('.recovery-target-card').length + 1;
    const targetId = `recovery-target-${targetSequence += 1}`;
    const providerOptions = (state?.dnsProviders || []).map(provider => `<option value="${escapeHtml(provider.id)}">${escapeHtml(provider.label)} · ${Number(provider.portable_record_bytes || 240)} 字节</option>`).join('');
    const providerId = channel?.provider_id || state?.dnsProviders?.[0]?.id || 'cloudflare';
    const provider = providerById(providerId);
    const required = !list.querySelector('.recovery-target-card') && role !== 'LEGACY';
    const card = document.createElement('article');
    card.className = 'recovery-target-card';
    card.id = targetId;
    card.dataset.role = role;
    card.dataset.mode = mode;
    card.dataset.channelId = channel?.id || '';
    card.dataset.ordinal = String(ordinal);
    card.innerHTML = `
      <div class="recovery-target-head"><div><strong>${mode === 'automatic' ? escapeHtml(channel?.label || 'API 通道') : '手动发布目标'}</strong><span>${mode === 'automatic' ? `${escapeHtml(channel?.provider_label || provider?.label || providerId)} · API 自动发布` : '无 API · 管理员写入后 DoH 验证'}</span></div><button class="action danger" type="button" data-recovery-action="remove-group-target" aria-label="删除该发布目标">删除</button></div>
      <div class="recovery-target-fields">
        ${mode === 'manual' ? `<label>DNS 服务商<select data-target-field="providerId" required>${providerOptions}</select></label>` : `<input data-target-field="providerId" type="hidden" value="${escapeHtml(providerId)}"><input data-target-field="dnsChannelId" type="hidden" value="${Number(channel?.id || 0)}">`}
        <label>权威 DNS Zone${mode === 'automatic' ? `<span class="recovery-inline-control"><select data-target-field="zoneName" required><option value="">请先读取账号 Zone</option></select><button class="action" type="button" data-recovery-action="load-target-zones">读取 Zone</button></span>` : '<input data-target-field="zoneName" placeholder="example.com" required>'}</label>
        <label class="full">完整 TXT 记录名<input data-target-field="recordName" placeholder="${roleMeta[role].prefix}.example.com" required><small>默认自动生成；可按需要修改，但必须位于所选 Zone 内。</small></label>
        <label class="recovery-target-required"><input data-target-field="requiredTarget" type="checkbox" ${required ? 'checked' : ''}><span>必需目标；未验证时阻止正式发布</span></label>
        <div class="recovery-byte-badge" data-target-bytes>每条 TXT 最多 ${Math.min(Number(provider?.portable_record_bytes || 240), Number(state?.txtPolicy?.portableBytes || 240))} 字节</div>
      </div>`;
    list.append(card);
    const providerSelect = card.querySelector('[data-target-field="providerId"]');
    if (mode === 'manual' && providerSelect) providerSelect.value = providerId;
    updateRoleCount(role);
  }

  function syncTargetRecord(card) {
    const zone = card.querySelector('[data-target-field="zoneName"]')?.value;
    const record = card.querySelector('[data-target-field="recordName"]');
    if (record && !record.dataset.edited) record.value = targetRecordName(card.dataset.role, zone, Number(card.dataset.ordinal || 1));
    const provider = providerById(card.querySelector('[data-target-field="providerId"]')?.value);
    const limit = Math.min(Number(provider?.portable_record_bytes || 240), Number(state?.txtPolicy?.portableBytes || 240));
    const badge = card.querySelector('[data-target-bytes]');
    if (badge) badge.textContent = `${provider?.label || '当前服务商'}：每条 TXT 最多 ${limit} 字节`;
  }

  function syncGroupMode() {
    const mode = document.querySelector('#recovery-bootstrap-group-form')?.elements.compatibilityMode.value || 'AB_R1';
    const activeRoles = rolesForMode(mode);
    document.querySelectorAll('[data-role-section]').forEach(section => { section.hidden = !activeRoles.includes(section.dataset.roleSection); });
  }

  function appendGroupDomain(values = {}) {
    const list = document.querySelector('#recovery-group-domain-list');
    if (!list || list.querySelectorAll('.recovery-group-domain-card').length >= 10) throw new Error('每个发布组合最多填写 10 个 TXT 候选域名');
    const card = document.createElement('article');
    card.className = 'recovery-group-domain-card';
    card.dataset.domainRow = String(groupDomainSequence += 1);
    card.innerHTML = `<div class="recovery-group-domain-fields"><label>名称<input data-group-domain="title" maxlength="80" value="${escapeHtml(values.title || '')}" placeholder="例如：DNS 备用前台 1" required></label><label>完整 HTTPS Origin<input data-group-domain="url" type="url" value="${escapeHtml(values.url || '')}" placeholder="https://dns-recovery.example.com" required></label><label>优先级<input data-group-domain="priority" type="number" value="${Number(values.priority || 0)}" required></label><label class="recovery-target-required"><input data-group-domain="status" type="checkbox" ${values.status === 0 ? '' : 'checked'}><span>启用</span></label><button class="action danger" type="button" data-recovery-action="remove-group-domain">删除</button></div>`;
    list.append(card);
  }

  function collectGroupDomains() {
    return [...document.querySelectorAll('.recovery-group-domain-card')].map(card => ({
      title: card.querySelector('[data-group-domain="title"]').value,
      url: card.querySelector('[data-group-domain="url"]').value,
      priority: Number(card.querySelector('[data-group-domain="priority"]').value || 0),
      status: card.querySelector('[data-group-domain="status"]').checked ? 1 : 0
    }));
  }

  function openBootstrapGroup() {
    const form = document.querySelector('#recovery-bootstrap-group-form');
    form.reset();
    form.elements.label.value = '主恢复发布组合';
    form.elements.compatibilityMode.value = 'AB_R1';
    document.querySelector('#recovery-group-domain-list').replaceChildren();
    appendGroupDomain();
    const policy = state?.txtPolicy || {};
    document.querySelector('#recovery-group-byte-policy').textContent = `系统统一采用每条 ${Number(policy.portableBytes || 240)} 字节安全上限；完整清单编码后最多 ${Number(policy.maxEncodedBytes || 4096)} 字节，每个角色最多 ${Number(policy.maxPartsPerRole || 50)} 条 TXT 值。`;
    document.querySelector('#recovery-group-error').hidden = true;
    renderGroupRoleSections();
    openModal('#recovery-bootstrap-group-modal');
  }

  function collectGroupTargets() {
    const mode = document.querySelector('#recovery-bootstrap-group-form').elements.compatibilityMode.value;
    const activeRoles = rolesForMode(mode);
    return [...document.querySelectorAll('.recovery-target-card')].filter(card => activeRoles.includes(card.dataset.role)).map((card, index) => ({
      label: `${document.querySelector('#recovery-bootstrap-group-form').elements.label.value} · ${roleMeta[card.dataset.role].label} ${index + 1}`,
      shareRole: card.dataset.role,
      publishMode: card.dataset.mode,
      dnsChannelId: Number(card.querySelector('[data-target-field="dnsChannelId"]')?.value || 0) || null,
      providerId: card.querySelector('[data-target-field="providerId"]')?.value || '',
      zoneName: card.querySelector('[data-target-field="zoneName"]')?.value || '',
      recordName: card.querySelector('[data-target-field="recordName"]')?.value || '',
      providerZoneId: card.querySelector('[data-target-field="zoneName"]')?.selectedOptions?.[0]?.dataset.zoneId || '',
      requiredTarget: card.querySelector('[data-target-field="requiredTarget"]')?.checked ? 1 : 0,
      status: 1,
      sortOrder: index
    }));
  }

  function renderChannelCredentials(providerId, channel = null) {
    const container = document.querySelector('#recovery-channel-credentials');
    const secretPlaceholder = channel ? '留空表示保持原值' : '请输入凭据';
    const templates = {
      cloudflare: `<label class="recovery-switch"><input name="reuseCentral" type="checkbox" value="1" ${channel?.reuse_central ? 'checked' : ''}><span><strong>复用中央 Cloudflare 凭据</strong><small class="hint">使用“Cloudflare 管理”中已保存的 Account ID 与 Token。</small></span></label><label>Account ID<input name="accountId" autocomplete="off" placeholder="${secretPlaceholder}"></label><label>API Token<input name="apiToken" type="password" autocomplete="new-password" placeholder="${secretPlaceholder}"></label>`,
      desec: `<label class="full">API Token<input name="apiToken" type="password" autocomplete="new-password" placeholder="${secretPlaceholder}"></label>`,
      cloudns: `<label>认证类型<select name="authType"><option value="auth-id">主账号 Auth ID</option><option value="sub-auth-id">子账号 Sub Auth ID</option><option value="sub-auth-user">子账号用户名</option></select></label><label>账号标识<input name="authId" autocomplete="off" placeholder="${secretPlaceholder}"></label><label class="full">Auth Password<input name="authPassword" type="password" autocomplete="new-password" placeholder="${secretPlaceholder}"></label>`,
      route53: `<label>Access Key ID<input name="accessKeyId" autocomplete="off" placeholder="${secretPlaceholder}"></label><label>Secret Access Key<input name="secretAccessKey" type="password" autocomplete="new-password" placeholder="${secretPlaceholder}"></label><label class="full">Session Token（可选）<input name="sessionToken" type="password" autocomplete="new-password" placeholder="临时凭据使用；留空保持原值"></label>`,
      dnspod: `<label>SecretId<input name="secretId" autocomplete="off" placeholder="${secretPlaceholder}"></label><label>SecretKey<input name="secretKey" type="password" autocomplete="new-password" placeholder="${secretPlaceholder}"></label>`,
      aliyun: `<label>AccessKey ID<input name="accessKeyId" autocomplete="off" placeholder="${secretPlaceholder}"></label><label>AccessKey Secret<input name="accessKeySecret" type="password" autocomplete="new-password" placeholder="${secretPlaceholder}"></label>`,
      baidu: `<label>Access Key ID<input name="accessKeyId" autocomplete="off" placeholder="${secretPlaceholder}"></label><label>Secret Access Key<input name="secretAccessKey" type="password" autocomplete="new-password" placeholder="${secretPlaceholder}"></label>`,
      volcengine: `<label>Access Key ID<input name="accessKeyId" autocomplete="off" placeholder="${secretPlaceholder}"></label><label>Secret Access Key<input name="secretAccessKey" type="password" autocomplete="new-password" placeholder="${secretPlaceholder}"></label><label>区域<input name="region" autocomplete="off" value="${escapeHtml(channel?.region || 'cn-beijing')}" placeholder="cn-beijing"></label><label>Session Token（可选）<input name="sessionToken" type="password" autocomplete="new-password" placeholder="临时凭据使用；留空保持原值"></label>`
    };
    container.innerHTML = templates[providerId] || '<p class="hint">该服务商当前没有自动发布接口。</p>';
    if (providerId === 'cloudns' && container.querySelector('[name="authType"]')) container.querySelector('[name="authType"]').value = channel?.auth_type || 'auth-id';
    const reuse = container.querySelector('[name="reuseCentral"]');
    const syncCentral = () => container.querySelectorAll('[name="accountId"], [name="apiToken"]').forEach(field => { field.disabled = reuse?.checked === true; });
    reuse?.addEventListener('change', syncCentral); syncCentral();
  }

  function syncBootstrapPublisher(preferredChannelId = '', preferredMode = '') {
    const form = document.querySelector('#recovery-bootstrap-form');
    const provider = providerById(form.elements.providerId.value);
    const mode = form.elements.publishMode;
    const supportsAutomatic = provider?.automatic_publish === true;
    const previousMode = preferredMode || mode.value;
    mode.innerHTML = `${supportsAutomatic ? '<option value="automatic">API 自动发布</option>' : ''}<option value="manual">手动发布并 DoH 验证</option>`;
    mode.value = supportsAutomatic && previousMode !== 'manual' ? 'automatic' : 'manual';
    const channels = (state?.dnsChannels || []).filter(item => item.provider_id === provider?.id && Number(item.status) === 1);
    const select = form.elements.dnsChannelId;
    select.innerHTML = `<option value="">请选择 API 通道</option>${channels.map(item => `<option value="${Number(item.id)}" ${item.configured ? '' : 'disabled'}>${escapeHtml(item.label)} · ${escapeHtml(item.account_hint || '未显示账号')}${item.configured ? '' : ' · 凭据不完整'}</option>`).join('')}`;
    if (preferredChannelId && channels.some(item => String(item.id) === String(preferredChannelId) && item.configured)) select.value = String(preferredChannelId);
    else if (channels.filter(item => item.configured).length === 1) select.value = String(channels.find(item => item.configured).id);
    const automatic = mode.value === 'automatic';
    document.querySelector('#recovery-bootstrap-channel-field').hidden = !automatic;
    select.required = automatic;
    document.querySelector('#recovery-bootstrap-publish-hint').innerHTML = automatic
      ? (channels.some(item => item.configured) ? '发布时使用所选通道写入 TXT，并在 DoH 验证成功后清理本系统旧代分片。' : `尚未配置可用的 ${escapeHtml(provider?.label || '')} API 通道，请先在页面右侧新增通道。`)
      : '系统生成 TXT 内容，由管理员写入权威 DNS 后再执行 DoH 回读验证。';
  }

  async function handleAction(event) {
    const button = event.target.closest('[data-recovery-action]');
    if (!button) return;
    const action = button.dataset.recoveryAction, id = Number(button.dataset.id || 0);
    try {
      if (action === 'reload') return load();
      if (action === 'create-profile') {
        const name = prompt('请输入恢复方案名称，例如：国内主站恢复'); if (!name) return;
        const code = prompt('请输入方案标识，只能使用小写字母、数字、连字符或下划线，例如：cn-main'); if (!code) return;
        const created = await request('/api/admin/recovery/profiles', { method: 'POST', body: JSON.stringify({ name, code }) });
        currentProfileId = Number(created.id); notify('恢复方案已创建，请继续配置备用域名和查询线路'); return load();
      }
      if (action === 'open-domain') return openDomainForm();
      if (action === 'edit-domain') { const item = domainById(id); if (item) return openDomainForm({ domain: item }); return; }
      if (action === 'open-bootstrap-group') return openBootstrapGroup();
      if (action === 'add-group-domain') { appendGroupDomain(); return; }
      if (action === 'remove-group-domain') { button.closest('.recovery-group-domain-card')?.remove(); return; }
      if (action === 'add-api-targets') {
        const role = button.dataset.role;
        const select = document.querySelector(`[data-role-channel-select="${role}"]`);
        const selected = [...(select?.selectedOptions || [])].map(option => Number(option.value)).filter(Boolean);
        if (!selected.length) throw new Error('请先选择一个或多个 API 通道');
        selected.forEach(channelId => appendTarget(role, 'automatic', channelId));
        select.selectedIndex = -1;
        return;
      }
      if (action === 'add-manual-target') { appendTarget(button.dataset.role, 'manual'); return; }
      if (action === 'remove-group-target') { const card = button.closest('.recovery-target-card'); const role = card?.dataset.role; card?.remove(); if (role) updateRoleCount(role); return; }
      if (action === 'copy-manual-value') { await navigator.clipboard.writeText(button.previousElementSibling?.textContent || ''); notify('TXT 值已复制'); return; }
      if (action === 'copy-manual-block') { const values = [...button.closest('.recovery-result').querySelectorAll('.recovery-manual-value')].map(item => item.textContent); await navigator.clipboard.writeText(values.join('\n')); notify(`已复制 ${values.length} 条 TXT 值`); return; }
      if (action === 'load-target-zones') {
        const card = button.closest('.recovery-target-card');
        const channelId = Number(card?.dataset.channelId || 0);
        if (!channelId) throw new Error('该目标没有可用的 API 通道');
        const zones = await busy(button, '读取中…', () => request(`/api/admin/recovery/dns-channels/${channelId}/zones`));
        const select = card.querySelector('[data-target-field="zoneName"]');
        select.innerHTML = `<option value="">请选择 Zone</option>${zones.map(zone => `<option value="${escapeHtml(zone.name)}" data-zone-id="${escapeHtml(zone.id || '')}">${escapeHtml(zone.name)}</option>`).join('')}`;
        if (zones.length === 1) select.value = zones[0].name;
        syncTargetRecord(card);
        notify(`已读取 ${zones.length} 个 Zone`);
        return;
      }
      if (action === 'configure-group-routes') {
        const form = document.querySelector('#recovery-route-plan-form');
        form.reset();
        form.elements.groupId.value = id;
        currentRoutePlan = null;
        form.querySelector('button[type="submit"]').disabled = true;
        document.querySelector('#recovery-route-plan-error').hidden = true;
        document.querySelector('#recovery-route-plan-preview').innerHTML = '<div class="recovery-empty">正在计算三层查询线路…</div>';
        openModal('#recovery-route-plan-modal');
        return previewRoutePlan(button);
      }
      if (action === 'preview-route-plan') return previewRoutePlan(button);
      if (action === 'test-group-routes') {
        const container = document.querySelector('#recovery-doh-results');
        container.innerHTML = '<div class="recovery-empty">正在检测中国大陆主力、全球主力和扩展容灾线路…</div>';
        const result = await busy(button, '检测中…', () => request(`/api/admin/recovery/bootstrap-groups/${id}/lookup-routes/test`, { method: 'POST', body: '{}' }));
        const summary = [`检测 ${Number(result.total)} 条`, `读取成功 ${Number(result.successful)} 条`];
        if (Number(result.propagating)) summary.push(`等待传播 ${Number(result.propagating)} 条`);
        if (Number(result.resolverUnavailable)) summary.push(`解析器不可用 ${Number(result.resolverUnavailable)} 条`);
        if (Number(result.otherFailed)) summary.push(`其他异常 ${Number(result.otherFailed)} 条`);
        const graceHint = result.propagationGraceActive ? `<p class="hint">当前处于发布后 ${Number(result.propagationGraceMinutes)} 分钟传播宽限期，“等待传播”不会判定为发布失败。</p>` : '';
        const tierRows = result.tiers.map(tier => {
          const notes = [];
          if (Number(tier.propagating)) notes.push(`传播中 ${Number(tier.propagating)}`);
          if (Number(tier.resolverUnavailable)) notes.push(`解析器不可用 ${Number(tier.resolverUnavailable)}`);
          return `<div><span>P${Number(tier.priorityGroup)} · ${escapeHtml(tier.label)}</span><b>${Number(tier.successful)}/${Number(tier.total)}</b><small>A+B：${tier.abValid ? '有效' : '未验证'} · R1：${tier.r1Valid ? '有效' : '未验证'}${notes.length ? ` · ${escapeHtml(notes.join(' · '))}` : ''}</small></div>`;
        }).join('');
        const detailRows = result.lines.filter(line => line.state !== 'healthy').map(line => `<div class="recovery-result recovery-result-error"><strong>P${Number(line.priorityGroup)} · ${escapeHtml(line.resolverLabel)} → ${escapeHtml(line.recordName)}</strong><p>${escapeHtml(line.statusLabel || '检测异常')}${line.error && line.error !== line.statusLabel ? `：${escapeHtml(line.error)}` : ''}</p></div>`).join('');
        container.innerHTML = `<div class="recovery-result"><strong>${escapeHtml(result.group.label)} · 三层查询线路检测</strong><p>${summary.join('，')}。</p>${graceHint}<div class="recovery-test-tier-list">${tierRows}</div></div>${detailRows}`;
        notify(`线路检测完成：成功 ${result.successful}，传播中 ${result.propagating || 0}，解析器不可用 ${result.resolverUnavailable || 0}`);
        return;
      }
      if (action === 'delete-bootstrap-group' && confirm('确定删除整个 DNS 发布组合吗？组合内目标和查询线路会一起删除，权威 DNS 中已写入的 TXT 不会自动删除。')) { await request(`/api/admin/recovery/bootstrap-groups/${id}`, { method: 'DELETE' }); notify('DNS 发布组合已删除'); return load(); }
      if (action === 'open-channel') { const form = document.querySelector('#recovery-channel-form'); form.reset(); form.elements.id.value = ''; form.elements.providerId.disabled = false; form.elements.status.checked = true; renderChannelCredentials(form.elements.providerId.value); return openModal('#recovery-channel-modal'); }
      if (action === 'edit-channel') { const item = channelById(id); if (!item) return; const form = document.querySelector('#recovery-channel-form'); form.reset(); form.elements.id.value = item.id; form.elements.label.value = item.label; form.elements.providerId.value = item.provider_id; form.elements.providerId.disabled = item.legacy === true; form.elements.status.checked = Number(item.status) === 1; renderChannelCredentials(item.provider_id, item); return openModal('#recovery-channel-modal'); }
      if (action === 'test-channel') { const result = await busy(button, '验证中…', () => request(`/api/admin/recovery/dns-channels/${id}/test`, { method: 'POST', body: '{}' })); notify(`API 通道验证成功，可访问 ${result.zoneCount} 个 Zone`); return load(); }
      if (action === 'load-channel-zones') { const form = document.querySelector('#recovery-bootstrap-form'); const channelId = Number(form.elements.dnsChannelId.value || 0); if (!channelId) throw new Error('请先选择 API 通道'); const zones = await busy(button, '读取中…', () => request(`/api/admin/recovery/dns-channels/${channelId}/zones`)); document.querySelector('#recovery-zone-options').innerHTML = zones.map(zone => `<option value="${escapeHtml(zone.name)}">${escapeHtml(zone.name)}</option>`).join(''); if (zones.length === 1) { form.elements.zoneName.value = zones[0].name; form.elements.providerZoneId.value = zones[0].id || ''; } notify(`已读取 ${zones.length} 个 Zone`); return; }
      if (action === 'delete-channel' && confirm('确定删除这个 DNS API 通道吗？仍被 Bootstrap DNS 使用的通道不能删除。')) { await request(`/api/admin/recovery/dns-channels/${id}`, { method: 'DELETE' }); notify('DNS API 通道已删除'); return load(); }
      if (action === 'open-bootstrap') { const form = document.querySelector('#recovery-bootstrap-form'); form.reset(); form.elements.id.value = ''; form.elements.status.checked = true; form.elements.providerId.value = 'cloudflare'; form.elements.shareRole.value = 'A'; syncBootstrapPublisher('', 'automatic'); return openModal('#recovery-bootstrap-modal'); }
      if (action === 'edit-bootstrap') { const item = bootstrapById(id); if (!item) return; const form = document.querySelector('#recovery-bootstrap-form'); form.reset(); form.elements.id.value = item.id; form.elements.label.value = item.label; form.elements.recordName.value = item.record_name; form.elements.zoneName.value = item.zone_name; form.elements.providerZoneId.value = item.provider_zone_id || ''; form.elements.sortOrder.value = item.sort_order; form.elements.providerId.value = item.provider_id || 'cloudflare'; form.elements.shareRole.value = item.share_role || 'LEGACY'; form.elements.status.checked = Number(item.status) === 1; syncBootstrapPublisher(item.dns_channel_id, item.publish_mode || 'manual'); return openModal('#recovery-bootstrap-modal'); }
      if (action === 'delete-domain' && confirm('确定删除这条恢复专用线路吗？已发布的历史版本不会被修改。')) { await request(`/api/admin/recovery/domains/${id}`, { method: 'DELETE' }); notify('恢复线路已删除'); return load(); }
      if (action === 'delete-bootstrap' && confirm('确定删除这个 Bootstrap DNS 配置吗？权威 DNS 中已发布的 TXT 不会自动删除。')) { await request(`/api/admin/recovery/bootstrap/${id}`, { method: 'DELETE' }); notify('Bootstrap DNS 已删除'); return load(); }
      if (action === 'delete-route' && confirm('确定删除这条 DNS/TXT 查询线路吗？')) { await request(`/api/admin/recovery/lookup-routes/${id}`, { method: 'DELETE' }); notify('查询线路已删除'); return load(); }
      if (action === 'probe-domain') { await busy(button, '检测中…', () => request(`/api/admin/recovery/domains/${id}/probe`, { method: 'POST', body: '{}' })); notify('线路检测完成'); return load(); }
      if (action === 'probe-all') { const result = await busy(button, '正在检测…', () => request('/api/admin/recovery/domains/probe-all', { method: 'POST', body: '{}' })); notify(`检测完成：正常 ${result.healthy} 条，异常 ${result.failed} 条`); return load(); }
      if (action === 'ensure-key') { await busy(button, '准备中…', () => request('/api/admin/recovery/keys/ensure', { method: 'POST', body: '{}' })); notify('签名密钥已就绪'); return load(); }
      if (action === 'next-key') { if (!confirm('生成下一代密钥后，应先通过新版本把公钥交付给客户端，再提升为当前密钥。是否继续？')) return; await busy(button, '生成中…', () => request('/api/admin/recovery/keys/next', { method: 'POST', body: '{}' })); notify('下一代密钥已生成'); return load(); }
      if (action === 'promote-key') { if (!confirm('提升密钥属于高风险操作。确认已经通过正式清单向老用户分发下一代公钥了吗？')) return; await busy(button, '提升中…', () => request('/api/admin/recovery/keys/promote', { method: 'POST', body: '{}' })); notify('密钥已轮换'); return load(); }
      if (action === 'create-draft') { await busy(button, '生成中…', () => request('/api/admin/recovery/releases/draft', { method: 'POST', body: '{}' })); notify('新版本草稿已生成'); return load(); }
      if (action === 'publish-latest') { const draft = state?.releases.find(item => ['draft', 'failed'].includes(item.status)); if (!draft) throw new Error('没有可发布的草稿，请先生成新版本'); return publish(button, draft.id); }
      if (action === 'publish') return publish(button, id);
      if (action === 'rollback') { const release = releaseById(id); if (!release || !confirm(`将以更高 generation 重新发布 generation ${release.generation} 的内容，是否继续？`)) return; const result = await busy(button, '回滚发布中…', () => request(`/api/admin/recovery/releases/${id}/rollback`, { method: 'POST', body: '{}' })); notify(result.warning || '历史内容已重新发布'); return load(); }
      if (action === 'preview-release') { const release = releaseById(id); if (release) alert(JSON.stringify(release.envelope, null, 2)); return; }
      if (action === 'doh') { const container = document.querySelector('#recovery-doh-results'); container.innerHTML = '<div class="recovery-empty">正在按当前方案中映射到该 TXT 的 DoH 线路回读…</div>'; const result = await busy(button, '回读中…', () => request(`/api/admin/recovery/bootstrap/${id}/doh`)); container.innerHTML = result.results.map(item => `<div class="recovery-result"><strong>${escapeHtml(item.label)} · ${item.ok ? '查询成功' : '查询失败'}</strong><p>${item.ok ? (item.envelopes.length ? item.envelopes.map(value => `generation ${value.generation} · 签名${value.signatureValid ? '有效' : '无效'}`).join('<br>') : '没有发现完整恢复清单') : escapeHtml(item.error)}</p></div>`).join('') || '<div class="recovery-empty">没有 DNS 服务商映射到这条 TXT，请先添加查询线路。</div>'; return; }
    } catch (error) { notify(error.message || '操作失败'); }
  }

  async function publish(button, id) {
    if (!confirm('发布会写入已配置的 Bootstrap DNS，并替换当前正式版本。确认继续吗？')) return;
    const result = await busy(button, '发布中…', () => request(`/api/admin/recovery/releases/${id}/publish`, { method: 'POST', body: '{}' }));
    const output = [];
    if (result.manualRecords?.length) {
      output.push(...result.manualRecords.map(record => `<div class="recovery-result"><strong>${escapeHtml(record.providerId)} · ${escapeHtml(record.recordName)} · ${escapeHtml(record.role === 'LEGACY' ? 'R1' : record.role)} 分片</strong><p>请把下列 ${record.values.length} 条值分别建立在同一个 TXT 记录名下；每条不得超过 ${Number(record.byteLimit)} 字节。</p><div class="recovery-manual-actions"><button class="action" type="button" data-recovery-action="copy-manual-block">复制全部</button></div>${record.values.map((value, index) => `<div class="recovery-manual-row"><code class="recovery-manual-value">${escapeHtml(value)}</code><button class="action" type="button" data-recovery-action="copy-manual-value">复制第 ${index + 1} 条</button></div>`).join('')}</div>`));
    }
    if (result.failedRecords?.length) output.push(`<div class="recovery-result recovery-result-error"><strong>未完成的 API 发布目标</strong>${result.failedRecords.map(record => `<p>${escapeHtml(record.providerId)} · ${escapeHtml(record.recordName)}：${escapeHtml(record.error || '发布失败')}</p>`).join('')}</div>`);
    document.querySelector('#recovery-doh-results').innerHTML = output.join('');
    notify(result.warning || `恢复清单已发布到 ${result.dnsPublished} 个 DNS 记录`);
    return load();
  }

  function bindPanel(panel) {
    panel.addEventListener('click', handleAction);
    panel.querySelectorAll('[data-close-recovery-modal]').forEach(button => button.addEventListener('click', closeModals));
    panel.querySelectorAll('.recovery-modal').forEach(modal => modal.addEventListener('click', event => {
      if (event.target !== modal) return;
      closeModals();
    }));
    panel.querySelector('#recovery-profile-select').addEventListener('change', event => { currentProfileId = Number(event.currentTarget.value) || 1; void load(); });
    panel.querySelector('#recovery-bootstrap-group-form').elements.compatibilityMode.addEventListener('change', syncGroupMode);
    panel.addEventListener('change', event => {
      const card = event.target.closest('.recovery-target-card');
      if (!card) return;
      if (event.target.matches('[data-target-field="zoneName"], [data-target-field="providerId"]')) syncTargetRecord(card);
    });
    panel.addEventListener('input', event => {
      const card = event.target.closest('.recovery-target-card');
      if (!card) return;
      if (event.target.matches('[data-target-field="recordName"]')) event.target.dataset.edited = event.target.value ? '1' : '';
      if (card.dataset.mode === 'manual' && event.target.matches('[data-target-field="zoneName"]')) syncTargetRecord(card);
    });
    const bootstrapForm = panel.querySelector('#recovery-bootstrap-form');
    bootstrapForm.elements.providerId.addEventListener('change', () => syncBootstrapPublisher('', 'automatic'));
    bootstrapForm.elements.publishMode.addEventListener('change', () => syncBootstrapPublisher(bootstrapForm.elements.dnsChannelId.value, bootstrapForm.elements.publishMode.value));
    const channelForm = panel.querySelector('#recovery-channel-form');
    channelForm.elements.providerId.addEventListener('change', event => renderChannelCredentials(event.currentTarget.value));
    const routePlanForm = panel.querySelector('#recovery-route-plan-form');
    [...routePlanForm.querySelectorAll('[name="applyMode"]')].forEach(field => field.addEventListener('change', () => {
      currentRoutePlan = null;
      routePlanForm.querySelector('button[type="submit"]').disabled = true;
      void previewRoutePlan(routePlanForm.querySelector('[data-recovery-action="preview-route-plan"]')).catch(error => notify(error.message));
    }));
    routePlanForm.addEventListener('submit', async event => {
      event.preventDefault();
      const form = event.currentTarget, submit = form.querySelector('button[type="submit"]');
      if (!currentRoutePlan?.configurationRevision) return notify('请先生成有效预览');
      const groupId = Number(form.elements.groupId.value || 0);
      const payload = { architecture: 'three_tier_full', applyMode: form.elements.applyMode.value, configurationRevision: currentRoutePlan.configurationRevision };
      try {
        await busy(submit, '应用中…', () => request(`/api/admin/recovery/bootstrap-groups/${groupId}/lookup-routes/apply`, { method: 'POST', body: JSON.stringify(payload) }));
        closeModals();
        currentRoutePlan = null;
        notify('中国大陆主力、全球主力和扩展容灾线路已应用');
        await load();
      } catch (error) {
        const errorBox = document.querySelector('#recovery-route-plan-error');
        errorBox.textContent = error.message;
        errorBox.hidden = false;
        errorBox.focus();
      }
    });
    panel.querySelector('#recovery-route-form').addEventListener('submit', async event => {
      event.preventDefault(); const form = event.currentTarget, submit = form.querySelector('button[type="submit"]');
      const payload = Object.fromEntries(new FormData(form)); payload.status = 1;
      try { await busy(submit, '添加中…', () => request('/api/admin/recovery/lookup-routes', { method: 'POST', body: JSON.stringify(payload) })); form.reset(); notify('DNS/TXT 查询线路已添加'); await load(); } catch (error) { notify(error.message); }
    });
    panel.querySelector('#recovery-settings-form').addEventListener('submit', async event => {
      event.preventDefault(); const form = event.currentTarget, submit = form.querySelector('button[type="submit"]');
      const payload = Object.fromEntries(new FormData(form)); payload.enabled = form.elements.enabled.checked ? 1 : 0;
      try { await busy(submit, '保存中…', () => request('/api/admin/recovery/settings', { method: 'PUT', body: JSON.stringify(payload) })); notify('恢复系统设置已保存'); await load(); } catch (error) { notify(error.message); }
    });
    panel.querySelector('#recovery-bootstrap-group-form').addEventListener('submit', async event => {
      event.preventDefault();
      const form = event.currentTarget, submit = form.querySelector('button[type="submit"]'), errorBox = document.querySelector('#recovery-group-error');
      const payload = { label: form.elements.label.value, compatibilityMode: form.elements.compatibilityMode.value, status: 1, domains: collectGroupDomains(), targets: collectGroupTargets() };
      try {
        errorBox.hidden = true;
        await busy(submit, '创建中…', () => request('/api/admin/recovery/bootstrap-groups', { method: 'POST', body: JSON.stringify(payload) }));
        closeModals(); notify(`DNS 发布组合已创建，包含 ${payload.domains.length} 个 TXT 候选域名和 ${payload.targets.length} 个目标`); await load();
      } catch (error) {
        errorBox.textContent = `${error.message}。请检查角色、通道、Zone、记录名和跨服务商配置。`;
        errorBox.hidden = false;
        errorBox.focus?.();
      }
    });
    channelForm.addEventListener('submit', async event => {
      event.preventDefault(); const form = event.currentTarget, id = form.elements.id.value, submit = form.querySelector('button[type="submit"]');
      const providerId = form.elements.providerId.value;
      const payload = Object.fromEntries(new FormData(form));
      payload.providerId = providerId;
      payload.status = form.elements.status.checked ? 1 : 0;
      payload.reuseCentral = form.elements.reuseCentral?.checked === true;
      try { await busy(submit, '保存中…', () => request(id ? `/api/admin/recovery/dns-channels/${id}` : '/api/admin/recovery/dns-channels', { method: id ? 'PUT' : 'POST', body: JSON.stringify(payload) })); form.elements.providerId.disabled = false; closeModals(); notify('DNS API 通道已保存'); await load(); } catch (error) { notify(error.message); }
    });
    panel.querySelector('#recovery-domain-form').addEventListener('submit', async event => {
      event.preventDefault(); const form = event.currentTarget, id = form.elements.id.value, submit = form.querySelector('button[type="submit"]');
      const payload = Object.fromEntries(new FormData(form)); payload.status = form.elements.status.checked ? 1 : 0;
      try {
        await busy(submit, '保存中…', () => request(id ? `/api/admin/recovery/domains/${id}` : '/api/admin/recovery/domains', { method: id ? 'PUT' : 'POST', body: JSON.stringify(payload) }));
        closeModals(); notify('直接恢复线路已保存'); await load();
      } catch (error) { notify(error.message); }
    });
    panel.querySelector('#recovery-bootstrap-form').addEventListener('submit', async event => {
      event.preventDefault(); const form = event.currentTarget, id = form.elements.id.value, submit = form.querySelector('button[type="submit"]');
      const payload = Object.fromEntries(new FormData(form)); payload.isPrimary = 0; payload.status = form.elements.status.checked ? 1 : 0;
      try { await busy(submit, '保存中…', () => request(id ? `/api/admin/recovery/bootstrap/${id}` : '/api/admin/recovery/bootstrap', { method: id ? 'PUT' : 'POST', body: JSON.stringify(payload) })); closeModals(); notify('Bootstrap DNS 已保存'); await load(); } catch (error) { notify(error.message); }
    });
  }

  installPanel();
  window.loadRecoveryAdmin = load;
})();
