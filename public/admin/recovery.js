/** 独立老用户恢复系统后台。与首页防失联弹窗、镜像节点完全隔离。 */
(() => {
  const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
  const formatTime = value => window.formatAdminTime?.(value) || value || '—';
  const notify = message => typeof window.toast === 'function' ? window.toast(message) : (() => {
    const el = document.querySelector('#toast'); if (!el) return; el.textContent = message; el.classList.add('show'); setTimeout(() => el.classList.remove('show'), 3000);
  })();
  let state = null;
  let currentProfileId = 1;

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
              <label>最多候选域名<input name="max_domains" type="number" min="1" max="10" required></label>
              <label>单次测活超时（毫秒）<input name="probe_timeout_ms" type="number" min="1000" max="10000" step="100" required></label>
              <label>测活并发数<input name="probe_concurrency" type="number" min="1" max="3" required></label>
              <div class="recovery-form-actions"><button class="button" type="submit">保存恢复设置</button></div>
            </form>
          </div>
          <div class="box"><div class="box-head"><div><h2>恢复专用线路</h2><p class="hint">仅接受 HTTPS Origin；测活固定使用 /.well-known/route-health.gif。</p></div><button class="button" type="button" data-recovery-action="open-domain">新增线路</button></div>
            <div class="table-wrap"><table class="recovery-table"><thead><tr><th>线路</th><th>地址</th><th>优先级</th><th>状态</th><th>动态图片检测</th><th>最近检测</th><th>操作</th></tr></thead><tbody id="recovery-domain-body"></tbody></table></div>
          </div>
          <div class="box"><div class="box-head"><div><h2>Bootstrap DNS</h2><p class="hint">新版本使用 A/B 两份 XOR 分片；至少从不同权威 DNS 各取得一份才可恢复。每条 TXT 强制不超过 240 字节，兼容五家托管商的 255 字节单字符串限制。</p></div><button class="button" type="button" data-recovery-action="open-bootstrap">新增 DNS</button></div>
            <div class="table-wrap"><table class="recovery-table"><thead><tr><th>名称</th><th>权威 DNS</th><th>TXT 记录</th><th>分片</th><th>单条限制</th><th>发布状态</th><th>当前代</th><th>操作</th></tr></thead><tbody id="recovery-bootstrap-body"></tbody></table></div>
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
      <div id="recovery-domain-modal" class="modal recovery-modal" role="dialog" aria-modal="true" aria-labelledby="recovery-domain-title"><form id="recovery-domain-form" class="dialog"><h3 id="recovery-domain-title">恢复线路</h3><input name="id" type="hidden"><div class="form-grid"><label>线路名称<input name="title" maxlength="80" required></label><label>优先级<input name="priority" type="number" value="0" required></label><label class="full">HTTPS 地址<input name="url" type="url" placeholder="https://recovery.example" required></label><label class="full exemption-option"><input name="status" type="checkbox" value="1" checked><span>启用该线路</span></label></div><div class="dialog-foot"><button class="button ghost" type="button" data-close-recovery-modal>取消</button><button class="button" type="submit">保存线路</button></div></form></div>
      <div id="recovery-bootstrap-modal" class="modal recovery-modal" role="dialog" aria-modal="true" aria-labelledby="recovery-bootstrap-title"><form id="recovery-bootstrap-form" class="dialog"><h3 id="recovery-bootstrap-title">Bootstrap DNS</h3><input name="id" type="hidden"><input name="isPrimary" type="hidden" value="0"><input name="providerZoneId" type="hidden"><div class="form-grid"><label>显示名称<input name="label" maxlength="80" required></label><label>排序<input name="sortOrder" type="number" value="0" required></label><label>权威 DNS 托管商<select name="providerId" required></select></label><label>分片角色<select name="shareRole" required><option value="A">A 分片</option><option value="B">B 分片</option><option value="LEGACY">旧版 r1 兼容</option></select></label><label>发布方式<select name="publishMode" required><option value="automatic">API 自动发布</option><option value="manual">手动发布并 DoH 验证</option></select></label><label id="recovery-bootstrap-channel-field">API 通道<select name="dnsChannelId"></select></label><p id="recovery-bootstrap-publish-hint" class="hint full"></p><label class="full">TXT 记录名<input name="recordName" placeholder="_recovery-a.bootstrap.example" required></label><label class="full">权威 DNS Zone<input name="zoneName" placeholder="bootstrap.example" required></label><p class="hint full">每条 TXT 使用 240 字节安全上限；自动发布只清理本系统旧代分片，不会删除同名的其他 TXT。</p><label class="exemption-option full"><input name="status" type="checkbox" value="1" checked><span>启用</span></label></div><div class="dialog-foot"><button class="button ghost" type="button" data-close-recovery-modal>取消</button><button class="button" type="submit">保存 DNS</button></div></form></div>
      <div id="recovery-channel-modal" class="modal recovery-modal" role="dialog" aria-modal="true" aria-labelledby="recovery-channel-title"><form id="recovery-channel-form" class="dialog"><h3 id="recovery-channel-title">DNS API 通道</h3><input name="id" type="hidden"><div class="form-grid"><label>通道名称<input name="label" maxlength="80" placeholder="例如：Cloudflare 主账号" required></label><label>DNS 服务商<select name="providerId" required></select></label><div id="recovery-channel-credentials" class="recovery-credential-fields full"></div><p class="hint full">敏感字段留空表示保持原值。保存后只显示脱敏账号标识，不回显密钥。</p><label class="exemption-option full"><input name="status" type="checkbox" value="1" checked><span>启用该 API 通道</span></label></div><div class="dialog-foot"><button class="button ghost" type="button" data-close-recovery-modal>取消</button><button class="button" type="submit">保存通道</button></div></form></div>
    `;
    document.querySelector('.shell')?.append(panel);
    bindPanel(panel);
  }

  function statusTag(value, labels = {}) {
    const map = { published: ['已发布', ''], draft: ['草稿', 'warn'], failed: ['失败', 'off'], superseded: ['已替代', 'neutral'], verified: ['已验证', ''], manual_required: ['待手动写入', 'warn'], unpublished: ['未发布', 'neutral'], healthy: ['正常', ''], untested: ['未检测', 'neutral'] };
    const [text, tone] = map[value] || [labels[value] || value || '未知', 'off'];
    return `<span class="tag ${tone}">${escapeHtml(text)}</span>`;
  }

  function renderOverview() {
    if (!state) return;
    const { settings, domains, bootstraps, releases, keys, audit, profiles = [], resolvers = [], dnsProviders = [], dnsChannels = [], lookupRoutes = [] } = state;
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
    document.querySelector('#recovery-bootstrap-body').innerHTML = bootstraps.map(item => `<tr><td><strong>${escapeHtml(item.label)}</strong></td><td><strong>${escapeHtml(item.provider_label || item.provider_id)}</strong><span class="domain">${item.publish_mode === 'automatic' ? `API 自动 · ${escapeHtml(item.channel_label || '未绑定通道')}` : '手动 + DoH 验证'}</span></td><td class="recovery-code">${escapeHtml(item.record_name)}<span class="domain">${escapeHtml(item.zone_name)}</span></td><td><span class="tag ${item.share_role === 'LEGACY' ? 'neutral' : ''}">${escapeHtml(item.share_role || 'LEGACY')}</span></td><td>${Number(item.portable_record_bytes || 240)} / ${Number(item.max_character_string_bytes || 255)} 字节</td><td>${statusTag(item.last_publish_status)}${item.last_publish_error ? `<span class="domain">${escapeHtml(item.last_publish_error)}</span>` : ''}</td><td>${Number(item.last_published_generation || 0) || '—'}</td><td><div class="actions"><button class="action" data-recovery-action="doh" data-id="${item.id}">DoH 回读</button><button class="action" data-recovery-action="edit-bootstrap" data-id="${item.id}">编辑</button><button class="action danger" data-recovery-action="delete-bootstrap" data-id="${item.id}">删除</button></div></td></tr>`).join('') || '<tr><td colspan="8" class="recovery-empty">尚未配置 Bootstrap DNS；已发布清单仍可在主站正常时同步到老用户浏览器。</td></tr>';
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
  function domainById(id) { return state?.domains.find(item => Number(item.id) === Number(id)); }
  function bootstrapById(id) { return state?.bootstraps.find(item => Number(item.id) === Number(id)); }
  function channelById(id) { return state?.dnsChannels?.find(item => Number(item.id) === Number(id)); }
  function providerById(id) { return state?.dnsProviders?.find(item => item.id === id); }
  function releaseById(id) { return state?.releases.find(item => Number(item.id) === Number(id)); }

  function renderChannelCredentials(providerId, channel = null) {
    const container = document.querySelector('#recovery-channel-credentials');
    const secretPlaceholder = channel ? '留空表示保持原值' : '请输入凭据';
    const templates = {
      cloudflare: `<label class="recovery-switch"><input name="reuseCentral" type="checkbox" value="1" ${channel?.reuse_central ? 'checked' : ''}><span><strong>复用中央 Cloudflare 凭据</strong><small class="hint">使用“Cloudflare 管理”中已保存的 Account ID 与 Token。</small></span></label><label>Account ID<input name="accountId" autocomplete="off" placeholder="${secretPlaceholder}"></label><label>API Token<input name="apiToken" type="password" autocomplete="new-password" placeholder="${secretPlaceholder}"></label>`,
      desec: `<label class="full">API Token<input name="apiToken" type="password" autocomplete="new-password" placeholder="${secretPlaceholder}"></label>`,
      cloudns: `<label>认证类型<select name="authType"><option value="auth-id">主账号 Auth ID</option><option value="sub-auth-id">子账号 Sub Auth ID</option><option value="sub-auth-user">子账号用户名</option></select></label><label>账号标识<input name="authId" autocomplete="off" placeholder="${secretPlaceholder}"></label><label class="full">Auth Password<input name="authPassword" type="password" autocomplete="new-password" placeholder="${secretPlaceholder}"></label>`,
      route53: `<label>Access Key ID<input name="accessKeyId" autocomplete="off" placeholder="${secretPlaceholder}"></label><label>Secret Access Key<input name="secretAccessKey" type="password" autocomplete="new-password" placeholder="${secretPlaceholder}"></label><label class="full">Session Token（可选）<input name="sessionToken" type="password" autocomplete="new-password" placeholder="临时凭据使用；留空保持原值"></label>`
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
      if (action === 'open-domain') { const form = document.querySelector('#recovery-domain-form'); form.reset(); form.elements.id.value = ''; form.elements.status.checked = true; return openModal('#recovery-domain-modal'); }
      if (action === 'edit-domain') { const item = domainById(id); if (!item) return; const form = document.querySelector('#recovery-domain-form'); form.elements.id.value = item.id; form.elements.title.value = item.title; form.elements.url.value = item.url; form.elements.priority.value = item.priority; form.elements.status.checked = Number(item.status) === 1; return openModal('#recovery-domain-modal'); }
      if (action === 'open-channel') { const form = document.querySelector('#recovery-channel-form'); form.reset(); form.elements.id.value = ''; form.elements.providerId.disabled = false; form.elements.status.checked = true; renderChannelCredentials(form.elements.providerId.value); return openModal('#recovery-channel-modal'); }
      if (action === 'edit-channel') { const item = channelById(id); if (!item) return; const form = document.querySelector('#recovery-channel-form'); form.reset(); form.elements.id.value = item.id; form.elements.label.value = item.label; form.elements.providerId.value = item.provider_id; form.elements.providerId.disabled = item.legacy === true; form.elements.status.checked = Number(item.status) === 1; renderChannelCredentials(item.provider_id, item); return openModal('#recovery-channel-modal'); }
      if (action === 'test-channel') { const result = await busy(button, '验证中…', () => request(`/api/admin/recovery/dns-channels/${id}/test`, { method: 'POST', body: '{}' })); notify(`API 通道验证成功，可访问 ${result.zoneCount} 个 Zone`); return load(); }
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
    if (result.manualRecords?.length) {
      document.querySelector('#recovery-doh-results').innerHTML = result.manualRecords.map(record => `<div class="recovery-result"><strong>${escapeHtml(record.providerId)} · ${escapeHtml(record.recordName)} · ${escapeHtml(record.role)} 分片</strong><p>请逐条建立同名 TXT（每条不超过 ${Number(record.byteLimit)} 字节）：</p>${record.values.map(value => `<code class="recovery-manual-value">${escapeHtml(value)}</code>`).join('')}</div>`).join('');
    }
    notify(result.warning || `恢复清单已发布到 ${result.dnsPublished} 个 DNS 记录`);
    return load();
  }

  function bindPanel(panel) {
    panel.addEventListener('click', handleAction);
    panel.querySelectorAll('[data-close-recovery-modal]').forEach(button => button.addEventListener('click', closeModals));
    panel.querySelectorAll('.recovery-modal').forEach(modal => modal.addEventListener('click', event => { if (event.target === modal) closeModals(); }));
    panel.querySelector('#recovery-profile-select').addEventListener('change', event => { currentProfileId = Number(event.currentTarget.value) || 1; void load(); });
    const bootstrapForm = panel.querySelector('#recovery-bootstrap-form');
    bootstrapForm.elements.providerId.addEventListener('change', () => syncBootstrapPublisher('', 'automatic'));
    bootstrapForm.elements.publishMode.addEventListener('change', () => syncBootstrapPublisher(bootstrapForm.elements.dnsChannelId.value, bootstrapForm.elements.publishMode.value));
    const channelForm = panel.querySelector('#recovery-channel-form');
    channelForm.elements.providerId.addEventListener('change', event => renderChannelCredentials(event.currentTarget.value));
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
      try { await busy(submit, '保存中…', () => request(id ? `/api/admin/recovery/domains/${id}` : '/api/admin/recovery/domains', { method: id ? 'PUT' : 'POST', body: JSON.stringify(payload) })); closeModals(); notify('恢复线路已保存'); await load(); } catch (error) { notify(error.message); }
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
