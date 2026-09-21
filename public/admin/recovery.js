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
          <div class="box"><div class="box-head"><div><h2>Bootstrap DNS</h2><p class="hint">主、备用 TXT 均保存同一份签名 JSON 分片；发布时先备用、后主记录。</p></div><button class="button" type="button" data-recovery-action="open-bootstrap">新增 DNS</button></div>
            <div class="table-wrap"><table class="recovery-table"><thead><tr><th>名称</th><th>TXT 记录</th><th>Zone</th><th>角色</th><th>发布状态</th><th>当前代</th><th>操作</th></tr></thead><tbody id="recovery-bootstrap-body"></tbody></table></div>
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
          <div class="box"><div class="box-head"><div><h2>Cloudflare DNS 凭据</h2><p class="hint">只用于写入 Bootstrap TXT；Token 保存后不回显。</p></div></div>
            <form id="recovery-cloudflare-form" class="recovery-form">
              <label class="recovery-switch"><input name="reuseCentral" type="checkbox" value="1"><span><strong>复用中央 Cloudflare 凭据</strong><small class="hint">Token 需要 Zone DNS 编辑权限。</small></span></label>
              <label class="full">Account ID<input name="accountId" autocomplete="off"></label>
              <label class="full">API Token<input name="apiToken" type="password" autocomplete="new-password" placeholder="留空表示不修改"></label>
              <div class="recovery-form-actions"><button class="button" type="submit">保存 DNS 凭据</button></div>
            </form>
          </div>
          <div class="box"><div class="box-head"><div><h2>安全边界</h2></div></div><div class="recovery-note">主域名正常时不测活、不查询备用线路、不访问 DoH。只有真实导航或核心接口失败后，才检查主域动态图片并进入恢复流程；找到地址后也只展示“立即前往”，不会自动跳转。</div></div>
          <div class="box"><div class="box-head"><div><h2>操作审计</h2><p class="hint">保留最近 100 条配置、检测、密钥和发布记录。</p></div></div><div id="recovery-audit" class="recovery-audit"></div></div>
        </div>
      </div>
      <div id="recovery-domain-modal" class="modal recovery-modal" role="dialog" aria-modal="true" aria-labelledby="recovery-domain-title"><form id="recovery-domain-form" class="dialog"><h3 id="recovery-domain-title">恢复线路</h3><input name="id" type="hidden"><div class="form-grid"><label>线路名称<input name="title" maxlength="80" required></label><label>优先级<input name="priority" type="number" value="0" required></label><label class="full">HTTPS 地址<input name="url" type="url" placeholder="https://recovery.example" required></label><label class="full exemption-option"><input name="status" type="checkbox" value="1" checked><span>启用该线路</span></label></div><div class="dialog-foot"><button class="button ghost" type="button" data-close-recovery-modal>取消</button><button class="button" type="submit">保存线路</button></div></form></div>
      <div id="recovery-bootstrap-modal" class="modal recovery-modal" role="dialog" aria-modal="true" aria-labelledby="recovery-bootstrap-title"><form id="recovery-bootstrap-form" class="dialog"><h3 id="recovery-bootstrap-title">Bootstrap DNS</h3><input name="id" type="hidden"><div class="form-grid"><label>显示名称<input name="label" maxlength="80" required></label><label>排序<input name="sortOrder" type="number" value="0" required></label><label class="full">TXT 记录名<input name="recordName" placeholder="_recovery.bootstrap.example" required></label><label class="full">Cloudflare Zone<input name="zoneName" placeholder="bootstrap.example" required></label><label class="exemption-option"><input name="isPrimary" type="checkbox" value="1"><span>主 Bootstrap</span></label><label class="exemption-option"><input name="status" type="checkbox" value="1" checked><span>启用</span></label></div><div class="dialog-foot"><button class="button ghost" type="button" data-close-recovery-modal>取消</button><button class="button" type="submit">保存 DNS</button></div></form></div>
    `;
    document.querySelector('.shell')?.append(panel);
    bindPanel(panel);
  }

  function statusTag(value, labels = {}) {
    const map = { published: ['已发布', ''], draft: ['草稿', 'warn'], failed: ['失败', 'off'], superseded: ['已替代', 'neutral'], verified: ['已验证', ''], unpublished: ['未发布', 'neutral'], healthy: ['正常', ''], untested: ['未检测', 'neutral'] };
    const [text, tone] = map[value] || [labels[value] || value || '未知', 'off'];
    return `<span class="tag ${tone}">${escapeHtml(text)}</span>`;
  }

  function renderOverview() {
    if (!state) return;
    const { settings, domains, bootstraps, releases, keys, cloudflare, audit, profiles = [], resolvers = [], lookupRoutes = [] } = state;
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
    const credentialForm = document.querySelector('#recovery-cloudflare-form');
    credentialForm.elements.reuseCentral.checked = cloudflare.reuseCentral === true;
    credentialForm.elements.accountId.value = cloudflare.accountId || '';
    credentialForm.elements.apiToken.value = '';
    credentialForm.elements.accountId.disabled = cloudflare.reuseCentral === true;
    credentialForm.elements.apiToken.disabled = cloudflare.reuseCentral === true;

    document.querySelector('#recovery-domain-body').innerHTML = domains.map(item => `<tr><td><strong>${escapeHtml(item.title)}</strong></td><td class="recovery-url">${escapeHtml(item.url)}</td><td>${Number(item.priority)}</td><td>${Number(item.status) === 1 ? '<span class="tag">启用</span>' : '<span class="tag neutral">停用</span>'}</td><td>${statusTag(item.last_probe_status)}${item.last_probe_ms ? ` <span class="hint">${item.last_probe_ms}ms</span>` : ''}${item.last_probe_error ? `<span class="domain">${escapeHtml(item.last_probe_error)}</span>` : ''}</td><td>${formatTime(item.last_probe_at)}</td><td><div class="actions"><button class="action" data-recovery-action="probe-domain" data-id="${item.id}">检测</button><button class="action" data-recovery-action="edit-domain" data-id="${item.id}">编辑</button><button class="action danger" data-recovery-action="delete-domain" data-id="${item.id}">删除</button></div></td></tr>`).join('') || '<tr><td colspan="7" class="recovery-empty">尚未添加恢复专用线路</td></tr>';
    document.querySelector('#recovery-bootstrap-body').innerHTML = bootstraps.map(item => `<tr><td><strong>${escapeHtml(item.label)}</strong></td><td class="recovery-code">${escapeHtml(item.record_name)}</td><td>${escapeHtml(item.zone_name)}</td><td>${Number(item.is_primary) === 1 ? '<span class="tag warn">主记录</span>' : '<span class="tag neutral">备用记录</span>'}</td><td>${statusTag(item.last_publish_status)}${item.last_publish_error ? `<span class="domain">${escapeHtml(item.last_publish_error)}</span>` : ''}</td><td>${Number(item.last_published_generation || 0) || '—'}</td><td><div class="actions"><button class="action" data-recovery-action="doh" data-id="${item.id}">DoH 回读</button><button class="action" data-recovery-action="edit-bootstrap" data-id="${item.id}">编辑</button><button class="action danger" data-recovery-action="delete-bootstrap" data-id="${item.id}">删除</button></div></td></tr>`).join('') || '<tr><td colspan="7" class="recovery-empty">尚未配置 Bootstrap DNS；已发布清单仍可在主站正常时同步到老用户浏览器。</td></tr>';
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
  function releaseById(id) { return state?.releases.find(item => Number(item.id) === Number(id)); }

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
      if (action === 'open-bootstrap') { const form = document.querySelector('#recovery-bootstrap-form'); form.reset(); form.elements.id.value = ''; form.elements.status.checked = true; return openModal('#recovery-bootstrap-modal'); }
      if (action === 'edit-bootstrap') { const item = bootstrapById(id); if (!item) return; const form = document.querySelector('#recovery-bootstrap-form'); form.elements.id.value = item.id; form.elements.label.value = item.label; form.elements.recordName.value = item.record_name; form.elements.zoneName.value = item.zone_name; form.elements.sortOrder.value = item.sort_order; form.elements.isPrimary.checked = Number(item.is_primary) === 1; form.elements.status.checked = Number(item.status) === 1; return openModal('#recovery-bootstrap-modal'); }
      if (action === 'delete-domain' && confirm('确定删除这条恢复专用线路吗？已发布的历史版本不会被修改。')) { await request(`/api/admin/recovery/domains/${id}`, { method: 'DELETE' }); notify('恢复线路已删除'); return load(); }
      if (action === 'delete-bootstrap' && confirm('确定删除这个 Bootstrap DNS 配置吗？Cloudflare 中已发布的 TXT 不会自动删除。')) { await request(`/api/admin/recovery/bootstrap/${id}`, { method: 'DELETE' }); notify('Bootstrap DNS 已删除'); return load(); }
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
    notify(result.warning || `恢复清单已发布到 ${result.dnsPublished} 个 DNS 记录`);
    return load();
  }

  function bindPanel(panel) {
    panel.addEventListener('click', handleAction);
    panel.querySelectorAll('[data-close-recovery-modal]').forEach(button => button.addEventListener('click', closeModals));
    panel.querySelectorAll('.recovery-modal').forEach(modal => modal.addEventListener('click', event => { if (event.target === modal) closeModals(); }));
    panel.querySelector('#recovery-profile-select').addEventListener('change', event => { currentProfileId = Number(event.currentTarget.value) || 1; void load(); });
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
    panel.querySelector('#recovery-cloudflare-form').elements.reuseCentral.addEventListener('change', event => {
      const form = event.currentTarget.form; form.elements.accountId.disabled = event.currentTarget.checked; form.elements.apiToken.disabled = event.currentTarget.checked;
    });
    panel.querySelector('#recovery-cloudflare-form').addEventListener('submit', async event => {
      event.preventDefault(); const form = event.currentTarget, submit = form.querySelector('button[type="submit"]');
      const payload = Object.fromEntries(new FormData(form)); payload.reuseCentral = form.elements.reuseCentral.checked;
      try { await busy(submit, '保存中…', () => request('/api/admin/recovery/cloudflare', { method: 'PUT', body: JSON.stringify(payload) })); notify('DNS 凭据已保存'); await load(); } catch (error) { notify(error.message); }
    });
    panel.querySelector('#recovery-domain-form').addEventListener('submit', async event => {
      event.preventDefault(); const form = event.currentTarget, id = form.elements.id.value, submit = form.querySelector('button[type="submit"]');
      const payload = Object.fromEntries(new FormData(form)); payload.status = form.elements.status.checked ? 1 : 0;
      try { await busy(submit, '保存中…', () => request(id ? `/api/admin/recovery/domains/${id}` : '/api/admin/recovery/domains', { method: id ? 'PUT' : 'POST', body: JSON.stringify(payload) })); closeModals(); notify('恢复线路已保存'); await load(); } catch (error) { notify(error.message); }
    });
    panel.querySelector('#recovery-bootstrap-form').addEventListener('submit', async event => {
      event.preventDefault(); const form = event.currentTarget, id = form.elements.id.value, submit = form.querySelector('button[type="submit"]');
      const payload = Object.fromEntries(new FormData(form)); payload.isPrimary = form.elements.isPrimary.checked ? 1 : 0; payload.status = form.elements.status.checked ? 1 : 0;
      try { await busy(submit, '保存中…', () => request(id ? `/api/admin/recovery/bootstrap/${id}` : '/api/admin/recovery/bootstrap', { method: id ? 'PUT' : 'POST', body: JSON.stringify(payload) })); closeModals(); notify('Bootstrap DNS 已保存'); await load(); } catch (error) { notify(error.message); }
    });
  }

  installPanel();
  window.loadRecoveryAdmin = load;
})();
