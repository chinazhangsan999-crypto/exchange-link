/** 外部系统接入、告警通道与数据库备份集中管理。 */
(() => {
  const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
  const notify = message => window.toast ? window.toast(message) : console.info(message);

  async function request(url, options = {}) {
    const response = await fetch(url, {
      ...options,
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) }
    });
    const result = await response.json();
    if (result.code !== 200) throw new Error(result.msg || '请求失败');
    return result.data;
  }

  function installOperationsPanel() {
    if (document.querySelector('#operations-tab')) return;
    const tabs = document.querySelector('.tabs');
    const settingsTab = document.querySelector('#settings-tab');
    const settingsPanel = document.querySelector('#settings');
    if (!tabs || !settingsPanel) return;
    const tab = document.createElement('button');
    tab.id = 'operations-tab'; tab.type = 'button'; tab.dataset.tab = 'operations'; tab.textContent = '接入与运维';
    tabs.insertBefore(tab, settingsTab || null);
    const panel = document.createElement('section');
    panel.id = 'operations'; panel.className = 'panel operations-panel';
    panel.innerHTML = `
      <div class="box operations-overview">
        <div class="box-head"><div><h2>接入与运维</h2><p class="hint">集中管理总后台、IP 情报、风险中心、告警通知和数据库异地备份。站点资料、风控参数、第三方统计与友链 CSV 仍保留在“系统设置”。</p></div><button id="refresh-operations" class="button ghost" type="button">刷新全部状态</button></div>
      </div>
      <section id="operations-integrations-slot" class="integration-settings"></section>
      <div class="box integration-box" id="alert-channel-management">
        <div class="box-head"><div><h2>导航站告警 Webhook 管理</h2><p class="hint">主 Webhook 负责业务和运维告警，Bark 仅在主通道发送失败时接管；与数据库备份 Bot 完全独立。</p></div></div>
        <form id="alert-settings-form" class="settings-form alert-settings-form"></form>
      </div>
      <div class="box backup-settings-box">
        <div class="box-head"><div><h2>数据库备份与异地保存</h2><p class="hint">使用独立 Backup Bot 发送加密数据库。超过 18 MiB 自动连续分片，不限制分片总数。</p></div><button id="refresh-backup-status" class="button ghost" type="button">刷新备份状态</button></div>
        <div id="backup-status" class="backup-status-grid" aria-live="polite"><p class="hint">正在读取备份状态…</p></div>
        <form id="backup-settings-form" class="settings-form backup-settings-form">
          <label class="switch-setting"><span>启用 Telegram 数据库备份</span><input name="enabled" type="checkbox" value="1"><small>启用后，每日备份完成会由独立 Bot 上传。</small></label>
          <label>独立 Backup Bot Token<input name="botToken" type="password" autocomplete="new-password" placeholder="留空表示不修改已保存 Token"><small id="backup-token-state">Token 仅保存在服务器凭据文件中，不会回显。</small></label>
          <label>Telegram Chat ID<input name="chatId" required placeholder="例如：-1001234567890"></label>
          <label>单个分片大小（MiB）<input name="partSizeMiB" type="number" min="1" max="18" value="18" required><small>最大 18 MiB；超出后继续生成后续分片，不限制分片总数。</small></label>
          <div class="backup-warning">⚠ 解密密钥会按你的要求写入每批备份的 Telegram 完成摘要。能够访问该会话的人即可解密备份。</div>
          <div class="settings-actions"><button class="button" type="submit">保存备份设置</button><button id="test-backup-bot" class="button ghost" type="button">测试备份 Bot</button><button id="run-backup-now" class="button ghost" type="button">立即备份并推送</button><button id="retry-backup" class="button ghost" type="button">重试失败分片</button></div>
        </form>
      </div>`;
    settingsPanel.parentNode.insertBefore(panel, settingsPanel);
    const settingsHint = settingsPanel.querySelector('.settings-box .box-head .hint');
    if (settingsHint) settingsHint.textContent = '配置站点资料、发布页信息、每日引导、自动审核与站点风控参数。';
    moveAlertSettings();
    panel.querySelector('#refresh-operations').addEventListener('click', loadOperations);
    panel.querySelector('#refresh-backup-status').addEventListener('click', loadBackup);
    panel.querySelector('#backup-settings-form').addEventListener('submit', saveBackup);
    panel.querySelector('#alert-settings-form').addEventListener('submit', saveAlerts);
    panel.querySelector('#test-backup-bot').addEventListener('click', event => runButton(event.currentTarget, '测试中…', '/api/admin/backups/test', '备份 Bot 测试成功'));
    panel.querySelector('#run-backup-now').addEventListener('click', event => runButton(event.currentTarget, '备份并上传中…', '/api/admin/backups/run', '备份已生成并上传'));
    panel.querySelector('#retry-backup').addEventListener('click', event => runButton(event.currentTarget, '重试中…', '/api/admin/backups/retry', '失败分片重试完成'));
    const style = document.createElement('link'); style.rel = 'stylesheet'; style.href = '/admin/backup.css?v=20260922-alert-layout-1'; document.head.append(style);
  }

  function moveAlertSettings() {
    const source = document.querySelector('#settings-form');
    const target = document.querySelector('#alert-settings-form');
    if (!source || !target) return;
    const webhookInput = source.elements.webhook_url;
    const webhookLabel = webhookInput?.closest('label');
    const bark = source.querySelector('#bark-fallback-settings');
    const health = source.querySelector('#webhook-health-card');
    const testWebhook = source.querySelector('#test-webhook');
    const testBark = source.querySelector('#test-bark');
    if (webhookLabel) {
      const primarySection = document.createElement('section');
      primarySection.className = 'alert-section alert-primary-section';
      primarySection.append(webhookLabel);
      target.append(primarySection);
    }
    if (bark) {
      const barkSection = document.createElement('section');
      barkSection.id = 'bark-fallback-settings';
      barkSection.className = 'alert-section alert-bark-section';
      const head = document.createElement('div'); head.className = 'alert-section-head';
      const title = document.createElement('strong'); title.textContent = bark.querySelector('legend')?.textContent || 'Bark 备用告警';
      const toggle = bark.querySelector('.switch-setting');
      head.append(title);
      if (toggle) head.append(toggle);
      barkSection.append(head);
      const fields = document.createElement('div'); fields.className = 'alert-bark-fields';
      [...bark.querySelectorAll(':scope > label')].forEach(label => fields.append(label));
      barkSection.append(fields);
      bark.remove();
      target.append(barkSection);
    }
    if (health) {
      health.classList.add('alert-health-section');
      target.append(health);
    }
    const actions = document.createElement('div'); actions.className = 'settings-actions alert-settings-actions';
    const save = document.createElement('button'); save.className = 'button'; save.type = 'submit'; save.textContent = '保存告警设置';
    actions.append(save);
    if (testWebhook) actions.append(testWebhook);
    if (testBark) actions.append(testBark);
    target.append(actions);
  }

  async function loadAlerts() {
    const form = document.querySelector('#alert-settings-form');
    if (!form) return;
    const data = await request('/api/admin/settings');
    ['webhook_url', 'bark_server_url', 'bark_group'].forEach(key => { if (form.elements[key]) form.elements[key].value = data[key] || ''; });
    if (form.elements.bark_enabled) form.elements.bark_enabled.checked = String(data.bark_enabled) === '1';
    if (form.elements.bark_device_key) form.elements.bark_device_key.value = '';
    const keyState = document.querySelector('#bark-key-state');
    if (keyState) keyState.textContent = data.bark_device_key_configured ? '已保存 Device Key；留空表示不修改。' : '尚未保存 Device Key。';
    document.querySelector('#refresh-webhook-health')?.click();
  }

  async function saveAlerts(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button[type="submit"]');
    const payload = Object.fromEntries(new FormData(form));
    payload.bark_enabled = form.elements.bark_enabled?.checked ? '1' : '0';
    if (!String(payload.bark_device_key || '').trim()) delete payload.bark_device_key;
    try {
      button.disabled = true; button.textContent = '保存中…';
      await request('/api/admin/settings', { method: 'POST', body: JSON.stringify(payload) });
      if (form.elements.bark_device_key) form.elements.bark_device_key.value = '';
      notify('告警设置已保存'); await loadAlerts();
    } catch (error) { notify(error.message); }
    finally { button.disabled = false; button.textContent = '保存告警设置'; }
  }

  function renderBackupStatus(data) {
    const area = document.querySelector('#backup-status');
    const config = data?.config || {};
    const latest = data?.latest;
    area.innerHTML = `
      <div><span>备份 Bot</span><strong>${config.botTokenConfigured ? '已配置' : '未配置'}</strong></div>
      <div><span>自动备份</span><strong>${config.enabled ? '已启用' : '未启用'}</strong></div>
      <div><span>最近状态</span><strong>${escapeHtml(latest?.status || '尚无记录')}</strong></div>
      <div><span>最近备份</span><strong>${escapeHtml(latest?.backupId || '—')}</strong></div>
      <div><span>完整性</span><strong>${escapeHtml(latest?.integrity || '—')}</strong></div>
      <div><span>分片</span><strong>${latest?.parts ? `${Number(latest.uploadedParts?.length || 0)}/${latest.parts.length}` : '—'}</strong></div>
      ${latest?.lastError ? `<p class="backup-error">最近错误：${escapeHtml(latest.lastError)}</p>` : ''}`;
    const form = document.querySelector('#backup-settings-form');
    form.elements.enabled.checked = Boolean(config.enabled);
    form.elements.chatId.value = config.chatId || '';
    form.elements.partSizeMiB.value = Number(config.partSizeMiB || 18);
    document.querySelector('#backup-token-state').textContent = config.botTokenConfigured ? 'Token 已保存；留空表示不修改。' : '尚未保存独立备份 Bot Token。';
  }

  async function loadBackup() {
    try { renderBackupStatus(await request('/api/admin/backups/status')); }
    catch (error) { const area = document.querySelector('#backup-status'); if (area) area.innerHTML = `<p class="backup-error">读取失败：${escapeHtml(error.message)}</p>`; }
  }

  async function saveBackup(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button[type="submit"]');
    const payload = Object.fromEntries(new FormData(form));
    payload.enabled = form.elements.enabled.checked;
    try {
      button.disabled = true; button.textContent = '保存中…';
      await request('/api/admin/backups/settings', { method: 'PUT', body: JSON.stringify(payload) });
      form.elements.botToken.value = '';
      notify('备份设置已保存'); await loadBackup();
    } catch (error) { notify(error.message); }
    finally { button.disabled = false; button.textContent = '保存备份设置'; }
  }

  async function runButton(button, busyText, url, successText) {
    const original = button.textContent;
    try { button.disabled = true; button.textContent = busyText; await request(url, { method: 'POST' }); notify(successText); await loadBackup(); }
    catch (error) { notify(error.message); await loadBackup(); }
    finally { button.disabled = false; button.textContent = original; }
  }

  async function loadOperations() {
    await Promise.allSettled([loadAlerts(), loadBackup(), window.loadOperationsIntegrations?.()]);
  }

  installOperationsPanel();
  window.loadOperationsAdmin = loadOperations;
})();
