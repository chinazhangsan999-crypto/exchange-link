/** 系统设置中的总后台与 IP 情报接入组件。敏感凭据只提交，不回显。 */
(() => {
  const notify = message => typeof window.toast === 'function' ? window.toast(message) : window.alert(message);

  function setBusy(button, busy, label) {
    if (!button) return;
    if (!button.dataset.label) button.dataset.label = button.textContent;
    button.disabled = busy;
    button.textContent = busy ? label : button.dataset.label;
  }

  function installIntegrationForms() {
    const settingsPanel = document.querySelector('#settings');
    if (!settingsPanel || document.querySelector('#control-center-integration')) return;
    const holder = document.createElement('section');
    holder.id = 'control-center-integration';
    holder.className = 'integration-settings';
    holder.innerHTML = `
      <div class="box integration-box">
        <div class="box-head"><div><h2>接入总后台</h2><p class="hint">从总后台复制站点接入地址和凭据。验证并接管成功后，本地账号密码登录将永久关闭，只能从总后台统一进入。</p></div><span id="control-center-state" class="tag">读取中</span></div>
        <form id="control-center-form" class="settings-form integration-form">
          <label>总后台地址<input name="url" type="url" required placeholder="https://zonghoutai.example.com"><small>填写总后台提供的 HTTPS 地址。</small></label>
          <label>站点接入凭据<input name="credential" type="password" required autocomplete="new-password" placeholder="从总后台复制完整凭据"><small>凭据仅写入服务器安全文件，不存入 SQLite，也不会回显。</small></label>
          <div class="settings-actions"><button class="button ghost" type="button" data-action="test-control">测试连接</button><button class="button" type="submit">验证并交由总后台接管</button></div>
        </form>
      </div>
      <div class="box integration-box" id="ip-intelligence-integration">
        <div class="box-head"><div><h2>接入 IP 情报系统</h2><p class="hint">用于后台展示访客网络画像。查询在后台异步执行，连接异常不会阻塞访客访问或带量计分。</p></div><span id="ip-intelligence-state" class="tag">读取中</span></div>
        <form id="ip-intelligence-form" class="settings-form integration-form">
          <label class="switch-setting"><span>启用 IP 情报接入</span><input name="enabled" type="checkbox" value="1" checked><small>关闭后停止新的后台查询，已有画像数据不会删除。</small></label>
          <label>服务地址<input name="baseUrl" type="url" required placeholder="https://ip.example.com"></label>
          <label>Client ID<input name="clientId" required maxlength="128" autocomplete="off" placeholder="总后台分配的 Client ID"></label>
          <label>Client Secret<input name="secret" type="password" autocomplete="new-password" placeholder="已配置时留空表示继续使用原密钥"><small id="ip-secret-state">密钥不会回显。</small></label>
          <div class="settings-actions"><button class="button ghost" type="button" data-action="test-ip">测试连接</button><button class="button" type="submit">验证并保存</button></div>
        </form>
      </div>`;
    const analyticsCard = settingsPanel.querySelector('#analytics-settings');
    settingsPanel.insertBefore(holder, analyticsCard || null);
    holder.querySelector('#control-center-form').addEventListener('submit', enrollControlCenter);
    holder.querySelector('[data-action="test-control"]').addEventListener('click', testControlCenter);
    holder.querySelector('#ip-intelligence-form').addEventListener('submit', saveIpIntelligence);
    holder.querySelector('[data-action="test-ip"]').addEventListener('click', testIpIntelligence);
  }

  async function loadIntegrationStatus() {
    if (!window.adminSessionActive) return;
    try {
      const control = await api('/api/admin/integrations/control-center');
      const form = document.querySelector('#control-center-form');
      if (form && control.controlCenterUrl) form.elements.url.value = control.controlCenterUrl;
      const state = document.querySelector('#control-center-state');
      if (state) {
        state.textContent = control.enrolled ? (control.connected ? '已接管 · 在线' : '已接管') : '未接管';
        state.classList.toggle('off', !control.enrolled);
      }
      if (control.enrolled && form) {
        form.querySelector('button[type="submit"]').textContent = '验证并更新接入凭据';
        form.elements.credential.required = true;
      }
    } catch (error) { notify(error.message); }

    try {
      const ip = await api('/api/admin/integrations/ip-intelligence');
      const form = document.querySelector('#ip-intelligence-form');
      if (form) {
        form.elements.enabled.checked = ip.enabled === true;
        form.elements.baseUrl.value = ip.baseUrl || '';
        form.elements.clientId.value = ip.clientId || '';
      }
      const state = document.querySelector('#ip-intelligence-state');
      if (state) { state.textContent = ip.enabled ? '已配置' : '未配置'; state.classList.toggle('off', !ip.enabled); }
      const secretState = document.querySelector('#ip-secret-state');
      if (secretState) secretState.textContent = ip.secretConfigured ? '已保存密钥；留空表示不修改。' : '尚未保存密钥。';
    } catch (error) { notify(error.message); }
  }

  function payload(form) { return Object.fromEntries(new FormData(form)); }
  function ipPayload(form) { return { ...payload(form), enabled: form.elements.enabled.checked ? '1' : '0' }; }

  async function testControlCenter(event) {
    const button = event.currentTarget;
    try { setBusy(button, true, '验证中…'); await api('/api/admin/integrations/control-center/test', { method: 'POST', body: JSON.stringify(payload(button.form)) }); notify('总后台连接与站点凭据验证成功'); }
    catch (error) { notify(error.message); }
    finally { setBusy(button, false); }
  }

  async function enrollControlCenter(event) {
    event.preventDefault();
    if (!confirm('接管后将永久关闭本地账号密码登录。确认继续吗？')) return;
    const button = event.currentTarget.querySelector('button[type="submit"]');
    try {
      setBusy(button, true, '正在接管…');
      const result = await api('/api/admin/integrations/control-center/enroll', { method: 'PUT', body: JSON.stringify(payload(event.currentTarget)) });
      window.adminSessionActive = false;
      notify('接管成功，本地登录已关闭');
      setTimeout(() => window.location.assign(result.controlCenterUrl || '/admin'), 900);
    } catch (error) { notify(error.message); setBusy(button, false); }
  }

  async function testIpIntelligence(event) {
    const button = event.currentTarget;
    try { setBusy(button, true, '验证中…'); await api('/api/admin/integrations/ip-intelligence/test', { method: 'POST', body: JSON.stringify(ipPayload(button.form)) }); notify('IP 情报服务连接验证成功'); }
    catch (error) { notify(error.message); }
    finally { setBusy(button, false); }
  }

  async function saveIpIntelligence(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button[type="submit"]');
    try { setBusy(button, true, '保存中…'); await api('/api/admin/integrations/ip-intelligence', { method: 'PUT', body: JSON.stringify(ipPayload(form)) }); form.elements.secret.value = ''; notify('IP 情报接入已保存并即时生效'); await loadIntegrationStatus(); }
    catch (error) { notify(error.message); }
    finally { setBusy(button, false); }
  }

  installIntegrationForms();
  const previousLoader = window.loadAdminSettings;
  window.loadAdminSettings = async function loadAdminSettingsWithIntegrations() {
    await previousLoader?.();
    await loadIntegrationStatus();
  };
})();
