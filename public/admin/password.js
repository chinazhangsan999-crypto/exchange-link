/** 接入与运维中的总后台、IP 情报与风险中心组件。敏感凭据只提交，不回显。 */
(() => {
  const notify = message => typeof window.toast === 'function' ? window.toast(message) : window.alert(message);

  function setBusy(button, busy, label) {
    if (!button) return;
    if (!button.dataset.label) button.dataset.label = button.textContent;
    button.disabled = busy;
    button.textContent = busy ? label : button.dataset.label;
  }

  function installIntegrationForms() {
    const integrationSlot = document.querySelector('#operations-integrations-slot');
    if (!integrationSlot || document.querySelector('#control-center-integration')) return;
    const holder = document.createElement('section');
    holder.id = 'control-center-integration';
    holder.className = 'operations-integration-list';
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
      </div>
      <div class="box integration-box" id="bot-risk-center-integration">
        <div class="box-head"><div><h2>接入风险中心</h2><p class="hint">集中上报疑似机器人行为并同步人工决策。观察模式只采集不拦截；执行模式会对风险中心下发的限制立即生效。</p></div><span id="bot-risk-center-state" class="tag">读取中</span></div>
        <form id="bot-risk-center-form" class="settings-form integration-form">
          <label class="switch-setting wide"><span>启用风险中心接入</span><input name="enabled" type="checkbox" value="1"><small>关闭后停止上报和决策同步，不删除风险中心已有记录。</small></label>
          <label>连接方式<select name="connectionType" required><option value="internal">内网直连</option><option value="https">HTTPS 外网连接</option></select><small>同一服务器或私网优先使用内网；跨服务器使用 HTTPS。</small></label>
          <label>运行模式<select name="mode" required><option value="observe">观察模式（只记录）</option><option value="enforce">执行模式（应用限制）</option></select><small>建议先观察确认数据正常，再切换到执行模式。</small></label>
          <label class="wide">风险中心地址<input name="baseUrl" type="url" required placeholder="https://fengxian.example.com"><small>填写纯 Origin，不要带 /admin 或其他路径。</small></label>
          <label>站点标识<input name="siteKey" required maxlength="64" pattern="[A-Za-z0-9_-]{3,64}" autocomplete="off" placeholder="webring-main"></label>
          <label>Client ID<input name="clientId" required maxlength="64" pattern="[A-Za-z0-9_-]{3,64}" autocomplete="off" placeholder="风险中心分配的 Client ID"></label>
          <label class="wide">Client Secret<input name="secret" type="password" autocomplete="new-password" placeholder="已配置时留空表示继续使用原密钥"><small id="bot-risk-secret-state">密钥仅保存于服务器受限文件，不会回显。</small><small id="bot-risk-maintenance-state">运行清单与更新建议尚未同步。</small></label>
          <div class="settings-actions"><button class="button ghost" type="button" data-action="test-bot-risk">测试连接</button><button class="button" type="submit">验证并保存</button></div>
        </form>
      </div>`;
    integrationSlot.append(holder);
    holder.querySelector('#control-center-form').addEventListener('submit', enrollControlCenter);
    holder.querySelector('[data-action="test-control"]').addEventListener('click', testControlCenter);
    holder.querySelector('#ip-intelligence-form').addEventListener('submit', saveIpIntelligence);
    holder.querySelector('[data-action="test-ip"]').addEventListener('click', testIpIntelligence);
    holder.querySelector('#bot-risk-center-form').addEventListener('submit', saveBotRisk);
    holder.querySelector('[data-action="test-bot-risk"]').addEventListener('click', testBotRisk);
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

    try {
      const risk = await api('/api/admin/integrations/bot-risk-center');
      const form = document.querySelector('#bot-risk-center-form');
      if (form) {
        form.elements.enabled.checked = risk.enabled === true;
        form.elements.connectionType.value = risk.connectionType || 'https';
        form.elements.mode.value = risk.mode === 'enforce' ? 'enforce' : 'observe';
        form.elements.baseUrl.value = risk.baseUrl || '';
        form.elements.siteKey.value = risk.siteKey || '';
        form.elements.clientId.value = risk.clientId || '';
      }
      const state = document.querySelector('#bot-risk-center-state');
      if (state) {
        const modeLabel = risk.mode === 'enforce' ? '执行' : '观察';
        state.textContent = risk.enabled ? `已连接 · ${modeLabel}` : '未启用';
        state.classList.toggle('off', !risk.enabled || risk.integrationDisabled === true);
      }
      const secretState = document.querySelector('#bot-risk-secret-state');
      if (secretState) secretState.textContent = risk.secretConfigured ? '已保存密钥；留空表示不修改。' : '尚未保存密钥。';
      const maintenanceState = document.querySelector('#bot-risk-maintenance-state');
      if (maintenanceState) maintenanceState.textContent = risk.lastInventoryAt
        ? `运行清单已上报；更新建议 ${Number(risk.advisoryCount) || 0} 条。`
        : (risk.enabled ? '等待首次运行清单上报。' : '启用后将低频上报版本清单，不影响访客请求。');
    } catch (error) { notify(error.message); }
  }

  function payload(form) { return Object.fromEntries(new FormData(form)); }
  function ipPayload(form) { return { ...payload(form), enabled: form.elements.enabled.checked ? '1' : '0' }; }
  function botRiskPayload(form) { return { ...payload(form), enabled: form.elements.enabled.checked ? '1' : '0' }; }

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

  async function testBotRisk(event) {
    const button = event.currentTarget;
    try { setBusy(button, true, '验证中…'); await api('/api/admin/integrations/bot-risk-center/test', { method: 'POST', body: JSON.stringify(botRiskPayload(button.form)) }); notify('风险中心连接与接入凭据验证成功'); }
    catch (error) { notify(error.message); }
    finally { setBusy(button, false); }
  }

  async function saveBotRisk(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button[type="submit"]');
    try {
      setBusy(button, true, '保存中…');
      await api('/api/admin/integrations/bot-risk-center', { method: 'PUT', body: JSON.stringify(botRiskPayload(form)) });
      form.elements.secret.value = '';
      notify(form.elements.enabled.checked ? '风险中心接入已保存并即时生效' : '风险中心接入已停用');
      await loadIntegrationStatus();
    } catch (error) { notify(error.message); }
    finally { setBusy(button, false); }
  }

  installIntegrationForms();
  window.loadOperationsIntegrations = loadIntegrationStatus;
})();
