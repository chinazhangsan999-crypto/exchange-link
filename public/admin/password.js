/** 系统设置中的管理员密码修改组件。 */
(() => {
  const notify = message => {
    if (typeof window.toast === 'function') return window.toast(message);
    const toastElement = document.querySelector('#toast');
    if (!toastElement) return window.alert(message);
    toastElement.textContent = message;
    toastElement.classList.add('show');
    window.setTimeout(() => toastElement.classList.remove('show'), 2400);
  };

  function installPasswordForm() {
    const settingsPanel = document.querySelector('#settings');
    if (!settingsPanel || document.querySelector('#admin-password-form')) return;

    const card = document.createElement('div');
    card.className = 'box password-settings-box';
    card.innerHTML = `
      <div class="box-head">
        <div>
          <h2>修改管理员密码</h2>
          <p class="hint">修改成功后当前登录凭证会被清除，需要使用新密码重新登录。</p>
        </div>
      </div>
      <form id="admin-password-form" class="settings-form password-settings-form">
        <label>
          原密码
          <input name="oldPassword" type="password" required autocomplete="current-password" placeholder="请输入当前管理员密码">
        </label>
        <label>
          新密码
          <input name="newPassword" type="password" required minlength="8" maxlength="128" autocomplete="new-password" placeholder="至少 8 位字符">
          <small>建议混合使用大小写字母、数字与符号。</small>
        </label>
        <div class="settings-actions">
          <button class="button" type="submit">保存新密码</button>
        </div>
      </form>
    `;

    const analyticsCard = settingsPanel.querySelector('#analytics-settings');
    settingsPanel.insertBefore(card, analyticsCard || null);
    card.querySelector('#admin-password-form').addEventListener('submit', changePassword);
  }

  async function changePassword(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button[type="submit"]');
    const oldPassword = form.elements.oldPassword.value;
    const newPassword = form.elements.newPassword.value;
    if (!oldPassword || !newPassword) return notify('请输入原密码和新密码');
    if (newPassword.length < 8) return notify('新密码长度不得少于 8 位');

    try {
      button.disabled = true;
      button.textContent = '保存中…';
      const response = await fetch('/api/admin/password', {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ oldPassword, newPassword })
      });
      const result = await response.json();
      if (!response.ok || result.code !== 200) throw new Error(result.msg || '密码修改失败');

      window.adminSessionActive = false;
      notify(result.msg || '密码修改成功，请重新登录');
      form.reset();
      window.setTimeout(() => window.location.replace('/admin/'), 1000);
    } catch (error) {
      notify(error.message || '密码修改失败，请稍后重试');
      button.disabled = false;
      button.textContent = '保存新密码';
    }
  }

  installPasswordForm();
})();
