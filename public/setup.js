'use strict';

const form = document.querySelector('#setup-form');
const button = document.querySelector('#deploy-button');
const status = document.querySelector('#setup-status');
const resultArea = document.querySelector('#setup-result');
const sameAccount = document.querySelector('#same-account');
const frontendAccountFields = document.querySelector('#frontend-account-fields');

function updateFrontendAccountFields() {
  const useSameAccount = sameAccount.checked;
  frontendAccountFields.hidden = useSameAccount;
  for (const input of frontendAccountFields.querySelectorAll('input')) input.required = !useSameAccount;
}

sameAccount.addEventListener('change', updateFrontendAccountFields);
updateFrontendAccountFields();

function setStatus(message, type = '') {
  status.textContent = message;
  status.className = `status ${type}`.trim();
}

async function readJson(response) {
  const result = await response.json().catch(() => null);
  if (!response.ok || result?.code !== 200) throw new Error(result?.msg || `请求失败（HTTP ${response.status}）`);
  return result.data;
}

fetch('/api/setup/status', { credentials: 'same-origin', cache: 'no-store' })
  .then(readJson)
  .then(() => setStatus('初始化入口可用。请填写 Cloudflare 信息并创建整套站点。'))
  .catch(() => {
    form.hidden = true;
    setStatus('初始化入口不可用或已经完成。', 'error');
  });

form.addEventListener('submit', async event => {
  event.preventDefault();
  if (!confirm('确定创建或更新中央 API、管理后台和第一个公共前台 Worker 吗？')) return;
  const payload = Object.fromEntries(new FormData(form));
  try {
    button.disabled = true;
    button.textContent = '正在创建整套站点…';
    setStatus('正在验证 Cloudflare 权限、创建三个入口并同步前台白名单，请勿关闭页面。');
    resultArea.replaceChildren();
    const response = await fetch('/api/setup/deploy', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await readJson(response);
    form.reset();
    form.hidden = true;
    setStatus(`${data.note || '初始化完成'}。一次性入口已经关闭。`, 'success');
    resultArea.className = 'result-links';
    const links = [
      { href: `https://${data.adminDomain}/admin`, label: '进入正式管理后台' },
      { href: data.frontend.url, label: '打开第一个公共前台' }
    ];
    for (const item of links) {
      const link = document.createElement('a');
      link.className = 'result-link';
      link.href = item.href;
      link.textContent = item.label;
      link.target = '_blank';
      link.rel = 'noopener';
      resultArea.append(link);
    }
  } catch (error) {
    form.elements.apiToken.value = '';
    form.elements.frontendApiToken.value = '';
    setStatus(`${error.message}。请修正后重新输入 Cloudflare API Token。`, 'error');
  } finally {
    button.disabled = false;
    button.textContent = '创建整套站点';
  }
});
