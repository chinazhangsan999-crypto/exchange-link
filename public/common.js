/** 前台共用剪贴板工具：优先现代 Clipboard API，失败时降级为临时输入框复制。 */
(() => {
  function fallbackToast(message) {
    let toast = document.querySelector('#common-copy-toast');
    if (!toast) {
      toast = document.createElement('div');
      toast.id = 'common-copy-toast';
      toast.style.cssText = 'position:fixed;left:50%;bottom:24px;z-index:200000;transform:translate(-50%,14px);opacity:0;transition:.2s;background:#1f2937;color:#fff;border-radius:999px;padding:10px 15px;font:13px "Microsoft YaHei",sans-serif;pointer-events:none;box-shadow:0 6px 20px #0003';
      document.body.appendChild(toast);
    }
    toast.textContent = message;
    toast.style.opacity = '1'; toast.style.transform = 'translate(-50%,0)';
    clearTimeout(fallbackToast.timer);
    fallbackToast.timer = setTimeout(() => { toast.style.opacity = '0'; toast.style.transform = 'translate(-50%,14px)'; }, 1800);
  }

  /** 复制防失联邮箱，并显示统一的轻量成功提示。 */
  window.copyEmailToClipboard = async function copyEmailToClipboard(emailText) {
    const value = String(emailText || '').trim();
    if (!value) return false;
    try { await navigator.clipboard.writeText(value); }
    catch {
      const input = document.createElement('input');
      input.value = value; input.setAttribute('readonly', '');
      input.style.cssText = 'position:fixed;opacity:0;pointer-events:none';
      document.body.appendChild(input); input.select();
      const copied = document.execCommand('copy');
      input.remove();
      if (!copied) return false;
    }
    if (typeof window.showToast === 'function') window.showToast('✓ 邮箱已成功复制到剪贴板！');
    else fallbackToast('✓ 邮箱已成功复制到剪贴板！');
    return true;
  };
})();

// 全站 PV 由每个公开页面在加载完成后主动上报；服务端按匿名访客与 IP 聚合到小时桶。
(() => {
  const pagePath = window.location.pathname || '/';
  if (!/^\/(?:index\.html|site-detail(?:\.html)?)?$/.test(pagePath)) return;
  fetch('/api/track/site-page-view', {
    method: 'POST', credentials: 'same-origin', keepalive: true,
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ pagePath })
  }).catch(() => {});
})();

// 有效入站在首页完成 3 秒心跳后才下发当前标签页的归因凭证；后续公开页面主动上报，避免静态文档请求中的 Cookie 差异造成漏记。
(() => {
  const token = sessionStorage.getItem('inflow_attribution_token');
  const pagePath = window.location.pathname || '/';
  if (!token) return;
  fetch('/api/track/page-view', {
    method: 'POST', credentials: 'same-origin', keepalive: true,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token, pagePath })
  }).then(response => {
    if (response.status === 401) sessionStorage.removeItem('inflow_attribution_token');
  }).catch(() => {});
})();
