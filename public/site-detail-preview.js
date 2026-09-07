/* 独立预览页：使用示例数据展示详情页结构，不读取或修改正式业务数据。 */
(() => {
  const recommendations = [
    ['OpenAI', 'openai.com', 'AI', '#111827', 18], ['Google Scholar', 'scholar.google.com', 'GS', '#4285f4', 16],
    ['MDN Web Docs', 'developer.mozilla.org', 'MDN', '#1f2937', 12], ['arXiv', 'arxiv.org', 'arX', '#b31b1b', 10],
    ['Hugging Face', 'huggingface.co', 'HF', '#e8a317', 9], ['Stack Overflow', 'stackoverflow.com', 'SO', '#f48024', 8],
    ['Bilibili', 'bilibili.com', 'BI', '#fb7299', 7], ['Notion', 'notion.so', 'N', '#111111', 6],
    ['DeepSeek', 'deepseek.com', 'DS', '#5267db', 5], ['知乎', 'zhihu.com', '知', '#1677ff', 4],
    ['少数派', 'sspai.com', 'SS', '#ed6a5e', 3], ['Wikipedia', 'wikipedia.org', 'W', '#59636d', 2]
  ];

  const escapeHtml = (value) => String(value || '').replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));

  function renderRecommendations() {
    const grid = document.getElementById('recommendGrid');
    grid.innerHTML = recommendations.map(([name, domain, initials, color, traffic]) => `
      <a class="recommend-card" href="https://${escapeHtml(domain)}" target="_blank" rel="noopener" title="${escapeHtml(name)} · ${escapeHtml(domain)}">
        <span class="recommend-icon" style="background:${color}">${escapeHtml(initials)}</span>
        <span class="recommend-info"><span class="recommend-name">${escapeHtml(name)}</span><span class="recommend-domain">${escapeHtml(domain)}</span></span>
        <span class="traffic-chip">${traffic} IP</span>
      </a>`).join('');
  }

  function showToast(message) {
    const toast = document.getElementById('previewToast');
    toast.textContent = message;
    toast.classList.add('show');
    window.clearTimeout(showToast.timer);
    showToast.timer = window.setTimeout(() => toast.classList.remove('show'), 1800);
  }

  async function copySiteUrl() {
    const url = document.getElementById('siteUrl').textContent.trim();
    try {
      await navigator.clipboard.writeText(url);
      showToast('站点链接已复制');
    } catch (_) {
      const input = document.createElement('input');
      input.value = url; document.body.appendChild(input); input.select(); document.execCommand('copy'); input.remove();
      showToast('站点链接已复制');
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    renderRecommendations();
    document.getElementById('copySiteBtn').addEventListener('click', copySiteUrl);
    document.querySelectorAll('[data-toast]').forEach((button) => button.addEventListener('click', () => showToast(button.dataset.toast)));
  });
})();
