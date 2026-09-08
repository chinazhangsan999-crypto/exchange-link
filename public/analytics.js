/* 全站第三方统计加载器：配置拉取和外部脚本均异步执行，失败绝不影响页面主流程。 */
(() => {
  const inserted = new Set();

  function validHttpsUrl(value) {
    try {
      const url = new URL(String(value || '').trim());
      return url.protocol === 'https:' ? url.href : '';
    } catch { return ''; }
  }

  function appendScript(id, src, attributes = {}) {
    if (!src || inserted.has(id) || document.getElementById(id)) return;
    const script = document.createElement('script');
    script.id = id;
    script.src = src;
    script.async = true;
    script.defer = true;
    script.referrerPolicy = 'strict-origin-when-cross-origin';
    Object.entries(attributes).forEach(([key, value]) => script.setAttribute(key, value));
    script.onerror = () => console.warn(`[Analytics] ${id} 加载失败，不影响站点正常使用。`);
    inserted.add(id);
    document.head.appendChild(script);
  }

  function safeDataAttributes(value) {
    try {
      const parsed = JSON.parse(String(value || '').trim() || '{}');
      if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') return {};
      return Object.fromEntries(Object.entries(parsed)
        .filter(([key]) => /^data-[a-z0-9][a-z0-9_-]*$/i.test(key))
        .map(([key, item]) => [key, String(item ?? '').slice(0, 500)]));
    } catch { return {}; }
  }

  async function loadAnalytics() {
    try {
      const response = await fetch('/api/analytics/config', { credentials: 'same-origin', cache: 'no-store' });
      const result = await response.json();
      if (!response.ok || result.code !== 200) return;
      const config = result.data || {};

      if (String(config.umami_enabled) === '1' && String(config.umami_website_id || '').trim()) {
        const umamiSrc = validHttpsUrl(config.umami_script_url || 'https://cloud.umami.is/script.js');
        if (umamiSrc) appendScript('umami-analytics-script', umamiSrc, { 'data-website-id': String(config.umami_website_id).trim() });
      }

      if (String(config.cf_analytics_enabled) === '1' && String(config.cf_beacon_token || '').trim()) {
        appendScript('cloudflare-web-analytics-script', 'https://static.cloudflareinsights.com/beacon.min.js', {
          'data-cf-beacon': JSON.stringify({ token: String(config.cf_beacon_token).trim() })
        });
      }

      const clarityProjectId = String(config.clarity_project_id || '').trim();
      if (String(config.clarity_enabled) === '1' && /^[a-z0-9_-]{4,100}$/i.test(clarityProjectId)) {
        appendScript('microsoft-clarity-script', `https://www.clarity.ms/tag/${encodeURIComponent(clarityProjectId)}`);
      }

      if (String(config.generic_analytics_enabled) === '1') {
        const genericSrc = validHttpsUrl(config.generic_analytics_script_url);
        if (genericSrc) appendScript('generic-analytics-script', genericSrc, safeDataAttributes(config.generic_analytics_data_attributes));
      }
    } catch (error) {
      console.warn('[Analytics] 读取统计配置失败，不影响站点正常使用。', error.message);
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', loadAnalytics, { once: true });
  else loadAnalytics();
})();
