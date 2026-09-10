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

  function appendCustomAnalyticsScripts(code) {
    const template = document.createElement('template');
    template.innerHTML = String(code || '');
    const sourceScripts = [...template.content.querySelectorAll('script')];

    sourceScripts.forEach((source, index) => {
      const id = `custom-analytics-script-${index}`;
      if (inserted.has(id) || document.getElementById(id)) return;
      const script = document.createElement('script');
      script.id = id;
      [...source.attributes].forEach(attribute => {
        if (!['id', 'src'].includes(attribute.name.toLowerCase()) && !/^on/i.test(attribute.name)) {
          script.setAttribute(attribute.name, attribute.value);
        }
      });
      const sourceUrl = source.getAttribute('src');
      if (sourceUrl) {
        const safeUrl = validHttpsUrl(sourceUrl);
        if (!safeUrl) return;
        script.src = safeUrl;
        script.async = source.async;
        script.defer = source.defer;
        script.referrerPolicy = 'strict-origin-when-cross-origin';
        script.onerror = () => console.warn('[Analytics] 自定义统计外部脚本加载失败，不影响站点正常使用。');
      } else {
        script.textContent = source.textContent || '';
      }
      inserted.add(id);
      document.head.appendChild(script);
    });
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

      if (String(config.generic_analytics_enabled) === '1') {
        appendCustomAnalyticsScripts(config.generic_analytics_code);
      }
    } catch (error) {
      console.warn('[Analytics] 读取统计配置失败，不影响站点正常使用。', error.message);
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', loadAnalytics, { once: true });
  else loadAnalytics();
})();
