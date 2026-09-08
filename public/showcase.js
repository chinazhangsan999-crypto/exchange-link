'use strict';

(() => {
  const mountedCodeIds = new Set();
  const safeUrl = value => {
    try {
      const url = new URL(String(value || '').trim(), window.location.origin);
      return /^https?:$/.test(url.protocol) ? url.href : '';
    } catch { return ''; }
  };

  const fallbackCover = title => {
    const text = String(title || '荐').trim().slice(0, 2).replace(/[&<>"']/g, '');
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="120" height="120"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#3b82f6"/><stop offset="1" stop-color="#8b5cf6"/></linearGradient></defs><rect width="120" height="120" rx="24" fill="url(#g)"/><text x="60" y="70" text-anchor="middle" font-size="34" font-family="Arial,sans-serif" font-weight="700" fill="white">${text}</text></svg>`;
    return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
  };

  function detectDevice() {
    const userAgent = navigator.userAgent || '';
    if (/HarmonyOS|OpenHarmony/i.test(userAgent)) return 'harmony';
    if (/Android/i.test(userAgent)) return 'android';
    if (/iPhone|iPad|iPod/i.test(userAgent)
      || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)) return 'ios';
    return 'pc';
  }

  function matchesPlatform(platform, device) {
    if (platform === 'all') return true;
    if (platform === 'non_ios') return device !== 'ios';
    return platform === device;
  }

  function normalizeRegular(source, device) {
    return (Array.isArray(source) ? source : []).map(item => ({
      id: Number(item.id),
      title: String(item.title || '').trim(),
      position: ['banner', 'icon'].includes(item.ad_position) ? item.ad_position : 'banner',
      platform: String(item.platform || 'all'),
      href: safeUrl(item.target_url),
      cover: safeUrl(item.image_url),
      hint: String(item.description || '').trim()
    })).filter(item => item.title && item.href && item.cover && matchesPlatform(item.platform, device));
  }

  function normalizeCode(source) {
    return (Array.isArray(source) ? source : []).map(item => ({
      id: Number(item.id),
      markup: String(item.markup || item.ad_code || '')
    })).filter(item => item.id > 0 && item.markup);
  }

  function appendMarkup(target, markup) {
    const template = document.createElement('template');
    template.innerHTML = String(markup || '');
    return Promise.all([...template.content.childNodes].map(child => copyTree(target, child)));
  }

  async function copyTree(target, sourceNode) {
    if (sourceNode.nodeType === Node.TEXT_NODE) {
      target.append(document.createTextNode(sourceNode.textContent || ''));
      return;
    }
    if (sourceNode.nodeType !== Node.ELEMENT_NODE) return;
    if (sourceNode.tagName === 'SCRIPT') {
      const fresh = document.createElement('script');
      for (const attribute of sourceNode.attributes) fresh.setAttribute(attribute.name, attribute.value);
      fresh.async = false;
      const scriptType = String(fresh.type || '').toLowerCase();
      const executable = !scriptType || ['text/javascript', 'application/javascript', 'module'].includes(scriptType);
      if (!executable) {
        fresh.textContent = sourceNode.textContent || '';
        target.append(fresh);
        return;
      }

      // 很多联盟脚本通过 document.write 输出卡片。页面加载完成后直接调用会清空整页，
      // 所以仅在本次脚本执行期间将输出接管到当前代码广告挂载区。
      const originalWrite = document.write.bind(document);
      const originalWriteln = document.writeln.bind(document);
      const originalOpen = document.open.bind(document);
      const originalClose = document.close.bind(document);
      let pendingOutput = Promise.resolve();
      const captureOutput = parts => {
        pendingOutput = pendingOutput.then(() => appendMarkup(target, parts.join('')))
          .catch(error => console.warn('[Showcase] 联盟代码输出失败：', error));
      };
      document.write = (...parts) => captureOutput(parts);
      document.writeln = (...parts) => captureOutput([...parts, '\n']);
      document.open = () => document;
      document.close = () => document;
      let blobUrl = '';
      try {
        if (fresh.src) {
          await new Promise(resolve => {
            fresh.addEventListener('load', resolve, { once: true });
            fresh.addEventListener('error', resolve, { once: true });
            target.append(fresh);
          });
        } else {
          blobUrl = URL.createObjectURL(new Blob([sourceNode.textContent || ''], { type: 'text/javascript' }));
          fresh.src = blobUrl;
          await new Promise(resolve => {
            fresh.addEventListener('load', resolve, { once: true });
            fresh.addEventListener('error', resolve, { once: true });
            target.append(fresh);
          });
        }
        await pendingOutput;
      } finally {
        document.write = originalWrite;
        document.writeln = originalWriteln;
        document.open = originalOpen;
        document.close = originalClose;
        if (blobUrl) URL.revokeObjectURL(blobUrl);
      }
      return;
    }
    const clone = sourceNode.cloneNode(false);
    target.append(clone);
    for (const child of sourceNode.childNodes) await copyTree(clone, child);
  }

  async function mountMarkup(target, source) {
    if (!source) return;
    const content = String(source);
    // 不能扫描整段文本判断 HTML：联盟 JS 往往把 "<div>" 放在字符串中，
    // 会被误判成 HTML 并作为文本渲染。仅识别开头真实存在的 HTML 标签。
    const beginsWithHtml = /^(?:\uFEFF)?\s*(?:<!--[\s\S]*?-->\s*)*<\/?[a-z][\w:-]*(?:\s[^<>]*)?>/i.test(content);
    // 后台允许直接粘贴纯 JavaScript；纯 JS 必须作为脚本执行，不能渲染为页面文本。
    if (!beginsWithHtml) {
      const script = document.createElement('script');
      script.textContent = content;
      await copyTree(target, script);
      return;
    }
    await appendMarkup(target, content);
  }

  function attachHint(element, text) {
    if (text) element.dataset.sponsorHint = text;
  }

  function imageEntry(item, variant) {
    const link = document.createElement('a');
    link.className = `${variant === 'icon' ? 's-tile' : 's-unit'} device-${item.platform}`;
    link.href = item.href;
    link.target = '_blank';
    link.rel = 'noopener';
    link.title = item.title;
    attachHint(link, item.hint);
    const image = document.createElement('img');
    image.className = variant === 'icon' ? 's-thumb' : 's-cover';
    image.src = item.cover;
    image.alt = item.title;
    image.loading = 'lazy';
    image.decoding = 'async';
    image.addEventListener('error', () => {
      if (image.dataset.fallbackApplied === '1') return;
      image.dataset.fallbackApplied = '1';
      image.src = fallbackCover(item.title);
    });
    link.append(image);
    if (variant === 'icon') {
      const title = document.createElement('span');
      title.className = 's-title';
      title.textContent = item.title;
      link.append(title);
    }
    return link;
  }

  function createRegion(items, position) {
    if (!items.length) return null;
    const region = document.createElement('div');
    region.className = position === 'icon' ? 's-matrix' : 's-strip';
    region.dataset.showcasePlace = position;
    region.setAttribute('aria-label', position === 'icon' ? '精选应用' : '精选推荐');
    items.forEach(item => region.append(imageEntry(item, position)));
    return region;
  }

  function renderRegular(source, device) {
    const items = normalizeRegular(source, device);
    if (!items.length || document.querySelector('[data-showcase-root]')) return;
    const banners = items.filter(item => item.position === 'banner');
    const icons = items.filter(item => item.position === 'icon');
    if (document.body.classList.contains('site-detail-page')) {
      const intro = document.querySelector('.intro-card');
      const explore = document.querySelector('.explore-section');
      const iconRegion = createRegion(icons, 'icon');
      const bannerRegion = createRegion(banners, 'banner');
      if (iconRegion && intro) intro.insertAdjacentElement('afterend', iconRegion);
      if (bannerRegion && explore) explore.insertAdjacentElement('afterend', bannerRegion);
      return;
    }
    const root = document.createElement('div');
    root.dataset.showcaseRoot = '1';
    root.className = 's-wrap';
    const bannerRegion = createRegion(banners, 'banner');
    const iconRegion = createRegion(icons, 'icon');
    if (bannerRegion) root.append(bannerRegion);
    if (iconRegion) root.append(iconRegion);
    const popular = document.querySelector('.popular-area');
    if (root.children.length && popular) popular.parentNode.insertBefore(root, popular);
  }

  async function renderCodeGroups(groups) {
    for (const source of groups) {
      for (const item of normalizeCode(source)) {
        if (mountedCodeIds.has(item.id)) continue;
        mountedCodeIds.add(item.id);
        await mountMarkup(document.body, item.markup);
      }
    }
  }

  async function fetchShowcase() {
    const response = await fetch('/api/showcase', { credentials: 'same-origin' });
    const result = await response.json();
    if (!response.ok || result.code !== 200) throw new Error(result.msg || '精选内容加载失败');
    return result.data || {};
  }

  document.addEventListener('DOMContentLoaded', async () => {
    try {
      const source = await fetchShowcase();
      const device = detectDevice();
      document.documentElement.dataset.clientDevice = device;
      renderRegular(source.regularItems, device);
      await renderCodeGroups([source.topFloatItems, source.bottomFloatItems, source.iconFloatItems]);
    } catch (error) {
      console.warn('[Showcase] 精选内容加载失败：', error.message);
    }
  });
})();
