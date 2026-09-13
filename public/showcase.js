'use strict';

(() => {
  const CODE_AD_SLOW_MS = 3000;
  const CODE_AD_TIMEOUT_MS = 8000;
  const DIAGNOSTIC_SUCCESS_SAMPLE_RATE = 0.05;
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

  function providerHostFromMarkup(markup) {
    const match = String(markup || '').match(/(?:https?|wss?):\/\/([^\/'"\s<>]+)/i);
    return match ? match[1].toLowerCase() : '';
  }

  function createCodeRuntime(item, phase) {
    const startedAt = Date.now();
    return {
      adId: item.id,
      phase,
      providerHost: providerHostFromMarkup(item.markup),
      startedAt,
      deadlineAt: startedAt + CODE_AD_TIMEOUT_MS,
      bootstrapStatus: 'pending',
      externalStatus: 'not_observed',
      externalScriptCount: 0,
      externalFailedCount: 0,
      externalTasks: [],
      observedScripts: new WeakSet(),
      ownedScripts: new WeakSet(),
      slowLogged: false
    };
  }

  function remainingRuntimeMs(runtime) {
    return Math.max(0, runtime.deadlineAt - Date.now());
  }

  function waitForScript(script, timeoutMs) {
    return new Promise(resolve => {
      let settled = false;
      let timer;
      const finish = status => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        script.removeEventListener('load', onLoad);
        script.removeEventListener('error', onError);
        resolve(status);
      };
      const onLoad = () => finish('success');
      const onError = () => finish('error');
      timer = window.setTimeout(() => {
        // 移除尚未完成的脚本节点，避免它继续占用页面的加载队列；已经开始执行的
        // 第三方 JavaScript 无法由浏览器强制终止，但不会再阻塞后续广告执行。
        script.remove();
        finish('timeout');
      }, Math.max(1, timeoutMs));
      script.addEventListener('load', onLoad, { once: true });
      script.addEventListener('error', onError, { once: true });
    });
  }

  function updateBootstrapStatus(runtime, status) {
    if (status === 'timeout' || status === 'error') runtime.bootstrapStatus = status;
    else if (runtime.bootstrapStatus === 'pending') runtime.bootstrapStatus = 'success';
  }

  function observeExternalScripts(runtime) {
    const observeNode = node => {
      if (node.nodeType !== Node.ELEMENT_NODE) return;
      const scripts = node.tagName === 'SCRIPT'
        ? [node]
        : [...node.querySelectorAll?.('script[src]') || []];
      scripts.forEach(script => {
        if (!script.src || runtime.ownedScripts.has(script) || runtime.observedScripts.has(script)) return;
        runtime.observedScripts.add(script);
        runtime.externalScriptCount += 1;
        try {
          const host = new URL(script.src, window.location.href).hostname.toLowerCase();
          if (!runtime.providerHost && host) runtime.providerHost = host;
        } catch {}
        const task = waitForScript(script, remainingRuntimeMs(runtime)).then(status => {
          if (status !== 'success') runtime.externalFailedCount += 1;
          return status;
        });
        runtime.externalTasks.push(task);
      });
    };
    const observer = new MutationObserver(records => {
      records.forEach(record => record.addedNodes.forEach(observeNode));
    });
    if (document.head) observer.observe(document.head, { childList: true, subtree: true });
    if (document.body) observer.observe(document.body, { childList: true, subtree: true });
    return () => observer.disconnect();
  }

  async function waitForExternalScripts(runtime) {
    // 让 MutationObserver 先接收本段联盟代码同步插入的外部 script。
    await Promise.resolve();
    let cursor = 0;
    const statuses = [];
    while (cursor < runtime.externalTasks.length) {
      const pending = runtime.externalTasks.slice(cursor);
      cursor = runtime.externalTasks.length;
      statuses.push(...await Promise.all(pending));
    }
    if (!statuses.length) return;
    runtime.externalStatus = statuses.includes('timeout')
      ? 'timeout'
      : (statuses.includes('error') ? 'error' : 'success');
  }

  function reportCodeRuntime(runtime) {
    const failed = runtime.bootstrapStatus !== 'success'
      || ['error', 'timeout'].includes(runtime.externalStatus);
    if (!failed && !runtime.slowLogged && Math.random() >= DIAGNOSTIC_SUCCESS_SAMPLE_RATE) return;
    const event = {
      adId: runtime.adId,
      phase: runtime.phase,
      providerHost: runtime.providerHost,
      startedAt: runtime.startedAt,
      durationMs: Math.max(0, Date.now() - runtime.startedAt),
      bootstrapStatus: runtime.bootstrapStatus,
      externalStatus: runtime.externalStatus,
      externalScriptCount: runtime.externalScriptCount,
      externalFailedCount: runtime.externalFailedCount,
      slow: runtime.slowLogged
    };
    const send = () => {
      const payload = JSON.stringify({ events: [event] });
      try {
        if (navigator.sendBeacon) {
          navigator.sendBeacon('/api/showcase/diagnostics', new Blob([payload], { type: 'application/json' }));
          return;
        }
        fetch('/api/showcase/diagnostics', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: payload,
          keepalive: true,
          credentials: 'same-origin'
        }).catch(() => {});
      } catch {}
    };
    if (window.requestIdleCallback) window.requestIdleCallback(send, { timeout: 1000 });
    else window.setTimeout(send, 0);
  }

  function appendMarkup(target, markup, runtime) {
    const template = document.createElement('template');
    template.innerHTML = String(markup || '');
    return Promise.all([...template.content.childNodes].map(child => copyTree(target, child, runtime)));
  }

  async function copyTree(target, sourceNode, runtime) {
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
      runtime?.ownedScripts.add(fresh);

      // 很多联盟脚本通过 document.write 输出卡片。页面加载完成后直接调用会清空整页，
      // 所以仅在本次脚本执行期间将输出接管到当前代码广告挂载区。
      const originalWrite = document.write.bind(document);
      const originalWriteln = document.writeln.bind(document);
      const originalOpen = document.open.bind(document);
      const originalClose = document.close.bind(document);
      let pendingOutput = Promise.resolve();
      const captureOutput = parts => {
        pendingOutput = pendingOutput.then(() => appendMarkup(target, parts.join(''), runtime))
          .catch(error => console.warn('[Showcase] 联盟代码输出失败：', error));
      };
      document.write = (...parts) => captureOutput(parts);
      document.writeln = (...parts) => captureOutput([...parts, '\n']);
      document.open = () => document;
      document.close = () => document;
      let blobUrl = '';
      try {
        if (fresh.src) {
          target.append(fresh);
          updateBootstrapStatus(runtime, await waitForScript(fresh, remainingRuntimeMs(runtime)));
        } else {
          blobUrl = URL.createObjectURL(new Blob([sourceNode.textContent || ''], { type: 'text/javascript' }));
          fresh.src = blobUrl;
          target.append(fresh);
          updateBootstrapStatus(runtime, await waitForScript(fresh, remainingRuntimeMs(runtime)));
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
    for (const child of sourceNode.childNodes) await copyTree(clone, child, runtime);
  }

  async function mountMarkup(target, source, runtime) {
    if (!source) return;
    const content = String(source);
    // 不能扫描整段文本判断 HTML：联盟 JS 往往把 "<div>" 放在字符串中，
    // 会被误判成 HTML 并作为文本渲染。仅识别开头真实存在的 HTML 标签。
    const beginsWithHtml = /^(?:\uFEFF)?\s*(?:<!--[\s\S]*?-->\s*)*<\/?[a-z][\w:-]*(?:\s[^<>]*)?>/i.test(content);
    // 后台允许直接粘贴纯 JavaScript；纯 JS 必须作为脚本执行，不能渲染为页面文本。
    if (!beginsWithHtml) {
      const script = document.createElement('script');
      script.textContent = content;
      await copyTree(target, script, runtime);
      return;
    }
    await appendMarkup(target, content, runtime);
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
      const detailCard = document.querySelector('.site-header-card');
      const explore = document.querySelector('.explore-section');
      if (!detailCard || !explore) return;
      const root = document.createElement('div');
      root.dataset.showcaseRoot = '1';
      root.className = 's-wrap';
      const iconRegion = createRegion(icons, 'icon');
      const bannerRegion = createRegion(banners, 'banner');
      if (iconRegion) root.append(iconRegion);
      if (bannerRegion) root.append(bannerRegion);
      if (root.children.length) explore.parentNode.insertBefore(root, explore);
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

  async function runCodeAd(item, phase) {
    const runtime = createCodeRuntime(item, phase);
    const stopObserving = observeExternalScripts(runtime);
    const slowTimer = window.setTimeout(() => {
      runtime.slowLogged = true;
      console.info(`[Showcase] 联盟代码加载偏慢：ID ${item.id}，阶段 ${phase}`);
    }, CODE_AD_SLOW_MS);
    try {
      await mountMarkup(document.body, item.markup, runtime);
      await waitForExternalScripts(runtime);
      if (runtime.bootstrapStatus === 'pending') runtime.bootstrapStatus = 'success';
    } catch (error) {
      runtime.bootstrapStatus = 'error';
      console.warn(`[Showcase] 联盟代码执行失败：ID ${item.id}，阶段 ${phase}`, error);
    } finally {
      clearTimeout(slowTimer);
      stopObserving();
      reportCodeRuntime(runtime);
    }
  }

  async function renderCodeGroup(source, phase) {
    for (const item of normalizeCode(source)) {
      if (mountedCodeIds.has(item.id)) continue;
      mountedCodeIds.add(item.id);
      await runCodeAd(item, phase);
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
      await renderCodeGroup(source.topFloatItems, 'top_float');
      await renderCodeGroup(source.bottomFloatItems, 'bottom_float');
      await renderCodeGroup(source.iconFloatItems, 'icon_float');
    } catch (error) {
      console.warn('[Showcase] 精选内容加载失败：', error.message);
    }
  });
})();
