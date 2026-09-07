/** 永久发布页：浏览器真实网络测速。Reject 一律离线，绝不把失败等待耗时作为延迟。 */
const mirrorList = document.querySelector('#mirror-list');
const mainSiteCard = document.querySelector('#main-site-card');
const toast = document.querySelector('#toast');
const lostPreventionPublish = document.querySelector('#lost-prevention-publish');
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));

function showToast(message) { toast.textContent = message; toast.classList.add('show'); setTimeout(() => toast.classList.remove('show'), 2200); }
function validUrl(value) { try { const url = new URL(String(value || '')); return /^https?:$/.test(url.protocol) ? url.href.replace(/\/$/, '') : ''; } catch { return ''; } }

/**
 * 精准测速：目标端口实际响应才 Resolve 为在线；连接拒绝、断网或超时进入 catch 后直接离线。
 * no-cors 的 opaque 响应仍代表目标端口已响应，适用于跨域镜像节点。
 */
async function testSingleNode(url, timeoutMs = 2500) {
  const cleanUrl = url.replace(/\/+$/, ''), testUrl = `${cleanUrl}/?_ping=${Date.now()}`;
  const start = performance.now(), controller = new AbortController(), timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    await fetch(testUrl, { method: 'HEAD', mode: 'no-cors', cache: 'no-store', signal: controller.signal });
    return { url: cleanUrl, isOnline: true, latency: Math.max(1, Math.round(performance.now() - start)), error: '' };
  } catch (error) {
    // 禁止把失败前的等待时间当作延迟；使用极大值仅用于排序沉底。
    return { url: cleanUrl, isOnline: false, latency: 999999, error: error.name === 'AbortError' ? '连接超时' : '无法连接/节点离线' };
  } finally { clearTimeout(timer); }
}

function latencyBadge(node, recommended = false) {
  if (!node.isOnline) return `<span class="badge badge-offline" title="${escapeHtml(node.error)}">🔴 无法连接</span>`;
  if (recommended) return '<span class="badge badge-green">★ 极速推荐</span>';
  if (node.latency >= 1000) return `<span class="badge badge-orange">🟠 ${node.latency} ms</span>`;
  if (node.latency >= 300) return `<span class="badge badge-yellow">🟡 ${node.latency} ms</span>`;
  return `<span class="badge badge-green">🟢 ${node.latency} ms</span>`;
}

/** 离线节点不可点击且强制灰化；主站固定在单独区域，不参与备用线路排序。 */
function cardHtml(node, { official = false, recommended = false } = {}) {
  const offline = !node.isOnline;
  const badge = official && !offline ? '<span class="badge official">★ 官方推荐</span>' : latencyBadge(node, recommended);
  const action = offline ? '<button class="go btn-disabled" type="button" disabled>⚠️ 暂不可用</button>' : `<a class="go" href="${escapeHtml(node.url)}" target="_blank" rel="noopener">一键直达 ↗</a>`;
  const status = offline ? `无法连接：${escapeHtml(node.error || '节点离线')}` : `你的网络延迟：${node.latency} ms`;
  return `<article class="node${offline ? ' offline node-offline' : ''}${official ? ' official' : ''}${recommended && !offline ? ' recommended' : ''}"><div><div class="node-name">${escapeHtml(node.name)} ${badge}</div><div class="node-url">${escapeHtml(node.url)}</div><div class="node-state">${status}</div></div>${action}</article>`;
}

function renderMirrors(nodes) {
  if (!nodes.length) { mirrorList.innerHTML = '<p class="empty">后台暂未配置备用网址，请稍后刷新本页。</p>'; return; }
  const sorted = [...nodes].sort((a, b) => a.isOnline === b.isOnline ? a.latency - b.latency : a.isOnline ? -1 : 1);
  const fastestId = sorted.find(node => node.isOnline)?.id;
  mirrorList.innerHTML = sorted.map(node => cardHtml(node, { recommended: node.id === fastestId })).join('');
}

/** 在永久发布页展示后台配置的最终防失联邮箱。 */
function renderLostPreventionEmail(emailValue) {
  const email = String(emailValue || '').trim();
  if (!email) { lostPreventionPublish.hidden = true; return; }
  lostPreventionPublish.hidden = false;
  document.querySelector('#publish-lost-email').textContent = email;
  document.querySelector('#publish-mailto-lost-email').href = `mailto:${encodeURIComponent(email)}`;
  document.querySelector('#publish-copy-lost-email').onclick = () => window.copyEmailToClipboard?.(email);
}

function renderPublishBrand(siteNameValue) {
  const siteName = String(siteNameValue || '星环导航').trim() || '星环导航';
  document.title = `${siteName} · 永久发布页`;
  document.querySelector('#publish-page-title').textContent = `${siteName} · 永久发布页`;
  document.querySelector('meta[name="description"]')?.setAttribute('content', `${siteName}永久发布页，提供主站与镜像节点实时测速。`);
}

function renderPublishLogo(logoValue) {
  const raw = String(logoValue || '').trim();
  const logoUrl = validUrl(raw) || (/^\/uploads\/logo\/[a-zA-Z0-9._-]+$/.test(raw) ? raw : '');
  const mark = document.querySelector('.hero-mark');
  if (!mark) return;
  mark.replaceChildren();
  if (!logoUrl) { mark.textContent = '✦'; return; }
  const image = new Image(); image.style.cssText = 'width:100%;height:100%;display:block;object-fit:contain;border-radius:inherit'; image.src = logoUrl; image.alt = '网站 Logo';
  image.onerror = () => { mark.replaceChildren(); mark.textContent = '✦'; };
  mark.append(image);
}

async function loadMirrors() {
  try {
    const response = await fetch('/api/mirrors', { cache: 'no-store' });
    const result = await response.json(); if (result.code !== 200) throw new Error(result.msg || '镜像列表加载失败');
    renderPublishBrand(result.data?.site_name);
    renderPublishLogo(result.data?.site_logo_url);
    renderLostPreventionEmail(result.data?.lost_prevention_email);
    const main = { ...(result.data?.mainSite || {}), url: validUrl(result.data?.mainSite?.url) };
    const mirrors = (result.data?.mirrors || []).map(item => ({ ...item, url: validUrl(item.url) })).filter(item => item.url && item.url !== main.url);
    const [mainTest, tests] = await Promise.all([
      main.url ? testSingleNode(main.url).then(test => ({ ...main, ...test })) : Promise.resolve(null),
      Promise.all(mirrors.map(async item => ({ ...item, ...(await testSingleNode(item.url)) })))
    ]);
    mainSiteCard.innerHTML = mainTest ? cardHtml(mainTest, { official: true }) : '<p class="empty">后台暂未配置主站地址。</p>';
    renderMirrors(tests);
  } catch (error) {
    const message = `<p class="empty">镜像测速失败：${escapeHtml(error.message)}。请稍后刷新重试。</p>`; mainSiteCard.innerHTML = message; mirrorList.innerHTML = message;
  }
}

document.addEventListener('keydown', event => { if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'd') showToast('请使用浏览器收藏功能保存本页'); });
loadMirrors();
