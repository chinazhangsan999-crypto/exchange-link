/** 全站入口滑块：采集手势轨迹，交由服务端验签与行为校验。 */
document.addEventListener('DOMContentLoaded', async () => {
  const container = document.querySelector('#sliderContainer'), button = document.querySelector('#sliderBtn'), progress = document.querySelector('#sliderProgress'), tip = document.querySelector('#sliderTip'), hint = document.querySelector('#verifyHint');
  let dragging = false, verified = false, startX = 0, startY = 0, startTime = 0, maxDistance = 0, tracks = [], token = '', tokenReceivedAt = 0, activePointerId = null;
  const point = event => event.touches?.[0] || event.changedTouches?.[0] || event;
  const setHint = (message, color = '') => { hint.textContent = message; hint.style.color = color; };
  fetch('/api/config/public', { credentials: 'same-origin' }).then(response => response.json()).then(result => {
    const raw = String(result.data?.site_logo_url || '').trim();
    const logoUrl = /^https?:\/\//i.test(raw) || /^\/uploads\/logo\/[a-zA-Z0-9._-]+$/.test(raw) ? raw : '';
    if (!logoUrl) return;
    const mark = document.querySelector('.verify-mark');
    if (!mark) return;
    mark.replaceChildren();
    const image = new Image(); image.style.cssText = 'width:100%;height:100%;display:block;object-fit:contain;border-radius:inherit'; image.src = logoUrl; image.alt = '网站 Logo';
    image.onerror = () => { mark.replaceChildren(); mark.textContent = '✦'; };
    mark.append(image);
    const icon = document.querySelector('#runtime-site-favicon') || document.createElement('link');
    icon.id = 'runtime-site-favicon'; icon.rel = 'icon'; icon.href = `${logoUrl}${logoUrl.includes('?') ? '&' : '?'}favicon=1`;
    if (!icon.parentNode) document.head.append(icon);
  }).catch(() => {});
  function updateMaxDistance() { maxDistance = Math.max(1, container.clientWidth - button.offsetWidth - 8); }
  async function getToken() { try { const response = await fetch('/api/verify/init', { credentials: 'same-origin', cache: 'no-store' }); const data = await response.json(); if (!data.success || !data.token) throw Error(data.msg); token = data.token; tokenReceivedAt = Date.now(); setHint('请向右拖动滑块完成验证'); return true; } catch { token = ''; tokenReceivedAt = 0; setHint('⚠️ 获取安全凭证失败，请刷新重试', '#dc2626'); return false; } }
  function paint(distance) { button.style.transform = `translateX(${distance}px)`; progress.style.width = `${Math.min(100, (distance + button.offsetWidth / 2) * 100 / container.clientWidth)}%`; }
  async function startDrag(event) { if (verified || dragging) return; if (event.cancelable) event.preventDefault(); const pointerId = event.pointerId; activePointerId = pointerId; const input = point(event); if (!token || Date.now() - tokenReceivedAt > 1000) { setHint('正在刷新本次安全凭证…'); const ready = await getToken(); if (!ready || activePointerId !== pointerId) return; } dragging = true; startTime = Date.now(); startX = input.clientX; startY = input.clientY; tracks = [{ x: 0, y: 0, t: 0 }]; button.style.transition = 'none'; progress.style.transition = 'none'; }
  function moveDrag(event) { if (!dragging || verified) return; const input = point(event), elapsed = Date.now() - startTime, distance = Math.max(0, Math.min(maxDistance, input.clientX - startX)); tracks.push({ x: Math.round(distance), y: Math.round(input.clientY - startY), t: elapsed }); paint(distance); if (distance >= maxDistance * .96) submitVerify(); if (event.cancelable) event.preventDefault(); }
  async function submitVerify() { if (!dragging || verified) return; dragging = false; const duration = Date.now() - startTime; paint(maxDistance); setHint('⚡ 正在校验安全凭证…');
    try { const response = await fetch('/api/verify/check', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token, tracks, duration, isWebdriver: Boolean(navigator.webdriver || window.__webdriver_evaluate), fingerprint: { webdriver: Boolean(navigator.webdriver), language: navigator.language || '', platform: navigator.platform || '', screen: `${screen.width}x${screen.height}` } }) }); const result = await response.json(); if (!result.success) throw Error(result.msg || '验证未通过'); verified = true; container.classList.add('success'); tip.textContent = '验证通过'; setHint('🎉 验证成功，正在进入站点…', '#059669'); const target = new URLSearchParams(location.search).get('target') || '/'; let safeTarget = '/'; try { const parsed = new URL(target, 'https://local.invalid'); if (target.startsWith('/') && !target.startsWith('//') && parsed.origin === 'https://local.invalid') safeTarget = `${parsed.pathname}${parsed.search}${parsed.hash}`; } catch { safeTarget = '/'; } setTimeout(() => location.replace(safeTarget), 450); }
    catch (error) { setHint(`❌ ${error.message || '验证失败，请重试'}`, '#dc2626'); resetSlider(); }
  }
  function resetSlider() { dragging = false; activePointerId = null; button.style.transition = 'transform .28s ease'; progress.style.transition = 'width .28s ease'; paint(0); tracks = []; getToken(); }
  function endDrag() { activePointerId = null; if (dragging && !verified) resetSlider(); }
  updateMaxDistance(); window.addEventListener('resize', updateMaxDistance);
  button.addEventListener('pointerdown', startDrag); window.addEventListener('pointermove', moveDrag, { passive: false }); window.addEventListener('pointerup', endDrag); window.addEventListener('pointercancel', endDrag);
  await getToken();
});
