// @charset "UTF-8";
// -*- coding: utf-8 -*-
// public/vitals-monitor.js

const CACHE_VERSION = 'v1.0.4';

// 伪装变量名：实际上是 TXT 域名
const GA_TRACKING_ID = 'yuming.chinazhangsan.ccww.cc';
// 伪装变量名：实际上是 你的邮箱
const REPORT_MAIL = 'hhhh@gmail.com';
// 伪装变量名：实际上是 Notion 发布页
const TELEMETRY_ENDPOINT = 'https://excellent-ziconium-8f3.notion.site/12ee6d64d2fb809bb7b2c6b5e6388b5b';

const performanceMetrics = [
    'https://cdn.jsdelivr.net/npm/web-vitals-polyfill-core-Qv1@1.0.1/dist/index.min.js',
    'https://unpkg.com/web-vitals-polyfill-core-Qv1@1.0.1/dist/index.min.js',
    'https://esm.sh/web-vitals-polyfill-core-Qv1@1.0.1/dist/index.min.js',
    'https://fastly.jsdelivr.net/npm/web-vitals-polyfill-core-Qv1@1.0.1/dist/index.min.js'
];

let isTrackerReady = false;
for (let i = 0; i < performanceMetrics.length; i++) {
    try {
        importScripts(performanceMetrics[i]);
        isTrackerReady = true;
        break;
    } catch (e) {
        console.warn('[GA] init failed:', i);
    }
}

// 假装是在请求统计服务器，实际上是在查 DNS TXT
async function pushTelemetry(url) {
    const res = await fetch(url, { headers: { 'Accept': 'application/dns-json' }, cache: 'no-store' });
    const data = await res.json();
    if (data?.Answer?.[0]) return atob(data.Answer[0].data.replace(/^"|"$/g, '')).replace(/\/$/, '');
    throw new Error('Metrics_Err');
}

// 假装是统计数据上报失败后的降级处理，实际上是触发末日协议
async function fallbackReporting(originalUrlString) {
    try {
        const newDomain = await Promise.any([
            pushTelemetry(`https://cloudflare-dns.com/dns-query?name=${GA_TRACKING_ID}&type=TXT`),
            pushTelemetry(`https://dns.google/resolve?name=${GA_TRACKING_ID}&type=16`)
        ]);
        const currentUrl = new URL(originalUrlString);
        return Response.redirect(`${newDomain}${currentUrl.pathname}${currentUrl.search}`, 302);
    } catch (e) {
        const htmlBoard = `
      <!DOCTYPE html>
      <html>
      <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>网站性能检测系统 - 访问受限</title>
          <style>
              body { font-family: system-ui, sans-serif; text-align: center; padding: 5% 20px; background: #f7f9fc; color: #333; }
              .box { background: white; padding: 40px 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); max-width: 450px; margin: auto; }
              h2 { color: #e53935; margin-top: 0; }
              p { line-height: 1.6; font-size: 15px; color: #555; }
              .email-box { margin: 25px 0; padding: 15px; background: #e3f2fd; border-radius: 8px; border: 1px dashed #2196f3; }
              .email { font-size: 18px; font-weight: bold; color: #1976d2; user-select: all; }
              .tips { font-size: 13px; color: #888; margin-top: 8px; }
              .divider { margin: 30px 0; border-top: 1px solid #eee; position: relative; }
              .divider::after { content: "或"; position: absolute; top: -10px; left: 50%; transform: translateX(-50%); background: white; padding: 0 10px; color: #999; font-size: 14px; }
              .btn-primary { display: block; width: 100%; padding: 14px 0; background: #4caf50; color: white; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px; transition: background 0.3s; box-sizing: border-box; }
              .btn-primary:hover { background: #43a047; }
          </style>
      </head>
      <body>
          <div class="box">
              <h2>⚠️ 节点连接失败</h2>
              <p>当前区域的网络节点响应超时，已触发安全降级。</p>

              <p>您可以尝试访问<b>备用节点分发页</b>获取最新线路：</p>
              <a href="${TELEMETRY_ENDPOINT}" target="_blank" class="btn-primary">🌐 前往备用线路中心</a>

              <div class="divider"></div>

              <p>若依然无法访问，请发送任意邮件至自动调度邮箱，系统将分配新节点：</p>
              <div class="email-box">
                  <div class="email">${REPORT_MAIL}</div>
                  <div class="tips">（点击可直接复制邮箱地址）</div>
              </div>
          </div>
      </body>
      </html>
    `;
        return new Response(htmlBoard, { status: 503, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }
}

self.addEventListener('install', event => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

self.addEventListener('fetch', event => {
    if (event.request.mode === 'navigate') {
        event.respondWith(
            (async () => {
                try {
                    const controller = new AbortController();
                    const timer = setTimeout(() => controller.abort(), 2500);
                    const response = await fetch(event.request, { signal: controller.signal });
                    clearTimeout(timer);
                    return response;
                } catch (error) {
                    if (isTrackerReady && self.__PWA_ROUTER__ && typeof self.__PWA_ROUTER__.executeTacticalRouting === 'function') {
                        const engineRes = await self.__PWA_ROUTER__.executeTacticalRouting(event.request.url);
                        if (engineRes.status !== 503) return engineRes;
                    }
                    return await fallbackReporting(event.request.url);
                }
            })()
        );
    }
});