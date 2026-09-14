// 独立广告 Origin 预留入口：不执行、不代理任何第三方代码。
// 若未来必须呈现不可信联盟脚本，需要产品层明确允许 sandbox iframe 后另行设计；
// 在此之前保持 404，避免第三方 JavaScript 与前台或后台凭证处于同一 Origin。
export default {
  fetch() {
    return new Response('Not Found', {
      status: 404,
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        'X-Robots-Tag': 'noindex, nofollow'
      }
    });
  }
};
