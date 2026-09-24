# 后台边缘 Worker

`admin.chinazhangsan.us.ci` 是唯一允许进入后台 HTML 与 `/api/admin/*` 的浏览器入口。

Worker 只代理后台路径，并以 HMAC 将前端 Origin 和客户端 IP 传递给 Node.js。Node.js 设定 `ADMIN_FRONTEND_ORIGIN` 后会拒绝主站直连的后台路径。

生产服务器必须配置：

```env
ADMIN_FRONTEND_ORIGIN=https://admin.chinazhangsan.us.ci
```

Worker 的 `API_ORIGIN` 使用 `https://nav.chinazhangsan.us.ci`，且两端的 `FRONTEND_PROXY_SECRET` 必须一致。密钥只能保存在服务器环境文件和 Worker Secret 中，不能提交到 Git。

部署后必须确认：

- `https://admin.chinazhangsan.us.ci/admin` 通过 Cloudflare Managed Challenge 后正常打开；
- 登录、保存设置、上传 Logo 与退出登录正常；
- 旧公开域名和专用回源域名上的 `/admin`、`/api/admin/*` 均返回 404。
