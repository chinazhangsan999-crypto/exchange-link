# 后台边缘 Worker

`houtai.chinazhangsan.ccwu.cc` 是唯一允许进入后台 HTML 与 `/api/admin/*` 的浏览器入口。

Worker 只代理后台路径，并以 HMAC 将前端 Origin 和客户端 IP 传递给 Node.js。Node.js 设定 `ADMIN_FRONTEND_ORIGIN` 后会拒绝主站直连的后台路径。

部署后必须确认：

- `https://houtai.chinazhangsan.ccwu.cc/admin` 正常打开；
- 登录、保存设置、上传 Logo 与退出登录正常；
- 旧公开域名和专用回源域名上的 `/admin`、`/api/admin/*` 均返回 404。
