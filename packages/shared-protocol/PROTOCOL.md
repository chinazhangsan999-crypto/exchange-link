# 星环总控共享协议 1.0

本协议是总控服务与各导航站 Agent 之间的内部边界。它只覆盖心跳、配置快照和一次性后台登录票据，不改变导航站的访客统计、友链积分、反链巡检或广告执行逻辑。

## 版本与握手

- 当前版本：`1.0`。
- Agent 每个请求必须携带 `X-Control-Protocol: 1.0`。
- 总控每个 Agent 响应都回传 `X-Control-Protocol` 和 `X-Request-Id`。
- 兼容规则：主版本必须相同；Agent 的次版本不能高于总控。不兼容时返回 HTTP `426` 和 `UNSUPPORTED_PROTOCOL_VERSION`。
- `X-Request-Id` 用于跨服务器排查。Agent 应为每次请求生成新值，总控原样回传；缺失或格式不合法时由总控生成。

## 认证

Agent 使用每站独立凭据：

```http
Authorization: Site <site_id>.<secret>
```

`secret` 只在建站或轮换时显示一次，总控数据库只保存摘要。不同站点不得共用凭据，轮换后旧凭据立即失效。

## 通用响应

成功响应：

```json
{ "protocol": "1.0", "ok": true, "code": 200, "message": "成功", "data": {} }
```

失败响应：

```json
{ "protocol": "1.0", "ok": false, "code": 400, "error_code": "INVALID_REQUEST", "message": "请求内容不合法", "details": null }
```

稳定错误码：`INVALID_REQUEST`、`INVALID_SITE_CREDENTIAL`、`UNSUPPORTED_PROTOCOL_VERSION`、`INVALID_CONFIG_SNAPSHOT`、`INVALID_OR_EXPIRED_SSO_TICKET`、`FORBIDDEN`、`INTERNAL_ERROR`。Agent 应按 `error_code` 分支，不应解析中文 `message`。

## 心跳

```http
POST /api/agent/heartbeat
Content-Type: application/json
```

```json
{
  "protocol_version": "1.0",
  "agent_version": "0.2.0",
  "applied_revision": "3-7-2",
  "capabilities": ["config.etag", "nodes.snapshot.v1", "ads.central.v1"],
  "metadata": { "runtime": "node", "instance": "site-a" }
}
```

- `applied_revision` 是站点已成功落库的版本，尚未同步时为空字符串。
- `capabilities` 用于总控识别 Agent 能力，不作为权限证明。
- `metadata` 不超过 8 KiB，不得放密码、令牌或访客隐私数据。
- 建议每 60 秒一次；网络错误不得阻断导航站对外服务。

## 配置快照

```http
GET /api/agent/config
If-None-Match: "cc-3-7-2"
```

版本是 `<nodes_revision>-<ads_revision>-<publish_revision>`。响应同时携带：

```http
ETag: "cc-3-7-2"
X-Config-Revision: 3-7-2
```

未变更时返回 `304` 且无正文。有变更时 `data` 是完整快照，不是增量补丁：

```json
{
  "protocol_version": "1.0",
  "site_id": "7",
  "revision": "3-7-2",
  "revisions": { "nodes_revision": "3", "ads_revision": "7", "publish_revision": "2" },
  "nodes": [],
  "ads": [],
  "ad_policies": [],
  "publish": {}
}
```

节点条目包含稳定的中央 `id`、`speed_name`、`partner_name`、`url`、布尔值 `enabled`，并可包含整数 `sort_order`。接收端同步启用与停用状态，并按 `sort_order DESC, id ASC` 展示；旧版 Agent 忽略新增可选字段仍保持兼容。

广告条目可包含 `priority`，用于中央广告排序及与本地 `sort_order` 进行混合排序。`ad_code` 必须保持原文，内容变化会导致 `integrity_sha256` 校验失败并拒绝整份快照。

Agent 必须按以下顺序处理：

1. 校验响应协议版本。
2. 校验快照 Schema、`site_id`、分项修订号和组合修订号。
3. 校验正文修订号、`ETag` 和 `X-Config-Revision` 一致。
4. 在本站一个短事务内原子替换完整快照。
5. 只有落库成功后才更新本地 `ETag` 和 `applied_revision`。

任何校验或落库失败都必须保留上一个可用快照。广告 `ad_code` 是不透明字符串，不过滤、不重写；`integrity_sha256` 用于检查传输与落库一致性，不代表代码可信。

## 一次性后台登录

浏览器先进入目标站的统一登录过渡页，票据必须放在 URL Fragment 中。过渡页清除 Fragment 后，以同源 POST 将票据交给 Agent；禁止把票据放在 Query 参数中，以免进入代理访问日志。

```http
POST /api/agent/sso/redeem
Content-Type: application/json

{ "ticket": "<32-128 位 base64url>" }
```

- 票据只能由它所属的目标站点凭据兑换。
- 票据只能成功兑换一次，过期、已用或串站均返回 `INVALID_OR_EXPIRED_SSO_TICKET`。
- Agent 不得将总控票据直接当作本站 Session；应生成一次性本地交换码，再由管理页建立本站 Session。
- 一次性交换页与所有响应必须使用 `Cache-Control: no-store`。
- 导航站交换码应放在 URL Fragment 中，默认 30 秒内一次性消费；前端开始交换前立即从地址栏删除 Fragment。
- 导航站签发本地管理员令牌时应使用自己的密钥，并建议把 `local_session_nonce` 写入本地令牌的 `jti`。

## 升级规则

- 只新增可选字段或可选能力时升次版本。
- 删除字段、改变字段语义、改变认证方式或状态机时升主版本。
- 总控先部署兼容代码，再灰度升级 Agent，最后才可停止旧版本。
- JSON Schema 是跨语言实现依据；`index.js` 是 Node.js 双端共用的运行时校验器。两者必须同版本发布。
