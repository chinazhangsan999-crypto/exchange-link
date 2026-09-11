# 导航站接入包

该包由每个导航站加载，导航站主动连接总后台，不要求固定公网 IP，也不需要向总后台开放数据库端口。

Agent 与总控使用 [共享协议](../shared-protocol/PROTOCOL.md)。当前版本为 `1.0`；接入站必须先通过版本握手、快照校验、原子落库和一次性 SSO 验收。

```js
const { createControlCenterAgent } = require('/path/to/packages/site-agent');

const agent = createControlCenterAgent({
  controlCenterUrl: process.env.CONTROL_CENTER_URL,
  credential: process.env.CONTROL_CENTER_SITE_CREDENTIAL,
  agentVersion: '0.1.0',
  metadata: () => ({ app: 'webring', node: process.version }),
  applyConfig: async config => {
    // 在一个短事务中把 config.nodes 写入本地 mirrors 快照，
    // 把 config.ads 写入 central:* 命名空间，保留 local:* 广告。
  },
  issueAdminToken: async (admin, context) => {
    // 调用导航站原有 JWT 签发逻辑，返回只属于本机后台的短期管理员令牌。
    // 建议把 context.nonce 写入 JWT jti，并记录 context.source。
  },
  onError: console.error
});

app.use('/api/admin/control-center', agent.router);
agent.start();
```

现有互助友链系统可使用同目录的 `webring-adapter.js`：

```js
const { createWebringConfigApplier } = require('/path/to/packages/site-agent/webring-adapter');
const database = require('./src/config/database');

const applier = createWebringConfigApplier({
  run: database.run,
  all: database.all,
  withTransaction: database.withTransaction,
  onChanged: async config => {
    if (Array.isArray(config.nodes)) await MirrorModel.syncMirrorsToPartners();
    CacheService.clearPublicCache();
  }
});

await applier.initialize();
// 将 applier.applyConfig 传给 createControlCenterAgent。
```

节点与广告都采用中央全量快照。节点同步只替换 `mirrors.managed_by='central'`，广告同步只替换 `ads.managed_by='central'`，原有本地数据不会被删除。中央节点与本地节点 URL 冲突时整次事务回滚，防止静默覆盖。

广告渲染前按广告位读取 `central_ad_policy:<slot>`，再把中央广告与本地广告交给 `selectAdsForSlot()`。`mixed` 会同时识别中央 `priority` 映射的 `sortOrder` 与本地 `sort_order`，并进行稳定降序排列。联盟 `ad_code` 保持总后台下发的原始字符串。

无构建工具的后台可将 `browser-sso.js` 复制到自己的静态目录，并在其他后台脚本之前加载：

```html
<script src="/admin/control-center-sso.js"></script>
<script>
  window.ControlCenterSso.consume({
    onSuccess: () => window.location.reload()
  }).catch(error => window.showToast?.(error.message));
</script>
```

使用 CommonJS 的后台也可以调用 `consumeControlCenterSso()`。两种方式都会先用 `history.replaceState` 删除地址片段，再将 code POST 到 `/api/admin/control-center/session`，并把本机管理员令牌写入现有的 `webring_admin_token`。

完整流程、安全边界和灰度策略见 [统一后台登录](../../docs/UNIFIED_LOGIN.md)。
