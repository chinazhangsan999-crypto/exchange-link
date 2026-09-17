# Cloudflare 回源 IP 白名单自动同步

该机制只管理 Caddy 的 Cloudflare 回源 CIDR，不修改公共前台 Origin 白名单。

## 工作方式

1. systemd timer 每天北京时间 04:20 触发，附加最多 30 分钟随机延迟。
2. 同时从 Cloudflare 官方 `ips-v4` 与 `ips-v6` 地址下载清单。
3. 使用 Node.js 校验 CIDR、IP 版本、重复项和最小条目数量。
4. 生成候选 `cloudflare-ips.caddy`，执行 `caddy validate`。
5. 校验通过后才 reload Caddy；reload 失败会恢复上一份清单。
6. 将不含凭据的结果写入应用 `data/cloudflare-ip-whitelist-state.json`，供后台概览仪表盘读取。

后台“立即核对并同步”按钮只允许运行固定的
`webring-cloudflare-ip-sync.service`，不能传入文件路径或任意命令。

## 首次部署

先备份服务器的 `/etc/caddy/Caddyfile`，再将仓库中的 `ops/Caddyfile` 与
`ops/cloudflare-ips.caddy` 放入 `/etc/caddy/`。确认 Caddy 配置中的源站域名正确后执行：

```bash
sudo APP_USER=niaiwo bash /home/niaiwo/app/ops/install-cloudflare-ip-sync.sh
```

安装脚本会：

- 安装 root 权限的固定同步程序；
- 安装并启用 systemd timer；
- 为应用用户增加仅能启动这一固定 service 的 sudoers 规则；
- 立即执行一次同步并生成后台状态文件。

## 运维检查

```bash
systemctl status webring-cloudflare-ip-sync.timer
systemctl status webring-cloudflare-ip-sync.service
journalctl -u webring-cloudflare-ip-sync.service -n 100 --no-pager
```

不应授予 Node.js 用户编辑 `/etc/caddy`、执行任意 `sudo` 或重启任意 systemd
服务的权限。
