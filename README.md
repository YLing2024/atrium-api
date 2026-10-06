[简体中文](README.md) ｜ [English](README.en.md)

# atrium-api

个人网站管理后台的接口服务：系统监控、文件、终端、应用与通知。

## 它能做什么

- **系统状态**：CPU（总体 / 每核）、内存与 swap、磁盘、磁盘 IO、网络速率、PSI 压力、负载、uptime。`/api/admin/system` 实时快照；`/api/admin/system/history` 返回最近 120 个采样点；`/api/admin/system/metrics` 按 `range`（`1h`/`6h`/`1d`/`7d`/`30d`）与 `step`（`1m`/`5m`/`1h`/`1d`）读物化聚合桶；`/api/admin/system/stream` 以 SSE 每秒推送。
- **版本与服务**：`/api/admin/versions`（60s 缓存）、`/api/admin/services`（各服务 up/down + 进程 TOP15 与总 CPU）。
- **文件区**：在 `ADMIN_FILE_DIR` 根下浏览 / 上传（500MB）/ 下载 / 新建 / 重命名 / 删除，并提供限时分享链接（公开入口 `/s/:token`）。另有旧接口 `/api/admin/upload`（100MB）与 `/api/admin/download`。
- **Web 终端**：终端口令二次验证 → 12 小时票据 → ttyd/tmux 会话列表与关闭。
- **应用面板**：只读登记表 + 实时探活，见下节。
- **通知中心**：写入、列表筛选、未读标记、类别注册、统计与 SSE 推送；SQLite 归档，保留 30 天。
- **Hermes 历史浏览**：只读 `~/.hermes/state.db`，请求内 open → query → close。
- **登录与 TOTP**：模式探测、TOTP 登录 / 登出、当前身份、TOTP 重置转发、登录设备会话、接口令牌。

## 应用面板

一个只读面板：把本机应用集中展示并实时探活，不启停服务、不改配置。

- 登记表 `data/apps.json`（`ADMIN_APPS_FILE` 覆盖），**只读消费**、不存在不生成；文件 `mtime` 变化即重读。样例见 `apps.example.json`（占位值）。
- `GET /api/admin/apps`：`?refresh=1` 绕过 10s 缓存；并发请求复用同一次采集。返回 `categories[] / apps[] / discovered[] / notice / warning` 等字段。
- `GET /api/public/apps`：**公开只读、免鉴权**（独立子域「应用中心」用）。沿用同一采集逻辑与 10s 缓存 / 单飞，但只回公开安全字段：`categories[]`（`{id, name}`）与 `apps[]`（白名单 `id / name / category / desc / url / icon / status / latencyMs / onDemand`），剔除 `port / unit / container / probe / registryPath / registryMtime / notice / warning` 与未登记发现 `discovered[]`。`?refresh=1` 按来源 IP 限流（10s 窗口内至多一次真正刷新，超出按缓存读）；响应头 `Cache-Control: no-store`；后端不可用回 `503`。
- **多分组**：`categories[] = {id, name}` 定义分组，未知分类归入「其他」。
- **探活**：优先级 `probe > container > unit > port`；状态 `up` / `auth` / `degraded` / `down` / `idle` / `unknown`。单条超时 1500ms，全部并行，单条失败不影响其它。
- **按需唤醒**：`onDemand: true` 的应用探活不通时归为 `idle`（休眠），不计入宕机。
- **未登记发现**：`ss -ltnp` 取 `127.0.0.1` 监听行；`ignorePorts` 排除固定的无主端口，`ignoreProcesses` 用进程名正则滤掉端口每次都在变的工具监听。
- **图标**：`icon` 为图标名（字符串）；缺省或为 null 时由前端回退为名称首字。

## 快速开始

```bash
npm install
npm start        # = node src/index.ts，默认监听 0.0.0.0:3100
```

无构建（Node 直接执行 TS）、无外部测试框架（`node:test`）、ESLint 只做正确性检查；改完重启进程才生效。

## 配置

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PORT` / `HOST` | `3100` / `0.0.0.0` | 监听端口与地址；systemd 单元设置 `HOST=127.0.0.1` |
| `AUTH_MODE` | `builtin` | 认证模式，见「认证与安全」 |
| `ADMIN_CONFIG_PATH` | `<repo>/config.json` | 配置文件（含初始口令与 TOTP secret，0600） |
| `ADMIN_UPLOAD_DIR` | `<repo>/uploads` | 旧上传接口的落盘目录 |
| `ADMIN_FILE_DIR` | `/root/files/download` | 文件区根目录，所有路径严格限制在其内 |
| `ADMIN_APPS_FILE` | `<repo>/data/apps.json` | 应用登记表 |
| `ADMIN_AUDIT_LOG` | `<repo>/audit.log` | 审计日志（JSON 行追加） |
| `HERMES_STATE_DB` | `~/.hermes/state.db` | 历史浏览数据源 |
| `AUTH_CENTER_BASE_URL` | 无 | 认证中心基址；设备会话与 TOTP 转发用，未配置返回 502 |
| `AUTH_CENTER_INTERNAL_TOKEN_FILE` | `../../auth-server/internal-token` | 认证中心内部令牌文件，只读、不打印 |
| `ADMIN_TERM_PW_FILE` | `~/.hermes/term_password` | 终端口令哈希（`sha256$<salt>$<hash>`，0600） |
| `ADMIN_TOTP_SECRET_FILE` | `<repo>/totp-secret.json` | TOTP secret 持久化 |
| `ADMIN_HISTORY_FILE` / `ADMIN_SAMPLER_LOCK` | 系统临时目录 | 历史缓冲与采样器锁（多实例共享，测试需隔离） |
| `ADMIN_METRICS_DB` / `ADMIN_NOTIFICATIONS_DB` | `<repo>/data/metrics.db` / `notifications.db` | 留样聚合库 / 通知库 |
| `ADMIN_SHARE_FILE` | `<repo>/data/file-shares.json` | 分享链接账本 |
| `ADMIN_SHARE_BASE_URL` | 无 | 分享链接基址；未设置时按请求头推导 |
| `ADMIN_REDIS_PREFIX` | `admin:session:` | Redis 会话 key 前缀（测试实例隔离） |

## 部署

systemd 单元 `admin-server.service`，`WorkingDirectory` 指向仓库根，以 `node src/index.ts` 启动，单元内设置 `HOST=127.0.0.1`。

```bash
systemctl restart admin-server
systemctl status admin-server
journalctl -u admin-server -n 100 --no-pager
```

nginx 反代 `/api/admin/*` → `127.0.0.1:3100`；文件区上传单独放一个 location（上限 512m），其余 `/api/admin/` 为 100m。超出上限由 nginx 先拒绝，返回 HTML 而非 JSON。

## 认证与安全

| `AUTH_MODE` | 行为 |
|---|---|
| `builtin`（默认） | 自带账号：TOTP 登录；`authRequired` 认 `Authorization: Bearer <token>` 或 HttpOnly cookie `admin_session`（Redis `admin:session:<token>` 命中即通过并滑动续期）；忽略外部 `X-Auth-User` |
| `sso` | 关掉自带口令，身份只看前置认证层注入的 `X-Auth-User`；`login` / `logout` / `me` 一律 404 |

- 客户端 IP 一律取 `X-Real-IP`（本服务只监听回环，`req.ip` 恒为 127.0.0.1）。
- 文件区根目录分两类保护，且只作用于根这一层：一类**不展示、整棵子树拒绝写**；一类正常展示，但根层该项不可删除 / 改名。具体名单由部署时的环境变量给定（不写进仓库）。列目录跳过符号链接与特殊文件，防逃逸。
- 终端票据校验 `/api/admin/term/verify` 只允许 `127.0.0.1` 调用；终端口令与票据只存哈希。
- 通知写入：本机直连免登录，其余走 `authRequired` 或可写接口令牌（`canWrite: true`）。
- 密钥、口令、内部令牌、私有地址一律不入源码，走 config.json 或环境变量；`config.json`、`data/`、`audit.log`、`totp-secret.json` 不入库。

## 许可证

MIT
