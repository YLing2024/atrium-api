# AGENTS.md — admin-server（管理后台后端）

> 维护本仓库前先读本文件。README.md 是面向用户的介绍；冲突时以本文件为准。

## 这个项目是什么

个人网站 Admin 系统的后端（Node.js + Express 4，CommonJS）。职责：

- 系统监控：CPU / 内存 / 磁盘 / 网络实时与历史采样（内存采样器 + SSE 推送）
- 软件版本、systemd 服务状态
- 文件上传 / 下载（限 `uploads/` 内）
- **文件区**（admin「文件」Tab 的后端）：目录浏览 / 上传 / 下载 / 新建文件夹 / 重命名 / 删除，根目录由 `ADMIN_FILE_DIR` 指定
- 修改管理密码、TOTP 重置转发
- 登录设备会话管理（转发到认证中心）
- 接口令牌（API Token）管理
- **Hermes 历史会话只读浏览**（直接读 `~/.hermes/state.db`）
- **Web 终端**：口令二次验证 + 票据签发 + ttyd 会话管理

监听 `127.0.0.1:3100`（systemd `admin-server.service`），由 nginx 反代并做 SSO 探针鉴权。

## 技术栈

- Node 24（nvm v24.19.0）+ Express 4，**CommonJS**（`'use strict'`，无 TS、无构建步骤）
- `ioredis`（会话/票据/限流）、`multer`（上传）、`bcryptjs`
- `totp-auth` — 通过 `file:../totp-auth`（软链到 `auth-server/lib/totp-auth`）引入，改动它等于改认证中心模块
- SQLite 用 **Node 内置 `node:sqlite`**（只读打开 Hermes `state.db`，请求内 open→query→close），**没有 better-sqlite3 依赖**

## 目录结构

```
src/
├── index.js    # 全部路由 + 采样器 + 探针中间件（单文件，1600+ 行）
└── config.js   # config.json 读写（首次运行自动生成，含初始密码）
config.json         # 本地生成，不入库（.gitignore）
uploads/            # 上传目录，不入库
data/               # 运行时数据（用户配置/日志，可能含密钥），不入库
audit.log           # 审计日志，不入库
```

## 命令

```bash
npm install
npm start        # = node src/index.js，监听 3100
```

**没有测试、没有 lint、没有构建**。改完直接 `npm start` 或 `systemctl restart admin-server` 验证。

## 主要接口（节选）

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| POST | `/api/admin/login` | 无 | TOTP 登录（过渡期保留） |
| POST | `/api/admin/sso/verify` | 无 | 旧客户端兼容，新前端不再调用 |
| GET | `/api/admin/system` | ✅ | 系统信息快照 |
| GET | `/api/admin/system/history` | ✅ | 历史采样 |
| GET | `/api/admin/system/stream` | ✅ | SSE 实时推送 |
| GET | `/api/admin/versions` | ✅ | 软件版本 |
| GET | `/api/admin/services` | ✅ | systemd 服务状态 |
| POST | `/api/admin/upload` | ✅ | multipart，字段名 `file`（上限 100MB） |
| GET | `/api/admin/download?path=` | ✅ | 仅限 `uploads/` 内 |
| GET | `/api/admin/files?path=` | ✅ | 文件区列目录（`{ path, parent, entries[] }`，目录在前） |
| POST | `/api/admin/files/upload?path=` | ✅ | 文件区上传（上限 500MB，保留原始文件名，重名加 `-2`） |
| GET | `/api/admin/files/download?path=` | ✅ | 文件区下载 |
| POST | `/api/admin/files/mkdir` | ✅ | 新建文件夹（body `{ path, name }`） |
| POST | `/api/admin/files/rename` | ✅ | 重命名（body `{ path, name }`） |
| DELETE | `/api/admin/files?path=` | ✅ | 删除文件或目录（目录递归） |
| POST | `/api/admin/password` | ✅ | 修改密码（≥8 位），同步写回 config.json |
| GET | `/api/admin/history[/:id]` | ✅ | Hermes 会话只读浏览 |
| `*` | `/api/admin/sessions*` | ✅ | 转发认证中心 `/api/sessions` |
| GET/POST/DELETE | `/api/admin/api-tokens` | ✅ | 接口令牌管理 |
| POST | `/api/admin/term/unlock` | ✅ | 校验终端口令 → 下发 12h 票据 |
| GET | `/api/admin/term/verify` | 仅本机 | ttyd wrapper 校验票据（127.0.0.1） |
| GET/POST/DELETE | `/api/admin/term/sessions` | ✅ | 终端会话列表 / 关闭 |

## 鉴权模型

1. **主路径**：nginx `auth_request /auth-check` → 认证中心 `127.0.0.1:3200/api/verify` → 通过后注入 `X-Auth-User` 头 → 本服务 `authRequired` 信任该 header。
2. **降级**（过渡期）：`X-Auth-User` 缺失时回退 Redis 会话校验（`Authorization: Bearer` 或 `?token=`，key 前缀 `admin:session:`，12h 滑动续期）。
3. 客户端 IP 一律用 `clientIp()` 读 **`X-Real-IP`**（`req.ip` 恒为 127.0.0.1 会导致限流退化成全局桶、审计日志丢真实 IP）。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` / `HOST` | `3100` / `127.0.0.1` | systemd 里设置了 `HOST=127.0.0.1` |
| `ADMIN_CONFIG_PATH` | `../config.json` | 配置文件路径 |
| `ADMIN_UPLOAD_DIR` | `../uploads` | 上传目录 |
| `ADMIN_FILE_DIR` | `/root/files/download` | 文件区根目录（admin「文件」Tab；所有路径严格限制在其内） |
| `ADMIN_AUDIT_LOG` | `../audit.log` | 审计日志 |
| `HERMES_STATE_DB` | `~/.hermes/state.db` | 历史浏览数据源（测试用可覆盖隔离） |
| `AUTH_CENTER_BASE_URL` / `AUTH_CENTER_VERIFY_URL` | 认证中心 | 转发与探针地址 |
| `ADMIN_REDIS_PREFIX` | 见代码 | Redis key 前缀（测试实例隔离） |
| `ADMIN_TERM_PW_FILE` | `/root/.hermes/term_password` | 终端口令哈希文件（`sha256$<salt>$<hash>`，600） |

## 安全红线

- **绝不硬编码任何密钥 / 密码 / 私有域名**：全部走 config.json 或环境变量。`config.json`、`data/`、`audit.log` 已被 `.gitignore` 拦截，**不要把真实值提交进仓库**。
- 🔒 **`audit.log.1` 目前是未跟踪的游离文件**（`git status` 可见）：改动审计相关代码时顺手清理，不要把日志轮转产物提交上去。
- 下载接口必须校验路径落在 `uploads/` 内（防路径穿越）。
- 终端票据校验：`/api/admin/term/verify` **只应允许 127.0.0.1 调用**，改动时不要放宽。
- 日志/错误信息里不得输出 token 明文。

## 已知坑

- **单文件大块头**：所有路由都在 `src/index.js`。改动时按注释分区定位，别整体重排（会产生巨大 diff）。
- 🔴 **nginx 侧有两条与大文件上传相关的硬约束**（2026-09-14 踩坑，改配置前必读）：
  1. `/api/admin/` 的 `client_max_body_size` 是 **100m**，文件区上传走的是单独加的 `location /api/admin/files/upload`（**512m**）。新增任何接收大 body 的接口，都要确认它落在哪个 location、那个 location 的上限是多少——**nginx 先于应用层拒绝，返回的是 HTML 而不是 JSON**。
  2. **`/auth-check` 探针 location 必须显式写 `client_max_body_size 0;`**。SSO 探针是个子请求，它**不会**继承父 location 的上限，而是用全局默认 **1m**——不写这行，任何 >1MB 的上传都会在鉴权阶段被 413 掉（表现为 500 + `auth request unexpected status: 413`）。
  3. 别在该 location 上加 `proxy_request_buffering off;`：`auth_request` 要求请求体先缓冲，关掉后**连 5MB 都传不上去**（会 500）。
- 历史浏览用 **`node:sqlite` 只读打开**，不要改成可写或长连接持有（Hermes 网关正在写同一个库）。
- 采样器有 Redis/文件锁（`ADMIN_SAMPLER_LOCK`）防多实例重复采样；测试实例务必改锁与前缀，否则会和线上互相干扰。
- 无热重载：改完必须重启进程才生效。
- 这是 **CommonJS**，不要混用 `import` 语法。

## 部署

```bash
systemctl restart admin-server      # WorkingDirectory=/root/proj/admin-server
systemctl status admin-server
journalctl -u admin-server -n 100 --no-pager
```

nginx 层：`/api/admin/*` → `127.0.0.1:3100`；免鉴权白名单 `login|sso/verify|totp/setup|totp/reset`；其余走探针。

## 项目记忆（PROJECT_MEMORY.md）

`PROJECT_MEMORY.md` 用于保存可演进的项目记忆；`AGENTS.md` 保持为稳定的硬规则。处理非简单任务，或任务涉及既有业务判断、Hermes 状态库与探针协议、API 参数、历史 bug、产品/UI 习惯时，先按关键词查阅 `PROJECT_MEMORY.md`。

- Agent 可以**自迭代** `PROJECT_MEMORY.md`：当前任务中确认了可复用、长期有效的项目经验后，应追加或更新对应条目。
- 每条记忆必须写明日期、适用范围和可追溯证据（源码路径/行号、Hermes 协议字段与实测响应对照、提交或验证结果）；可能过期的结论须标明复核条件。
- 不记录临时猜测、单次偶发现象、未经验证的产品判断、敏感信息或与项目无关的个人偏好。
- `PROJECT_MEMORY.md` 与 `AGENTS.md` 冲突时，以 `AGENTS.md` 为准；只有经明确确认的、长期稳定且必须遵守的规则，才能由用户决定升级到 `AGENTS.md`。
- 本文件已在 `.gitignore` 中忽略：**只存本机，不提交、不推送**。
