# AGENTS.md — admin-server（管理后台后端）

> 维护本仓库前先读本文件。README.md 是面向用户的介绍；冲突时以本文件为准。

## 这个项目是什么

个人网站 Admin 系统的后端（Node.js + Express 4，CommonJS）。职责：

- 系统监控：CPU / 内存 / 磁盘 / 网络实时与历史采样（内存采样器 + SSE 推送）
- 软件版本、systemd 服务状态
- 文件上传 / 下载（限 `uploads/` 内）
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
| POST | `/api/admin/upload` | ✅ | multipart，字段名 `file` |
| GET | `/api/admin/download?path=` | ✅ | 仅限 `uploads/` 内 |
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

## 项目记忆（PROJECT_MEMORY.md · 自迭代 · 不入库）

仓库根目录的 `PROJECT_MEMORY.md` 是**只存在于本机的项目记忆**，跨会话累积。与本文档分工：**AGENTS.md 记「当前事实与铁律」，PROJECT_MEMORY.md 记「过程与理由」**。

**它自迭代——你随时可以写进去，不必请示，也不需要用户批准：**

- 用户/维护者在本项目新立的规矩（命名、文案口径、设计令牌、流程约束）
- 排查确认的结论与有效验证命令（「这个报错其实是 X 导致的」）
- 决策背景：为什么选 A 不选 B、哪个方案被否决过及原因
- AGENTS.md 里没有、但下次会省时间的一切

**约束：**

- 已在 `.gitignore` 中忽略，**不提交、不推送**（`git status` 里也不该出现）。因此可以放心写内部信息（真实域名、绝对路径、内部地址），但**禁止写入密钥 / token 明文**
- 追加式记录、**最新在上**、每条带日期；不要回头改写或删除历史条目
- 文件不存在时按此骨架创建：

```markdown
# PROJECT_MEMORY — <项目名>
> 本机项目记忆，已被 .gitignore 忽略，不提交。

## 用户/维护者立下的规矩
## 决策与理由
## 踩坑与验证配方
```
