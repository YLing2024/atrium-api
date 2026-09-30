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

监听 `127.0.0.1:3100`（systemd `admin-server.service`）。默认自带账号口令，也可用 `AUTH_MODE=sso` 关掉自带口令、交给前置认证层（见「认证模型（AUTH_MODE）」）。

## 技术栈

- Node 24（nvm v24.19.0，`.nvmrc` 已钉）+ Express 4，**TypeScript**（CommonJS 语法，Node 直接执行 `.ts`，**无构建步骤**）
- `ioredis`（会话/票据/限流）、`multer`（上传）、`bcryptjs`
- `totp-auth` — 通过 `file:../totp-auth`（软链到 `auth-server/lib/totp-auth`）引入，改动它等于改认证中心模块
- SQLite 用 **Node 内置 `node:sqlite`**（只读打开 Hermes `state.db`，请求内 open→query→close），**没有 better-sqlite3 依赖**

## 目录结构

```
src/
├── index.ts            # 入口：依赖装配 + 路由挂载 + 启动（无业务逻辑）
├── config.ts           # config.json 读写（首次运行自动生成，含初始密码）
├── db.ts               # SQLite 单例与建表（metrics.db / notifications.db，用 node:sqlite）
├── state.ts            # Redis 单例与 key 前缀
├── util.ts             # 通用工具（时间/格式化/HTTP 状态映射等纯函数）
├── apps.ts             # 应用面板：登记表读取 + 探活采集
├── middleware/
│   ├── auth.ts         # 认证中间件（builtin 会话 / sso 网关注入 Header）
│   └── errors.ts       # 错误处理与 404
├── probe/              # 探活采集
│   ├── system.ts       #   系统指标采样
│   └── services.ts     #   systemd/docker 服务状态
├── metrics/            # 指标留样与聚合
│   ├── store.ts        #   写入与留存
│   ├── proctop.ts      #   进程排行
│   └── aggregate.ts    #   分钟/小时/天物化桶
├── notifications/
│   ├── store.ts        #   通知表读写
│   └── sse.ts          #   SSE 流
└── routes/             # 全部 HTTP 路由（每个 router 内部写完整路径，根挂载）
    ├── system.ts  auth.ts  api-tokens.ts  notifications.ts  versions.ts
    └── term.ts  apps.ts  files.ts  shares.ts  history.ts
test/                   # node:test 单测（33 例：探活归一化、状态映射、登记表扫描过滤、聚合口径等）
apps.example.json   # 应用登记表样例（占位值，入库；复制到 data/apps.json 使用）
config.json         # 本地生成，不入库（.gitignore）
uploads/            # 上传目录，不入库
data/               # 运行时数据（用户配置/日志，可能含密钥），不入库
audit.log           # 审计日志，不入库
```

**新增一层时的规矩**：路由加在对应 `routes/*.ts`（内部写完整路径）；跨层共享的东西放 `util.ts`，别让 `db.ts`/`state.ts` 反向依赖 `routes/`。改动后必须 `npm run check`。

## 命令

```bash
npm install
npm start        # = node src/index.ts，监听 3100
npm run check    # typecheck + lint + test（改完代码先跑这个）
```

**无构建步骤**（Node 直接执行 TS）；单测用 Node 内置 `node:test`，ESLint 只开正确性规则。改完再 `systemctl restart admin-server` 验证线上。

## 主要接口（节选）

| 方法 | 路径 | 鉴权 | 说明 |
|---|---|---|---|
| GET | `/api/admin/auth-mode` | 无 | 模式探测 → `{"authMode":"builtin"\|"sso"}` |
| POST | `/api/admin/login` | 无 | `builtin` 专属：TOTP 登录，成功下发会话 cookie；`sso` → 404 |
| POST | `/api/admin/logout` | 无 | `builtin` 专属：删会话 + 清 cookie（幂等）；`sso` → 404 |
| GET | `/api/admin/me` | ✅ | `builtin` 专属：`{name, role}`；`sso` → 404 |
| GET | `/api/admin/system` | ✅ | 系统信息快照 |
| GET | `/api/admin/system/history` | ✅ | 历史采样 |
| GET | `/api/admin/system/stream` | ✅ | SSE 实时推送 |
| GET | `/api/admin/versions` | ✅ | 软件版本 |
| GET | `/api/admin/services` | ✅ | systemd 服务状态 |
| GET | `/api/admin/apps` | ✅ | 应用面板：登记表全部应用 + 实时探活（`?refresh=1` 绕过 10s 缓存）；只读 |
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
| `*` | `/api/admin/sessions*` | ✅ | 身份取 `X-Auth-User`，用 `X-Internal-Token` 转发认证中心内部接口 `/api/internal/sessions*` |
| POST | `/api/admin/totp/reset` | ✅ | TOTP 两阶段重置①：取 `X-Auth-User`，用 `X-Internal-Token` 调 `/api/internal/totp/reset?sub=`（不转发客户端凭证） |
| POST | `/api/admin/totp/confirm` | ✅ | TOTP 两阶段重置②：body `{code}`，同上调 `/api/internal/totp/confirm?sub=` |
| GET/POST/DELETE | `/api/admin/api-tokens` | ✅ | 接口令牌管理 |
| POST | `/api/admin/term/unlock` | ✅ | 校验终端口令 → 下发 12h 票据 |
| GET | `/api/admin/term/verify` | 仅本机 | ttyd wrapper 校验票据（127.0.0.1） |
| GET/POST/DELETE | `/api/admin/term/sessions` | ✅ | 终端会话列表 / 关闭 |

## 应用面板（Apps Panel）

admin「应用」Tab 的后端：一个**只读**面板，把本机应用集中展示 + 实时探活。不启停服务、不改配置。

- **接口**：`GET /api/admin/apps`（`authRequired`）。`?refresh=1` 跳过 10s 模块级缓存；并发请求单飞复用同一 Promise。
  响应字段：`generatedAt / cached / ttlSeconds / registryPath / registryMtime / notice / warning / categories[] / apps[] / discovered[]`。
- **登记表**：`data/apps.json`（`ADMIN_APPS_FILE` 覆盖，默认 `<repo>/data/apps.json`）。**只读消费，不存在不自动生成**；
  `mtime` 变化即重读（改登记表无需重启）。样例见 `apps.example.json`（占位值）。缺失 → `200 + apps:[] + notice`；解析失败 → `500 + {error}`。
- **schema**：顶层 `version / updated / ignorePorts[] / ignoreProcesses[] / categories[] / apps[]`。
  `categories[] = {id,name}`；`apps[]` 字段：`id`(唯一，`^[a-z0-9][a-z0-9-]{0,31}$`)、`name`(≤16 字)、`category`、
  `desc`(≤24 字)、`url`、`icon`(图标名，字符串；缺省/null 时前端回退 name 首字)、`onDemand`(布尔，默认 `false`；按需唤醒应用)、
  `port`、`unit`(systemd)、`container`(docker)、`probe`、`tags`、`hidden`。重复 id 保留第一条并记 `warning`；未知 category 归入「其他」。
- **探活**：优先级 `probe > container > unit > port(tcp) > 无(unknown)`。
  `probe` 形如 `{type:"http",target,expect?}` / `{type:"systemd",unit}` / `{type:"docker",container}` / `{type:"tcp",port}`。
  状态：`up`（2xx/3xx 或 expect 命中 / systemd active / docker running / tcp 通）、`auth`（http 401/403）、
  `degraded`（http 5xx 或超时 / activating|reloading / restarting|paused）、`down`、`unknown`。
  另有 `idle → 休眠（按需唤醒应用当前未运行，非故障）`：仅当 `onDemand:true` 且探活结果为 `down` 时归入，不计入宕机；
  `onDemand` 不改变 up / auth / degraded 等任何其它判定。
  单条超时 1500ms，全部 `Promise.allSettled` 并行；单条异常只影响该条（`status:"down"`）。
- **未登记发现**：`ss -ltnp` 取 `127.0.0.1:` 监听行，排除 `ignorePorts` / `ignoreProcesses`（进程名正则，滤掉 chrome、agent-browser 这类端口每次都在变的工具监听）/ 已登记 `port` / `docker-proxy`，按端口升序最多 30 条；解析失败返回 `[]`，不影响 `apps`。
- **审计**：`apps_list` 只记条数 / 耗时 / 失败条数，**不记录登记表里的 `url`**（可能含内网地址）。

## 认证模型（`AUTH_MODE`）

默认自带账号口令，开箱即用；也可以关掉自带口令。

| `AUTH_MODE` | 行为 |
|---|---|
| `builtin`（默认） | 自带账号 + 登录页；`authRequired` 认本服务会话（`Authorization: Bearer <token>` 或 HttpOnly cookie `admin_session`，Redis `admin:session:<token>` 命中即通过并滑动续期）；**忽略外部 `X-Auth-User`**，不因外部头提权 |
| `sso` | 关掉自带口令，管理端身份由 `X-Auth-User` 决定——自家项目接 SSO 时走这一档；`authRequired` 只认该头 |

关掉后的登录跳转与 401 由你前面的认证层决定，本服务不再展开。

- 模式探测：`GET /api/admin/auth-mode`（免鉴权）→ `{"authMode":"builtin"|"sso"}`；取值非法/未设置按 `builtin`，启动时 stdout 打印一行当前模式。
- `builtin` 独有：`POST /api/admin/login`（TOTP，成功除 `{token}` 外下发 HttpOnly cookie `admin_session`）、`POST /api/admin/logout`（删 Redis 会话 + 清 cookie，幂等）、`GET /api/admin/me` → `{name, role}`。`sso` 下这三者一律 `404`（不 401/302）。
- 与模式无关、保持现状：接口令牌（`api:token:<sha256>`）通道；通知写入回环/可写令牌通道；设备会话 `/api/admin/sessions*` 与 TOTP 重置 `/api/admin/totp/*` 经内部令牌 `X-Internal-Token` 调认证中心 `/api/internal/*`（令牌只读、不打印、不返回）。
- 客户端 IP 一律用 `clientIp()` 读 **`X-Real-IP`**（`req.ip` 恒为 127.0.0.1 会导致限流退化成全局桶、审计日志丢真实 IP）。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` / `HOST` | `3100` / `0.0.0.0`（代码默认） | systemd 单元里设置 `HOST=127.0.0.1`，只监听回环 |
| `AUTH_MODE` | `builtin` | 认证模式：`builtin`（自带账号 + 登录页）/ `sso`（关掉自带口令，只看 `X-Auth-User`）；非法/未设置按 `builtin` |
| `ADMIN_CONFIG_PATH` | `../config.json` | 配置文件路径 |
| `ADMIN_UPLOAD_DIR` | `../uploads` | 上传目录 |
| `ADMIN_FILE_DIR` | `/root/files/download` | 文件区根目录（admin「文件」Tab；所有路径严格限制在其内） |
| `ADMIN_APPS_FILE` | `../data/apps.json` | 应用面板登记表路径（admin「应用」Tab；只读消费，不存在不自动生成） |
| `ADMIN_AUDIT_LOG` | `../audit.log` | 审计日志 |
| `HERMES_STATE_DB` | `~/.hermes/state.db` | 历史浏览数据源（测试用可覆盖隔离） |
| `AUTH_CENTER_BASE_URL` | 无默认 | 认证中心基址（转发设备会话 `/api/admin/sessions*` 与 `/api/admin/totp/*` 用）；未配置时相关接口返回 502 |
| `AUTH_CENTER_INTERNAL_TOKEN_FILE` | `../../auth-server/internal-token` | 认证中心内部令牌文件（`X-Internal-Token`，0600）；只读、不打印、不返回 |
| `ADMIN_REDIS_PREFIX` | 见代码 | Redis key 前缀（测试实例隔离） |
| `ADMIN_TERM_PW_FILE` | `/root/.hermes/term_password` | 终端口令哈希文件（`sha256$<salt>$<hash>`，600） |

## 安全红线

- **绝不硬编码任何密钥 / 密码 / 私有域名**：全部走 config.json 或环境变量。`config.json`、`data/`、`audit.log` 已被 `.gitignore` 拦截，**不要把真实值提交进仓库**。
- 🔒 **`audit.log.1` 目前是未跟踪的游离文件**（`git status` 可见）：改动审计相关代码时顺手清理，不要把日志轮转产物提交上去。
- 下载接口必须校验路径落在 `uploads/` 内（防路径穿越）。
- 终端票据校验：`/api/admin/term/verify` **只应允许 127.0.0.1 调用**，改动时不要放宽。
- 日志/错误信息里不得输出 token 明文。

## 已知坑

- **改哪一层去哪个文件**：路由 → `src/routes/<业务线>.ts`（内部写完整路径，`index.ts` 根挂载）；探活 → `src/probe/`；指标留样/聚合 → `src/metrics/`；通知 → `src/notifications/`；中间件 → `src/middleware/`；纯工具 → `src/util.ts`。单文件 3558 行的时代已结束（2026-09-30 拆分），改一处不必再全文件通读——但**别把新逻辑塞回 `index.ts`**，它只做装配。
- **大重构前先建安全网**：本仓库有一份「全路由快照比对」脚本（49 路由 / 73 变体 / 7 探针，含真 TOTP 登录取真凭证 + 响应归一化 diff），做法见本地项目笔记。重构前后各跑一次，差异必须能逐条解释。⚠️ 抽路由的工具**必须按目录扫 `src/`**（只读 `index.ts` 会漏掉 `routes/*` 里的全部路由，2026-09-30 踩过）。
- 🔴 **nginx 侧与大文件上传相关的硬约束**（2026-09-14 踩坑，改配置前必读）：
  1. `/api/admin/` 的 `client_max_body_size` 是 **100m**，文件区上传走的是单独加的 `location /api/admin/files/upload`（**512m**）。新增任何接收大 body 的接口，都要确认它落在哪个 location、那个 location 的上限是多少——**nginx 先于应用层拒绝，返回的是 HTML 而不是 JSON**。
  2. ~~`/auth-check` 探针 location 必须显式写 `client_max_body_size 0;`~~ —— **探针已废弃（2026-09-28 改由 Auth Gateway 鉴权），本坑不再适用**。网关自行处理请求体，不再有「子请求不继承父 location 上限」的问题。
  3. ~~别在探针 location 上加 `proxy_request_buffering off;`~~ —— 同上，`auth_request` 子请求机制已不存在，本坑不再适用。
- 历史浏览用 **`node:sqlite` 只读打开**，不要改成可写或长连接持有（Hermes 网关正在写同一个库）。
- 采样器有 Redis/文件锁（`ADMIN_SAMPLER_LOCK`）防多实例重复采样；测试实例务必改锁与前缀，否则会和线上互相干扰。
- 无热重载：改完必须重启进程才生效。
- 这是 **CommonJS**（`require` / `module.exports`）；类型导入用 `import type`（会被原样剥离，不产生运行时 import）。

## 部署

```bash
systemctl restart admin-server      # WorkingDirectory=/root/proj/admin-server
systemctl status admin-server
journalctl -u admin-server -n 100 --no-pager
```

nginx 层：`/api/admin/*` → 反代 `127.0.0.1:3100`（认证方式见「认证模型（AUTH_MODE）」；默认 `builtin` 自带账号，`sso` 时由前置认证层决定）。

## 项目记忆（PROJECT_MEMORY.md）

**分工**：`AGENTS.md` 记**规则**（稳定、必须遵守）；`PROJECT_MEMORY.md` 记**记忆**（可演进、随事实更新）。
两者冲突时以 `AGENTS.md` 为准；只有经用户明确确认、且长期稳定的规则，才由用户决定升级进 `AGENTS.md`。
`PROJECT_MEMORY.md` 已被 `.gitignore` 拦截：**只存本机，不提交、不推送**。

### 什么时候写

- 读完代码 / 查完日志后，**确认了可复用、长期有效**的结论：API 契约与参数语义、数据模型与单位、踩坑的根因、
  产品与 UI 习惯、历史 bug 的判据（"见到 X 现象就查 Y"）。
- **任务收尾时必须回写**：本次确认了什么、推翻了什么、遗留了什么（写清复核条件）。
- **不要写**：临时猜测、单次偶发现象、未经验证的产品判断、敏感信息（密钥 / token / 口令 / 私有地址）、
  与项目无关的个人偏好、以及从代码一眼可见的常识。

### 每条记忆的字段（缺一不可）

```md
### YYYY-MM-DD · 主题（一句话）
- **结论**：一句话说清（可执行、可判断真假）。
- **适用范围**：哪个模块 / 接口 / 页面；**不适用**的情况也要写。
- **证据**：`路径:行号` / commit / 实测输出摘要（附可复现命令）。
- **复核条件**：什么情况下这条会失效（如"升级 Flutter 大版本后重测"）。
- **最后复核**：YYYY-MM-DD
```

### 迭代规则

1. **先查后写**：任务开始时按关键词（模块名 / 接口名 / 报错文本 / 表名）检索本文件；命中就按结论行事，
   并**把该条的「最后复核」更新为今天**（同一次任务只更新一次，不要刷日期）。
2. **更新优先于新增**：主题已有条目 → 就地改写（结论变了要写"曾认为 X，实测为 Y"），**不要追加重复条目**。
3. **失效即删**：结论被推翻、或复核条件已命中（代码已改 / 版本已升）→ 直接删掉或改写，不留"已废弃"堆积。
4. **合并同类**：同一模块超过 3 条相关记忆 → 合并成一节，只保留最新结论 + 关键证据。

### 容量与清理（硬约束）

- 文件上限 **200 行 / 12 KB**（以 `wc -c` 为准）。超限时按以下优先级淘汰：
  ① 已被代码或配置取代的（先删）→ ② 「最后复核」最久远的 → ③ 证据最弱的（只有结论、没有出处）。
- 单条记忆 **≤ 15 行**；细节过长就把细节留在代码注释 / `references/` 里，本文件只留结论与指针。
- **每次写入后顺手清理一次**（行数、体积、重复项、失效项），保证文件始终处于上限内。
- 清理若删掉仍有价值的内容，必须在提交说明或对话里说明，**不要静默丢弃**。

### 写法

- 读者是**下一个接手这个仓库的人**：用最短的句子、最强的证据，先写结论再写理由。
- 结论要能被证伪：写"接口 X 的 `:id` 是数据库数字 id（`WHERE id = ?`）"，不要写"注意 id 类型"。
- 需要跨文件的长篇背景（架构选型、迁移过程）放 `references/` 或项目文档，这里只留一行指针。
