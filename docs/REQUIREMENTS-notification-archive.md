# 需求书：通知中心「归档 + 富内容」改造

> 状态：待实现（2026-10-15）
> 读者：执行本任务的编码代理。**本文件自包含**，看完即可动手；配套规则见 `AGENTS.md`（冲突以 `AGENTS.md` 为准，本文件不放宽任何红线）。

## 1. 背景与目标

个人自托管的通知体系里，原来的移动端（Flutter `home-admin`，已归档停维）带 IM 消息流；现在 IM 客户端没有了，
用户要求把通知体系改成：

1. **每条通知都归档到 admin 后台的通知页面**，方便回溯（不再依赖移动端）；
2. 通知内容**以"美观的网页"呈现** —— 每条通知是个可打开的详情页，正文支持 Markdown，**支持内联图片**（定时任务生成的报告图 / 截图直接看）；
3. 通知**同时**继续由外部渠道（IM，由 Hermes 侧脚本负责）推送 —— 本任务只负责**归档侧**；
4. 适用对象：**所有定时任务**（服务器运维 + 个人秘书两类来源）。

现状（已核实）：

- 后端 `admin-server` 已有通知中心：`data/notifications.db`（SQLite，`notifications` + `notification_types` 两表），
  路由在 `src/routes/notifications.ts`（写入 / 列表 / 类别 / 已读 / 删除 / 批量删除 / 统计 / SSE），读写语义在 `src/notifications/store.ts`，广播在 `src/notifications/sse.ts`。
- 写入契约：`POST /api/admin/notifications`，body `{ level?, type?, source, title, body?, link?, dedupKey? }`，
  鉴权 `notificationsWriteAuth`（**本机直连回环** 或 **canWrite=true 的接口令牌**）；level ∈ `urgent|normal|digest`；`type` 缺省用 `source`，未注册自动注册。
- 库内已有 74 条、8 个类别；正文目前**只有纯文本**，**没有附件/图片**，前端**没有通知页**；保留期硬编码 30 天。
- 前端 `admin-web`：React18 + Vite + TS + **antd**（B 端一律 antd 默认设计语言）；Markdown 渲染已有依赖 `marked` + `dompurify`。

## 2. 后端改造（`admin-server`）

### 2.1 附件（图片）支持 —— 新增

写入接口 `POST /api/admin/notifications` 的 body **新增可选字段** `attachments`：

```jsonc
{
  "level": "normal", "type": "cron", "source": "quota-monitor",
  "title": "OpencodeGo 额度变化",
  "body": "## 变化\n- GLM-5.2 月额度 $40 → $60",   // Markdown 原文，服务端只存不渲染
  "link": "https://admin.example.com/#/notifications/12",   // 可选
  "dedupKey": "quota-opencodego-20261015",                  // 可选，沿用现语义
  "attachments": [                                          // 可选，最多 4 个
    { "name": "report-opencodego.png", "mime": "image/png", "dataBase64": "iVBORw0K..." }
  ]
}
```

约束与行为：

- `attachments` 最多 **4** 个；单个解码后 ≤ **8 MB**；合计 ≤ **20 MB**；超限 → `413 {error:"附件过大"}`（或 400，二选一，保持全接口一致）。
- 允许的 `mime`：`image/png`、`image/jpeg`、`image/webp`、`image/gif`、`application/pdf`、`text/markdown`、`text/plain`；其它 → `400`。
- `name` 必须经过**安全化**：仅保留 basename，替换 `[^A-Za-z0-9._-]` 为 `_`，长度 ≤ 80，去首部 `.`；同一通知内重名自动加 `-2`；**绝不能**用客户端给的路径。
- 落盘位置：`path.join(dirname(NOTIFICATIONS_DB_FILE), 'notification-files', String(id), safeName)`，目录 0700、文件 0600。
  目录可被 `ADMIN_NOTIFICATION_FILES_DIR` 覆盖（默认如上）。
- 写入顺序：先 `writeNotification()` 拿到 id，再落附件，最后返回。落附件失败**不影响**通知本身（返回 201 但 `attachmentsWarnings` 里说明），并在 stdout `console.warn` 记一行（不含敏感内容）。
- 响应扩展为：`201 { id, ts, attachments: [{name, mime, size, url}] }`（无附件时 `attachments: []`；**既有字段 id/ts 不变**）。
- **`dataBase64` 不得进日志/审计**。

### 2.2 单条详情 —— 新增

`GET /api/admin/notifications/:id`（`authRequired`）→

```jsonc
{
  "item": {
    "id": 12, "ts": 1760500000, "level": "normal", "source": "quota-monitor", "type": "cron",
    "title": "…", "body": "…markdown…", "link": "…", "readAt": null,
    "attachments": [{ "name": "report.png", "mime": "image/png", "size": 612345,
                      "url": "/api/admin/notifications/12/files/report.png" }]
  }
}
```

- 不存在 → `404 {error:"通知不存在"}`。
- **列表接口** `GET /api/admin/notifications` 的每个 item 也带上同名 `attachments` 字段（列表只回元信息 + url，不回二进制），
  并附加 `hasImage: true|false` 方便前端列表显示图片标记。**不得**破坏既有字段。

### 2.3 附件读取 —— 新增

`GET /api/admin/notifications/:id/files/:name`（`authRequired`）：

- 只允许读 `notification-files/<id>/` 内的文件；`name` 必须与落盘文件名**精确匹配**（先解码 URI、再 `path.basename` 比对并做 `path.resolve` 前缀校验，防穿越）。
- 响应：`Content-Type` 用入库 mime；`Content-Disposition: inline; filename="…"`；`Cache-Control: private, max-age=3600`。
- 未命中 → `404`；`id`/`name` 非法 → `400`。

### 2.4 保留期与清理

- 保留期从硬编码 30 天改为 **env 可配**：`ADMIN_NOTIFICATION_RETENTION_DAYS`，默认 **180**（`NOTIFICATIONS_RETENTION_SECONDS` 由此计算，保持既有常量名可用，避免大范围改动）。
- `cleanupNotifications()` 删除过期通知时，**同步删除** `notification-files/<id>/` 整个目录（先查 id 再删文件再删行；删文件失败只 `console.warn`，不阻断）。
- 保留「启动一次 + 每小时一次」的既有节奏。

### 2.5 其它后端约束

- 该写入路由需提高 body 上限：**只对通知写入路由**挂 `express.json({ limit: '24mb' })`（默认 100kb 会拒掉图片），**不要**全局放大。
- 不新增任何 npm 依赖（`multer` 已存在但本需求用 base64，不必用）。
- 不动既有路由契约、不动鉴权模型（`AUTH_MODE`）、不动 `notificationsWriteAuth` 的放行规则。
- 审计沿用现有风格：只记 `id` / 条数 / 失败原因，**绝不记正文、附件名之外的 body、dataBase64**。
- `npm run check`（typecheck + lint + test）必须通过；为 store 的新函数补 `node:test` 单测（至少：附件安全化命名、重名加后缀、过期清理含附件目录、列表带 attachments 字段）。
- 顺手清理仓库根目录那个游离的 `notifications.db`（未跟踪文件，实际库在 `data/notifications.db`）——不要提交它。

## 3. 前端改造（`admin-web`）—— **改造既有通知页，不要新建任何组件**

**现状（已核实 2026-10-15）**：通知前端已存在且可用，本需求在前端**只补"图片/附件"**：

- `src/components/NotificationCenter.tsx` —— 通知展示/阅读页：antd `List` + 筛选（级别 / 类别，类别走 `/types` 动态取）+ 单条已读 / 删除 + 桌面通知开关 + 顶部 SSE 状态点；
  SSE 走**全站单例** `src/notificationStream.ts`；正文用 `src/components/MarkdownBody.tsx` 渲染 Markdown。页面在 `Main.tsx` 中常驻挂载（只切显隐）。
- `src/components/NotificationManage.tsx`（通知管理：批量删除 / 统计等）、`src/components/NotificationDebug.tsx`（调试）。
- `src/components/Main.tsx` 已挂载上述组件。

**要做的（只此四条）**：

1. `src/api.ts`：`NotificationItem` 类型补 `attachments?: { name: string; mime: string; size: number; url: string }[]` 与 `hasImage?: boolean`；
   新增 `getNotification(id)` → `GET /api/admin/notifications/:id`（返回 `{ item }`）。
   **只加，不改**既有请求封装、鉴权流程与全局 401 出口。
2. `NotificationCenter.tsx`：
   - 列表行：`hasImage` 为真时显示一个**图片标记**（antd 图标或小 `Tag`，**不得用 emoji**）；
   - 阅读区：正文下方渲染 `attachments`——图片用 antd `Image`（`src={url}`、宽度自适应容器、点击可放大预览）；非图片附件给下载链接（`<a href={url}>`）；
   - 附件 url 是**后端返回的相对路径**，直接使用、不要拼域名；图片请求需带站点既有凭证（SSE/接口同源，沿用现有做法即可）。
   - **不得改动**：`notificationStream.ts`、`MarkdownBody.tsx`、SSE 行为、已读/删除/桌面通知/筛选逻辑。
3. `NotificationManage.tsx`：若列表里会展示条目，补一个"有图"标记（可选，不强求）。
4. 约束：antd 默认 token；文案克制、**禁 emoji**；**不新增依赖**；不改公开页 `PublicApps.tsx` / `AppCard.tsx` / `AppIcon.tsx`；
   验证构建用独立输出目录 `BUILD_OUT_DIR=/tmp/admin-web-verify npx vite build --emptyOutDir`；改完跑 `npm run check`。

**明确不要做**：新建 `Notifications.tsx` 之类的重复组件；重写通知页；改 SSE；改鉴权；新建 Tab。

## 4. 验收标准（由提出需求的人执行）

1. 脚本侧写入一条带 PNG 附件的通知（回环直连）→ 库里出现该行，附件落在 `data/notification-files/<id>/`（权限 0600）。
2. 浏览器打开后台**通知页**：列表能看到该条（有图标记），阅读区能看到图片（可点开放大）与 Markdown 正文；刷新后仍在。
3. 「全部已读」「按筛选批量删除（含 dryRun 二次确认）」行为正确，未读徽标随之更新。
4. 类别筛选来自后端 types 接口（新增类别后无需改前端即可出现）。
5. 把保留期环境变量设为 1 天并用一条老数据验证：清理后通知行与其附件目录一并消失。
6. `npm run check` 两个仓库都通过；既有接口回归无损（列表/统计/SSE/删除字段不变）。

## 5. 不在本需求内（由提出需求的人另行处理）

- IM（飞书）推送本身、以及把 6 个定时任务 + 秘书任务改为「出图 + 归档 + 推送」的统一发送器；
- 移动端 Flutter 仓库（已归档，不再改动）。
