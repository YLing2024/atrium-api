# admin-server

个人网站 Admin 系统后端：系统监控（CPU/内存/磁盘/网络/服务状态）、文件上传下载、修改密码、历史会话只读浏览。监听 `127.0.0.1:3100`（systemd: `admin-server.service`）。

## 项目作用

- REST：`/api/admin/system`、`/api/admin/system/history`、`/api/admin/services`、`/api/admin/versions`、`/api/admin/upload`、`/api/admin/download`、`/api/admin/password`
- 历史浏览（只读）：`/api/admin/history`（会话列表）、`/api/admin/history/:id`（会话消息），数据源为 Hermes `~/.hermes/state.db`（`node:sqlite` 只读打开，请求内 open→query→close）
- 登录：`GET /api/admin/auth-mode` 探测模式。`builtin`（默认）走本服务自带 TOTP 登录；`sso` 关掉自带口令，管理端身份由 `X-Auth-User` 决定（见「认证（AUTH_MODE）」）

## 认证（AUTH_MODE）

默认自带账号口令（TOTP）开箱即用；也可以关掉自带口令。

| 模式 | 说明 |
|---|---|
| `builtin`（默认） | 自带账号 + 登录页，开箱即用 |
| `sso` | 关掉自带口令，管理端身份由 `X-Auth-User` 决定——自家项目接 SSO 时走这一档 |

关掉后的登录跳转与 401 由你前面的认证层决定，本服务不再展开。

- 模式探测：`GET /api/admin/auth-mode`（免鉴权）→ `{"authMode":"builtin"|"sso"}`。
- `builtin`：`POST /api/admin/login`（TOTP 动态码，成功下发 HttpOnly 会话 cookie）、`POST /api/admin/logout`、`GET /api/admin/me`。
- 接口令牌（API Token）通道两种模式都保留。

## 运行

```bash
cd /root/proj/admin-server
npm install
node --check src/index.js
systemctl restart admin-server     # 或 npm start
