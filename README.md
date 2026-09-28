# admin-server

个人网站 Admin 系统后端：系统监控（CPU/内存/磁盘/网络/服务状态）、文件上传下载、修改密码、历史会话只读浏览。监听 `127.0.0.1:3100`（systemd: `admin-server.service`）。

## 项目作用

- REST：`/api/admin/system`、`/api/admin/system/history`、`/api/admin/services`、`/api/admin/versions`、`/api/admin/upload`、`/api/admin/download`、`/api/admin/password`
- 历史浏览（只读）：`/api/admin/history`（会话列表）、`/api/admin/history/:id`（会话消息），数据源为 Hermes `~/.hermes/state.db`（`node:sqlite` 只读打开，请求内 open→query→close）
- 登录：登录 / TOTP / SSO 全部由 Auth Gateway 负责；本服务只读网关注入的 `X-Auth-User`。TOTP 端点（`/api/admin/login` 等）保留但不再由前端引导使用

## 鉴权接入架构（Auth Gateway）

1. 用户在 Auth Gateway（Go 单二进制，`127.0.0.1:18920`，nginx 反代进来）完成登录（TOTP 在认证中心）；会话由网关的站点 cookie 持有。
2. 浏览器请求 `/api/admin/*`：nginx 交给网关，网关鉴权通过后**注入 `X-Auth-User` 头**再反代到 admin-server。
3. admin-server 的 `authRequired` **只读该头**：存在且非空 → 通过；缺失/为空 → `401 {error:'未登录'}`。
4. 前端不再存 token、不再需要认证中心地址。

### 已废弃（仅旧客户端兼容保留）

- Redis 会话（`admin:session:<token>`）与接口令牌（`api:token:<sha256>`）**不再是 `/api/admin/*` 的凭证**；
- `POST /api/admin/sso/verify` 与 nginx `auth_request /auth-check` 探针已废弃；
- 通知写入（`notificationsWriteAuth`）仍接受回环直连与可写 API Token，是独立通道。

## 运行

```bash
cd /root/proj/admin-server
npm install
node --check src/index.js
systemctl restart admin-server     # 或 npm start
