# admin-server

个人网站 Admin 系统后端：系统监控（CPU/内存/磁盘/网络/服务状态）、文件上传下载、修改密码、Hermes WS 桥接。监听 `127.0.0.1:3100`（systemd: `admin-server.service`）。

## 项目作用

- REST：`/api/admin/system`、`/api/admin/system/history`、`/api/admin/services`、`/api/admin/versions`、`/api/admin/upload`、`/api/admin/download`、`/api/admin/password`、`/api/admin/notify`
- WebSocket：`/api/admin/ws`，客户端 ⇄ Hermes(9119) JSON-RPC 双向透传
- 登录：TOTP 动态码（`/api/admin/login`，过渡期保留）+ 统一 SSO（认证中心）

## SSO 接入架构（Nginx 探针 + auth_token）

1. 用户在认证中心（auth-server，3200）完成 TOTP 登录，token 回跳给前端；
2. 前端把 token 存 `localStorage.auth_token`，所有 REST 请求带 `Authorization: Bearer <auth_token>`；
3. **REST 鉴权由 Nginx `auth_request` 探针完成**：`/auth-check` 转发到 `http://127.0.0.1:3200/api/verify`，验证通过后注入 `X-Auth-User` 头 → admin-server 信任该 header；
4. **WS 鉴权由后端完成**：`/api/admin/ws` 用 query token 调 `http://127.0.0.1:3200/api/verify?token=` 验证认证中心 token，失败关 4001。

### 鉴权降级（过渡期）

- REST：`X-Auth-User` 缺失时回退旧 **Redis 会话**校验（`Authorization: Bearer` 或 `?token=`，key 前缀 `admin:session:`，12h 滑动续期）；
- WS：认证中心 verify 失败/不可达时回退旧 Redis 会话校验；
- `POST /api/admin/sso/verify` 保留（兼容旧客户端，新前端已不再调用）。

## 运行

```bash
cd /root/proj/admin-server
npm install
node --check src/index.js
systemctl restart admin-server     # 或 npm start
```

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` | 3100 | 监听端口（测试实例 3101） |
| `HOST` | 0.0.0.0 | 监听地址 |
| `ADMIN_REDIS_PREFIX` | `admin:session:` | Redis 会话 key 前缀 |
| `AUTH_CENTER_VERIFY_URL` | `http://127.0.0.1:3200/api/verify` | 认证中心验证地址 |
| `ADMIN_NOTIFY_KEY` | 空 | 内部通知共享密钥（非本机来源需携带） |
| `ADMIN_TOTP_SECRET_FILE` | `./totp-secret.json` | TOTP secret 持久化路径 |
