# admin-server 接口文档

> 唯一权威接口文档。**与代码同一笔提交维护：改了路由不改本文件，`npm run check:api-docs` 会红。**
> 路由清单机检脚本：`scripts/check-api-docs.mjs`（从 `src/routes/*.ts` 提取实际路由，与本文
> 的 `### METHOD 路径` 标题比对，缺失/多余都非 0 退出）。

## 一、通用约定

- **基址**：本文所有示例用占位符 `$BASE_URL`，部署环境注入（如 `http://` + 反代入口）。仓库不写任何真实域名 / 内网地址。
- **内容类型**：请求与响应均为 JSON（`Content-Type: application/json`）；文件上传为 `multipart/form-data`；SSE 为 `text/event-stream`；文件下载为二进制附件。
- **鉴权凭证**：本文示例用 `$TOKEN` 占位。默认模式下为自带账号会话 token（`Authorization: Bearer <token>` 或 HttpOnly cookie `admin_session`，二者取其一）；`sso` 模式下为反代注入的 `X-Auth-User` 头。
- **错误响应**：统一 JSON `{ "error": "<中文可定位文案>" }`，部分接口附 `code` / `retryAfter`。未单独列出的错误分支按「错误码表」的通用项处理。
- **审计**：涉及写操作的接口会写 `audit.log`（记录动作、客户端 IP、成功/失败与资源标识；**绝不记录令牌明文与登记表中的 url**）。
- **时间单位**：见「数据模型约定」。
- **客户端 IP**：一律取自 `X-Real-IP`（反代注入），用于限流与审计定位。

## 二、认证模式

服务端环境变量 `AUTH_MODE` 决定鉴权通道，生产实际取值以部署环境为准（本文不写具体值）：

| `AUTH_MODE` | 语义 | 鉴权通道 |
|---|---|---|
| `builtin`（默认） | 自带账号口令：本服务自己的登录页 + 会话 cookie | `Authorization: Bearer <token>` 或 cookie `admin_session`；Redis 命中 `admin:session:<token>` 即通过并滑动续期。**忽略外部 `X-Auth-User`**（防提权） |
| `sso` | 关掉自带口令，管理端身份由前置认证层决定 | 只认反代注入的 `X-Auth-User`（网关会先剥掉客户端伪造的同名头） |

- 模式探测：`GET /api/admin/auth-mode`（免鉴权）。
- `builtin` 独有：`POST /api/admin/login`、`POST /api/admin/logout`、`GET /api/admin/me`；`sso` 下这三者一律 `404`。
- 鉴权失败一律 `401 JSON { "error": "未登录" }`（不 302、不 500）。会话存储异常为 `500 { "error": "会话服务异常" }`。
- 环境变量名：`AUTH_MODE`、`ADMIN_REDIS_PREFIX`（会话 key 前缀，测试实例隔离用）、`ADMIN_CONFIG_PATH`（配置文件路径）。具体取值由部署环境注入。

## 三、数据模型约定

### 3.1 单位与语义

| 字段（示例） | 单位 / 语义 |
|---|---|
| `mem_mb` | 进程**自身** RSS（MB，整数）；RSS 会把共享页在每个进程里各算一次 |
| `subtree_mem_mb` | 该进程**自身 + 全部后代**的 RSS 之和（MB，整数）；同样含共享页重复计算 |
| `subtree_cpu` | 该进程自身 + 全部后代的瞬时 CPU 之和（%），与 `cpu` 同源同基准 |
| `subtree_count` | 含自身的后代进程数（整数） |
| `thread_count` | 该进程的线程数（读 `/proc/<pid>/task` 条目数，整数）；进程已退出/读不到为 `null` |
| `cgroup_mem_mb` | 该 systemd 单位 cgroup 的**真值**（MB，整数，含页缓存）；与 RSS 口径不同、不可直接比 |
| `total_mem_mb` | 全部进程 RSS 之和（MB，整数）；含共享页重复计算 |
| `total_threads` | 全部进程线程数之和（整数，截断前口径）；与 `count` 是**两个口径，不得混算** |
| `total_cgroup_mb` | `system.slice` 的 cgroup 真值（MB，整数） |
| `total_cpu` | 系统**总** CPU 占用（%），**不是**列表之和 |
| `mem_percent` / `cpu.usage_percent` | 百分比（0–100） |

> 三个内存数（`total_mem_mb` / `total_cgroup_mb` / `free` 口径）都「对」，但**口径不同**：RSS 含共享页重复计算、cgroup 含页缓存。界面上必须并列标注，不能混用。

### 3.2 时间与 ID

- **时间**：`ts` / `readAt`（通知）为 **epoch 秒**；`createdAt` / `expiresAt` / `lastUsedAt`（令牌、分享）为 **epoch 毫秒**；`system.uptime` 为**秒**。一律 UTC 数值，由前端按本地时区展示。
- **ID 类型**：
  - 通知 `id`：**number**（SQLite 行 id）。
  - 接口令牌 `id`：**string**（`sha256(token)` 十六进制），令牌明文仅生成时返回一次。
  - 分享 `id`：**string**（随机短 id）；分享 `token`：**string**（随机 URL-safe）。
  - 会话 `id`：**string**（会话 token）；历史会话 `id`：**string**（Hermes 会话 id）。
  - **项目级约定**：博客等模块的**雪花 ID（`public_id`）一律为字符串，禁止转 Number**（会丢精度）；本服务当前无雪花 ID 字段，`/api/blog/*` 由别的后端提供。

## 四、系统与进程

### GET /

- 鉴权：无
- 请求参数：无
- curl：`curl -sS "$BASE_URL/"`
- 成功 200：`{ "name": "admin-server", "status": "ok" }`
- 错误：无
- 副作用：无
- 幂等：幂等；无显式限流

### GET /api/admin/system

- 鉴权：`authRequired`
- 请求参数：无
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/system"`
- 成功 200（节选；所有字段缺失时为 `null`/省略，前端需容错）：

```json
{
  "cpu": { "usage_percent": 12.3, "per_core": [{ "id": 0, "usage_percent": 8.1 }], "model": "…", "cores": 8, "loadavg": [0.5, 0.4, 0.3] },
  "memory": { "percent": 47, "used": 7239, "available": 8000, "buffCache": 2100, "free": 1000, "total": 16000,
              "swapTotal": 0, "swapUsed": 0, "swapFree": 0, "swapPercent": 0, "zram": null },
  "disk": { "mount": "/", "used": 120, "total": 500, "free": 380, "percent": 24 },
  "disks": [ { "mount": "/", "percent": 24 } ],
  "network": { "rx_rate": 1024, "tx_rate": 512, "rx_bytes": 0, "tx_bytes": 0 },
  "disk_io": { "read_rate": 0, "write_rate": 0, "read_bytes": 0, "write_bytes": 0 },
  "processes": { "running": 1, "total": 344 },
  "psi": { "memory": { "some": { "avg10": 0 } }, "cpu": { "some": { "avg10": 1 } }, "io": { "some": { "avg10": 0 } } },
  "uptime": 123456, "os": "Linux …", "hostname": "…"
}
```

- 错误码：

  | 状态码 | 语义 |
  |---|---|
  | 401 | 未登录 / 会话失效 |
  | 500 | `{ "error": "获取系统信息失败: …" }` |

- 副作用：同步写入历史采样 buffer（趋势图数据源）。幂等：是。限流：无。

### GET /api/admin/system/history

- 鉴权：`authRequired`
- 请求参数：无
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/system/history"`
- 成功 200：环形 buffer 中的采样点数组（最多约 120 点）`[{ "ts": <epoch ms>, "cpu": …, "mem_percent": …, … }]`；无数据为 `[]`
- 错误：401
- 副作用：无；幂等：是；限流：无

### GET /api/admin/system/metrics

- 鉴权：`authRequired`
- 请求参数：

  | 名称 | 位置 | 类型 | 必填 | 默认 | 取值/校验 |
  |---|---|---|---|---|---|
  | `range` | query | string | 否 | `1d` | `1d`/`7d`/`30d` 之一，未知值回退 `1d` |
  | `step` | query | string | 否 | `1m` | `1m`/`1h`/`1d` 之一，未知值回退 `1m` |

- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/system/metrics?range=1d&step=1m"`
- 成功 200：`{ "step": "1m", "range": "1d", "points": [{ "ts": <epoch ms>, … }], "meta": { "step": "1m", "range": "1d", "bucketCount": 0, "firstBucket": null, "lastBucket": null, "recordedSeconds": 0 } }`；无数据/单点也返回结构完整的 200（`points` 可为空/单点）
- 错误：401；查询失败不 500，降级为空 `points` + 完整 `meta`（写 `console.warn`）
- 副作用：无；幂等：是；限流：无

### GET /api/admin/system/stream

- 鉴权：`authRequired`
- 请求参数：无
- curl：`curl -N -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/system/stream"`
- 成功 200（`text/event-stream`，每 1 秒一帧，每 10 帧一条 `: ping` 注释防代理超时）：

  ```
  event: snapshot
  data: {"system": { … },"services": {"services": [ … ],"total_cpu": 12.3},"history": [ … ]}
  ```

  帧结构固定为 `{ system, services: { services, total_cpu }, history }`；**不含进程明细**（进程树走 REST `/api/admin/services`）。
- 错误：401；单次采集失败不断流，下个 tick 重试
- 副作用：每次 tick 写历史采样；幂等：否（长连接流）；限流：无。客户端断开（`req close`）即停表

### GET /api/admin/services

- 鉴权：`authRequired`
- 请求参数：无
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/services"`
- 成功 200：

  ```json
  {
    "services": [ { "name": "nginx", "status": "up", "pid": 1234 } ],
    "processes": [
      {
        "name": "systemd", "pid": 1, "ppid": 0,
        "mem_mb": 15, "cpu": 0.1,
        "subtree_mem_mb": 7845, "subtree_cpu": 12.3, "subtree_count": 300,
        "cgroup_mem_mb": null, "thread_count": 1
      },
      {
        "name": "admin-server", "pid": 2345, "ppid": 1,
        "mem_mb": 80, "cpu": 0.4,
        "subtree_mem_mb": 120, "subtree_cpu": 1.2, "subtree_count": 3,
        "cgroup_mem_mb": 118, "thread_count": 11
      }
    ],
    "count": 344,
    "truncated": false,
    "total_mem_mb": 7855,
    "total_cpu": 12.3,
    "parsed_count": 344,
    "skipped_count": 0,
    "total_cgroup_mb": 11459,
    "total_threads": 1401
  }
  ```

  顶层字段：

  | 字段 | 类型 | 语义 |
  |---|---|---|
  | `count` | number | `ps` 解析到的进程总数，**截断前** |
  | `truncated` | boolean | 是否因超过硬上限被截断（默认上限 2000，可用 `ADMIN_PROC_MAX_ROWS` 覆盖） |
  | `total_mem_mb` | number | 全部进程 RSS 之和（截断前口径）；含共享页重复计算 |
  | `total_cpu` | number | 系统总占用（不是列表之和） |
  | `parsed_count` | number | `ps` 输出成功解析的行数 |
  | `skipped_count` | number | 解析失败被丢弃的行数（`>0` 前端应提示） |
  | `total_cgroup_mb` | number \| null | `system.slice` 的 cgroup 真值；取不到为 `null` |
  | `total_threads` | number | 全部进程线程数之和（截断前口径）；与 `count` 为两个口径，**不得相加/混算** |

  单行字段：`name` / `pid` / `ppid` / `mem_mb`（自身 RSS）/ `cpu` / `subtree_mem_mb` / `subtree_cpu` / `subtree_count` / `cgroup_mem_mb`（仅 systemd 单位主进程行有值，否则 `null`）/ `thread_count`（读 `/proc/<pid>/task` 条目数，取不到为 `null`）。

- 错误码：

  | 状态码 | 语义 |
  |---|---|
  | 401 | 未登录 |
  | 500 | `{ "error": "获取服务状态失败: …" }` |

- 副作用：单次 `/proc` 全量遍历 + `ps`/`systemctl`/`docker` 只读调用；不写库。幂等：是。限流：无。**cgroup 取值优先 `/sys/fs/cgroup/system.slice/<unit>/memory.current`，回退 `systemctl show <unit> -p MemoryCurrent --value`，取不到为 `null`（绝不猜）。**

## 五、认证与账号

### GET /api/admin/auth-mode

- 鉴权：无
- 请求参数：无
- curl：`curl -sS "$BASE_URL/api/admin/auth-mode"`
- 成功 200：`{ "authMode": "builtin" }`（或 `"sso"`）
- 错误：无；副作用：无；幂等：是；限流：无

### POST /api/admin/login

- 鉴权：无（仅 `builtin`；`sso` → `404`）
- 请求参数（body，JSON）：

  | 名称 | 类型 | 必填 | 校验 |
  |---|---|---|---|
  | `code` | string | 是 | TOTP 动态验证码（30 秒一变，±1 步容忍） |

- curl：`curl -sS -X POST -H 'Content-Type: application/json' -d '{"code":"123456"}' "$BASE_URL/api/admin/login"`
- 成功 200：`{ "token": "<64 位 hex>" }`，并下发 `Set-Cookie: admin_session=<token>; Path=/; HttpOnly; SameSite=Lax`（HTTPS 下加 `Secure`）
- 错误码：

  | 状态码 | 语义 | 附加字段 |
  |---|---|---|
  | 403 | TOTP 未配置，需先设置 | `code: "totp_setup_required"` |
  | 401 | 验证码错误 | — |
  | 429 | 同 IP 连续失败 5 次锁定 | `code: "rate_limited"`、`retryAfter`（秒） |
  | 500 | `{ "error": "会话服务异常" }` | — |

- 副作用：写 Redis 会话、写审计；幂等：否；限流：**是**（同 IP 连续失败 5 次锁 60 秒）

### POST /api/admin/logout

- 鉴权：无（仅 `builtin`；`sso` → `404`）
- 请求参数：无（会话 token 取 `Authorization: Bearer` 或 cookie）
- curl：`curl -sS -X POST -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/logout"`
- 成功 200：`{ "ok": true }`（未登录也 200，幂等）；并清 cookie
- 错误：无（Redis 异常也不阻断，cookie 照清）
- 副作用：删 Redis 会话；幂等：**是**；限流：无

### GET /api/admin/me

- 鉴权：`authRequired`（仅 `builtin`；`sso` → `404`）
- 请求参数：无
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/me"`
- 成功 200：`{ "name": "admin", "role": "admin" }`
- 错误：401 未登录
- 副作用：无；幂等：是；限流：无

### POST /api/admin/totp/reset

- 鉴权：`authRequired`
- 请求参数：无（身份取 `X-Auth-User` / 会话，转发时带内部令牌）
- curl：`curl -sS -X POST -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/totp/reset"`
- 成功：透传认证中心 `/api/internal/totp/reset?sub=<用户名>` 的响应（两阶段①：只写 pending，不覆盖正式 secret）
- 错误码：

  | 状态码 | 语义 |
  |---|---|
  | 401 | 缺少身份 |
  | 500 | 内部令牌文件缺失/为空 → `{ "error": "服务未正确配置" }` |
  | 502 | 认证中心地址未配置 / 不可达 → `{ "error": "认证中心不可达" }` |

- 副作用：调用认证中心内部接口；幂等：否；限流：无（由认证中心侧决定）

### POST /api/admin/totp/confirm

- 鉴权：`authRequired`
- 请求参数：body `{ "code": "<动态码>" }`（透传认证中心）
- curl：`curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"code":"123456"}' "$BASE_URL/api/admin/totp/confirm"`
- 成功：透传认证中心 `/api/internal/totp/confirm?sub=<用户名>`（两阶段②：pending 验证通过才转正）
- 错误：同 `/api/admin/totp/reset`（401 / 500 / 502，及认证中心返回的 4xx）
- 副作用：调用认证中心内部接口；幂等：否；限流：无

### ALL /api/admin/sessions

- 鉴权：`authRequired`（挂载点，转发认证中心内部接口 `/api/internal/sessions*`）
- 子路径与语义（透传，`?sub=<用户名>` 由本服务补齐）：

  | 方法 | 路径 | 语义 |
  |---|---|---|
  | GET | `/api/admin/sessions` | 登录设备会话列表，`{ "sessions": [ … ] }` |
  | PUT | `/api/admin/sessions/:id/name` | body `{ "deviceName": "<名称>" }` 重命名会话 |
  | DELETE | `/api/admin/sessions/:id` | 踢下线 |

- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/sessions"`
- 错误码：401 未登录；500 内部令牌不可用；502 认证中心地址未配置/不可达；其余状态透传
- 副作用：调用认证中心内部接口；幂等：GET 是、DELETE 是、PUT 是；限流：无

### ALL /api/admin/totp

- 鉴权：挂载 `totp-auth` 模块路由。其中 `/setup` 无鉴权（仅未配置 secret 时可用；`sso` 模式一律 `404`）；本服务的 `/reset`、`/confirm` 见上方（由 `authRequired` 保护）
- 子路径：

  | 方法 | 路径 | 语义 |
  |---|---|---|
  | POST | `/api/admin/totp/setup` | 首次设置：生成 secret，返回 `{ "secret": "<base32>", "otpauthUri": "<otpauth://…>" }`；已配置 → `409` |

- curl：`curl -sS -X POST "$BASE_URL/api/admin/totp/setup"`
- 错误码：409 已配置（`{ "code": "totp_already_setup" }`）；`sso` 模式 `/setup` → 404
- 副作用：写 secret 文件（0600，不入库）；幂等：否（已配置即 409）；限流：无

### POST /api/admin/password

- 鉴权：`authRequired`
- 请求参数（body）：

  | 名称 | 类型 | 必填 | 校验 |
  |---|---|---|---|
  | `old_password` | string | 是 | 必须与当前口令匹配 |
  | `new_password` | string | 是 | 长度 ≥ 6 |

- curl：`curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"old_password":"…","new_password":"…"}' "$BASE_URL/api/admin/password"`
- 成功 200：`{ "ok": true, "msg": "密码已修改，请重新登录" }`（同步删除全部会话，所有已登录端失效）
- 错误码：400 旧密码错误 / 新密码不足 6 位；500 `{ "error": "会话服务异常" }`
- 副作用：写 `config.json`、删全部 Redis 会话、写审计；幂等：否；限流：无

## 六、接口令牌

### GET /api/admin/api-tokens

- 鉴权：`authRequired`
- 请求参数：无
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/api-tokens"`
- 成功 200：`{ "tokens": [ { "id": "<sha256>", "name": "…", "note": "", "createdAt": <ms>, "expiresAt": <ms>, "lastUsedAt": <ms>, "canWrite": false } ] }`（**绝不含明文**，按 `createdAt` 倒序）
- 错误：401；500 `{ "error": "获取接口令牌失败" }`
- 副作用：写审计；幂等：是；限流：无

### POST /api/admin/api-tokens

- 鉴权：`authRequired`
- 请求参数（body）：

  | 名称 | 类型 | 必填 | 默认 | 校验 |
  |---|---|---|---|---|
  | `name` | string | 是 | — | 非空 |
  | `note` | string | 否 | `""` | — |
  | `expiresInDays` | number | 否 | `30` | 1~365 的整数 |
  | `canWrite` | boolean | 否 | `false` | 是否可写（通知写入） |

- curl：`curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"name":"ci","expiresInDays":30,"canWrite":true}' "$BASE_URL/api/admin/api-tokens"`
- 成功 200：`{ "id": "<sha256>", "token": "<64 位 hex，仅此一次>", "meta": { … } }`
- 错误码：400 名称空 / 有效期非 1~365 整数；500 `{ "error": "生成接口令牌失败" }`
- 副作用：写 Redis（固定过期，不滑动）、写审计；幂等：否；限流：无

### PATCH /api/admin/api-tokens/:id

- 鉴权：`authRequired`
- 请求参数：path `id`（string，sha256）；body 任选 `{ name?, note?, canWrite?, expiresInDays? }`（`expiresInDays` 需 1~365 整数，重设即刷新 TTL）
- curl：`curl -sS -X PATCH -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"note":"新备注"}' "$BASE_URL/api/admin/api-tokens/$ID"`
- 成功 200：更新后的令牌元数据（无明文）
- 错误码：400 名称空 / 有效期非法；404 令牌不存在或已过期；500 `{ "error": "更新接口令牌失败" }`
- 副作用：写 Redis、写审计；幂等：是（同入参结果一致）；限流：无

### DELETE /api/admin/api-tokens/:id

- 鉴权：`authRequired`
- 请求参数：path `id`（string）
- curl：`curl -sS -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/api-tokens/$ID"`
- 成功 200：`{ "ok": true }`（立即失效）
- 错误：401；500 `{ "error": "吊销接口令牌失败" }`
- 副作用：删 Redis key、写审计；幂等：**是**；限流：无

## 七、通知中心

### POST /api/admin/notifications

- 鉴权：`notificationsWriteAuth`（本机直连回环免鉴权；其余来源需 `authRequired`，或可写 API 令牌 `canWrite=true`）
- 请求参数（body）：

  | 名称 | 类型 | 必填 | 默认 | 校验 |
  |---|---|---|---|---|
  | `source` | string | 是 | — | 非空 |
  | `title` | string | 是 | — | 非空 |
  | `level` | string | 否 | 类别默认 / `normal` | `urgent`/`normal`/`digest` |
  | `type` | string | 否 | = `source` | 未注册类别自动注册 |
  | `body` | string | 否 | `null` | — |
  | `link` | string | 否 | `null` | — |
  | `dedupKey` | string | 否 | `null` | 相同 key 去重 |

- curl：`curl -sS -X POST -H 'Content-Type: application/json' -d '{"source":"deploy","title":"部署完成"}' "$BASE_URL/api/admin/notifications"`（本机直连回环可免鉴权）
- 成功 201：`{ "id": 1, "ts": <epoch 秒> }`
- 错误码：400 `level` 非法 / `source`、`title` 空；403 只读令牌写入；503 通知库不可用；500 写入失败
- 副作用：写通知库、SSE 广播、写审计；幂等：否（`dedupKey` 可去重）；限流：无

### GET /api/admin/notifications

- 鉴权：`authRequired`
- 请求参数（query）：

  | 名称 | 类型 | 必填 | 默认 | 校验 |
  |---|---|---|---|---|
  | `limit` | number | 否 | `50` | 夹紧 1~200 |
  | `before` | number | 否 | — | 按 `ts` 分页 |
  | `level` | string | 否 | — | `urgent`/`normal`/`digest`，非法忽略 |
  | `source` | string | 否 | — | — |
  | `type` | string | 否 | — | 类别维度 |
  | `unread` | string | 否 | — | `1` 只看未读 |

- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/notifications?limit=20&unread=1"`
- 成功 200：`{ "items": [ { "id": 1, "ts": <秒>, "level": "normal", "source": "…", "type": "…", "title": "…", "body": null, "link": null, "readAt": null } ], "unread": 3, "total": 42 }`
- 错误：503 通知库不可用；500 `{ "error": "获取通知失败" }`
- 副作用：无；幂等：是；限流：无

### GET /api/admin/notifications/types

- 鉴权：`authRequired`
- 请求参数：无
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/notifications/types"`
- 成功 200：`{ "types": [ { "key": "deploy", "label": "部署", "description": "", "defaultLevel": "normal", "sort": 0, "enabled": 1, "count": 5, "unread": 1 } ] }`（客户端据此动态渲染筛选器）
- 错误：503；500 `{ "error": "获取通知类别失败" }`
- 副作用：无；幂等：是；限流：无

### PATCH /api/admin/notifications/types/:key

- 鉴权：`authRequired`
- 请求参数：path `key`（string）；body 任选 `{ label?, description?, defaultLevel?, sort?, enabled? }`
- curl：`curl -sS -X PATCH -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"enabled":false}' "$BASE_URL/api/admin/notifications/types/deploy"`
- 成功 200：`{ "ok": true }`
- 错误码：400 无效类别 / `label` 空 / `defaultLevel` 非法 / `sort` 非整数 / 无可改字段；404 类别不存在；503；500
- 副作用：改通知库、写审计；幂等：是；限流：无

### POST /api/admin/notifications/:id/read

- 鉴权：`authRequired`
- 请求参数：path `id`（number）
- curl：`curl -sS -X POST -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/notifications/1/read"`
- 成功 200：`{ "ok": true }`
- 错误：400 无效 id；503；500 `{ "error": "标记已读失败" }`
- 副作用：写通知库；幂等：是；限流：无

### POST /api/admin/notifications/read-all

- 鉴权：`authRequired`
- 请求参数：无
- curl：`curl -sS -X POST -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/notifications/read-all"`
- 成功 200：`{ "ok": true, "count": 12 }`
- 错误：503；500 `{ "error": "全部已读失败" }`
- 副作用：写通知库；幂等：是（再次调用 count=0）；限流：无

### DELETE /api/admin/notifications/:id

- 鉴权：`authRequired`
- 请求参数：path `id`（number）
- curl：`curl -sS -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/notifications/1"`
- 成功 200：`{ "ok": true }`
- 错误：400 无效 id；503；500 `{ "error": "删除通知失败" }`
- 副作用：删通知、写审计；幂等：是；限流：无

### POST /api/admin/notifications/bulk-delete

- 鉴权：`authRequired`
- 请求参数（body，全部可选）：`{ level?, source?, unreadOnly?, readOnly?, dryRun? }`；`unreadOnly` 与 `readOnly` 同时为真时不匹配任何行（返回 0）
- curl：`curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"level":"digest","dryRun":true}' "$BASE_URL/api/admin/notifications/bulk-delete"`
- 成功 200：`{ "ok": true, "count": 5 }`（`dryRun=true` 只统计不删）
- 错误：503；500 `{ "error": "批量删除失败" }`
- 副作用：`dryRun=false` 时删库、写审计；幂等：否；限流：无。**不带任何条件即全部删除。**

### GET /api/admin/notifications/stats

- 鉴权：`authRequired`
- 请求参数：无
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/notifications/stats"`
- 成功 200：`{ "total": 42, "unread": 3, "sources": [ { "source": "deploy", "count": 10 } ] }`（按条数降序）
- 错误：503；500 `{ "error": "获取通知统计失败" }`
- 副作用：无；幂等：是；限流：无

### GET /api/admin/notifications/stream

- 鉴权：`authRequired`
- 请求参数：无
- curl：`curl -N -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/notifications/stream"`
- 成功 200（SSE）：`event: notification`（新通知 item）/ `event: heartbeat`（每 25s）；开头 `retry: 5000`
- 错误：401
- 副作用：订阅广播；幂等：否；限流：无。客户端断开即移除订阅

## 八、版本与应用面板

### GET /api/admin/versions

- 鉴权：`authRequired`
- 请求参数：无
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/versions"`
- 成功 200：`{ "list": [ { "name": "Node.js", "category": "runtime", "version": "24.19.0", "ok": true } ] }`（60 秒结果缓存）
- 错误：500 `{ "error": "获取软件版本失败: …" }`
- 副作用：执行本机版本命令；幂等：是；限流：无（内部 60s 缓存）

### GET /api/admin/apps

- 鉴权：`authRequired`
- 请求参数：`refresh`（query，string，否）—— `1`/`true` 绕过 10s 缓存
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/apps?refresh=1"`
- 成功 200：`{ "apps": [ { "id": "…", "name": "…", "status": "up" } ], "categories": [ … ], "discovered": [ … ], "generatedAt": …, "cached": false, "ttlSeconds": 10, "registryPath": "…", "notice": null, "warning": null }`
- 错误：500 `{ "error": "…" }`
- 副作用：读登记表 + 探活（TCP/systemd/docker 只读）、写审计（**不记 url**）；幂等：是；限流：无（10s 缓存 + 单飞）

### GET /api/public/apps

- 鉴权：无
- 请求参数：`refresh`（query，string，否）—— `1`/`true` 请求刷新，但**按来源 IP 每 10s 至多一次真正刷新**，超出按缓存读
- curl：`curl -sS "$BASE_URL/api/public/apps"`
- 成功 200：`{ "categories": [ { "id": "…", "name": "…" } ], "apps": [ { "id": "…", "name": "…", "status": "up" } ] }`（字段白名单，剔除 `port/unit/container/probe/registryPath/registryMtime/notice/warning/discovered`）；响应头 `Cache-Control: no-store`
- 错误：503 `{ "error": "应用数据暂不可用" }`（不返回栈信息）
- 副作用：探活只读、写审计（`public_apps_list`，不记 url）；幂等：是；限流：**是**（刷新窗口 10s / IP）

## 九、文件

### POST /api/admin/upload

- 鉴权：`authRequired`
- 请求参数：`multipart/form-data`，字段名 `file`（单文件，上限 100MB）
- curl：`curl -sS -X POST -H "Authorization: Bearer $TOKEN" -F "file=@/path/to/file" "$BASE_URL/api/admin/upload"`
- 成功 200：`{ "path": "<绝对路径>" }`（按时间戳命名，落 `uploads/`）
- 错误码：400 未收到文件（`字段名应为 file`）；413 超过 100MB（multer）
- 副作用：写磁盘、写审计；幂等：否；限流：无

### POST /api/admin/files/upload

- 鉴权：`authRequired`
- 请求参数：query `path`（string，目标目录相对文件区根，缺省根）；`multipart/form-data` 字段 `file`（上限 500MB，保留原始文件名，重名加 `-2`）
- curl：`curl -sS -X POST -H "Authorization: Bearer $TOKEN" -F "file=@/path/to/file" "$BASE_URL/api/admin/files/upload?path=docs"`
- 成功 200：`{ "name": "<文件名>", "size": 1234, "path": "<绝对路径>" }`
- 错误码：400 路径非法 / 未收到文件；403 受保护路径；413 超过 500MB
- 副作用：写磁盘、写审计（受保护路径命中会删除已落盘文件）；幂等：否；限流：无

### GET /api/admin/files

- 鉴权：`authRequired`
- 请求参数：query `path`（string，相对文件区根，缺省根）
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/files?path="`
- 成功 200：`{ "path": "", "parent": null, "entries": [ { "name": "…", "type": "dir", "size": 0, "mtime": <ms> } ] }`（目录在前，中文按拼音序；跳过符号链接与受保护根项）
- 错误码：400 路径非法 / 不是目录；404 目录不存在；500 `{ "error": "读取目录失败：…" }`
- 副作用：无；幂等：是；限流：无

### GET /api/admin/files/download

- 鉴权：`authRequired`
- 请求参数：query `path`（string，相对文件区根，必填）
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" -OJ "$BASE_URL/api/admin/files/download?path=docs/a.txt"`
- 成功 200：二进制附件（`Content-Disposition: attachment`）
- 错误码：400 路径非法 / 不是普通文件；403 受保护路径；404 文件不存在
- 副作用：无；幂等：是；限流：无

### POST /api/admin/files/mkdir

- 鉴权：`authRequired`
- 请求参数（body）：`{ "path": "<父目录相对路径>", "name": "<文件夹名>" }`
- curl：`curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"path":"","name":"docs"}' "$BASE_URL/api/admin/files/mkdir"`
- 成功 200：`{ "ok": true, "path": "docs" }`
- 错误码：400 路径/名称非法；403 受保护路径；409 同名已存在；500 `{ "error": "创建失败：…" }`
- 副作用：建目录、写审计；幂等：否；限流：无

### POST /api/admin/files/rename

- 鉴权：`authRequired`
- 请求参数（body）：`{ "path": "<完整相对路径>", "name": "<新名称>" }`
- curl：`curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"path":"docs/a.txt","name":"b.txt"}' "$BASE_URL/api/admin/files/rename"`
- 成功 200：`{ "ok": true, "path": "docs/b.txt" }`
- 错误码：400 路径/名称非法；403 源或目标受保护；404 文件不存在；409 同名已存在；500
- 副作用：改磁盘、写审计；幂等：否；限流：无

### DELETE /api/admin/files

- 鉴权：`authRequired`
- 请求参数：query `path`（string，相对文件区根，必填）
- curl：`curl -sS -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/files?path=docs/a.txt"`
- 成功 200：`{ "ok": true }`（目录递归）
- 错误码：400 路径非法；403 受保护路径；404 文件不存在；500 `{ "error": "删除失败：…" }`
- 副作用：删磁盘、写审计；幂等：否；限流：无

### GET /api/admin/download

- 鉴权：`authRequired`
- 请求参数：query `path`（string，必填；支持 `~/…` 展开；resolve 后须落在白名单根目录内）
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" -OJ "$BASE_URL/api/admin/download?path=%2Ftmp%2Fa.txt"`
- 成功 200：二进制附件
- 错误码：400 缺少 path / 路径不在允许范围；404 文件不存在
- 副作用：无；幂等：是；限流：无

## 十、文件区临时链接（限时分享）

### POST /api/admin/files/shares

- 鉴权：`authRequired`
- 请求参数（body）：

  | 名称 | 类型 | 必填 | 默认 | 校验 |
  |---|---|---|---|---|
  | `path` | string | 是 | — | 相对文件区根、必须是普通文件、非受保护路径 |
  | `expiresAt` | number | 否 | — | epoch 毫秒整数；`0`=永久；非 0 须为将来时刻；优先于 `ttlHours` |
  | `ttlHours` | number | 否 | `24` | 夹紧 1~8760 小时 |
  | `note` | string | 否 | `""` | 截断 500 字 |

- curl：`curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"path":"docs/a.txt","ttlHours":24}' "$BASE_URL/api/admin/files/shares"`
- 成功 201：share 视图：`{ "id": "…", "token": "…", "relPath": "docs/a.txt", "size": 1234, "note": "", "createdAt": <ms>, "expiresAt": <ms>, "revokedAt": null, "downloads": 0, "lastAccessAt": null, "lastAccessIp": null, "url": "<分享基址>/s/<token>", "status": "active", "remainingMs": <ms|null>, "fileExists": true }`
- 错误码：400 路径非法 / 参数非法 / 目录或不支持类型；403 受保护路径；404 文件不存在
- 副作用：写本地 JSON 账本、写审计；幂等：否；限流：无

### GET /api/admin/files/shares

- 鉴权：`authRequired`
- 请求参数：无
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/files/shares"`
- 成功 200：`{ "shares": [ <share 视图…> ] }`（按 `createdAt` 倒序；惰性清理 revoked>30 天 / expired>90 天）
- 错误：无（账本损坏按空处理）；副作用：可能有惰性清理写盘；幂等：是；限流：无

### PATCH /api/admin/files/shares/:id

- 鉴权：`authRequired`
- 请求参数：path `id`（string）；body 任选 `{ expiresAt?, note?, revoked? }`（`revoked:true` 撤销不可逆；`revoked:false` 拒绝；`expiresAt:0` 转永久）；仅 `active` 记录可操作
- curl：`curl -sS -X PATCH -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"note":"新版"}' "$BASE_URL/api/admin/files/shares/$ID"`
- 成功 200：更新后的 share 视图
- 错误码：400 `revoked` 非布尔 / 试图恢复撤销 / 无可更新字段 / 非 active / 时间非法；404 链接不存在
- 副作用：写账本、写审计；幂等：是；限流：无

### DELETE /api/admin/files/shares/:id

- 鉴权：`authRequired`
- 请求参数：path `id`（string）
- curl：`curl -sS -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/files/shares/$ID"`
- 成功 200：`{ "ok": true }`（只删记录，不动磁盘文件）
- 错误：404 链接不存在
- 副作用：写账本、写审计；幂等：是；限流：无

### GET /s/:token

- 鉴权：无（公开）
- 请求参数：path `token`（string，分享 token）
- curl：`curl -sS -OJ "$BASE_URL/s/<token>"`
- 成功 200：二进制附件（按 RFC 5987 编码文件名）；命中 `active` 时计数 +1 并记最后访问 IP
- 错误码：

  | 状态码 | 语义 |
  |---|---|
  | 404 | token 不存在 / 文件已删（返回极简 HTML 提示页） |
  | 410 | 链接已撤销 / 已过期（同上 HTML 提示页） |

- 副作用：更新下载计数与最后访问、写审计；幂等：否（每次计数）；限流：无

## 十一、Hermes 历史（只读）

### GET /api/admin/history

- 鉴权：`authRequired`
- 请求参数：无
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/history"`
- 成功 200：`{ "sessions": [ { "id": "…", "title": "…", "time": <epoch ms|null>, "message_count": 3 } ] }`（按最后活动倒序）
- 错误码：503 `{ "error": "历史记录暂不可用" }`（数据库不可用）；500 `{ "error": "获取历史会话失败" }`
- 副作用：只读打开 Hermes `state.db`（请求内 open→query→close）；幂等：是；限流：无

### GET /api/admin/history/:id

- 鉴权：`authRequired`
- 请求参数：path `id`（string，会话 id）
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/history/$ID"`
- 成功 200：`{ "session": { "id": "…", "title": "…" }, "messages": [ { "role": "user|assistant", "content": "…", "ts": <epoch ms|null> } ] }`
- 错误码：404 `{ "error": "会话不存在" }`；503 数据库不可用；500 `{ "error": "获取会话消息失败" }`
- 副作用：只读；幂等：是；限流：无

## 十二、Web 终端

### POST /api/admin/term/unlock

- 鉴权：`authRequired`
- 请求参数（body）：`{ "password": "<终端口令>" }`
- curl：`curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"password":"…"}' "$BASE_URL/api/admin/term/unlock"`
- 成功 200：`{ "ticket": "<64 位 hex>", "expiresIn": 43200 }`
- 错误码：401 口令不正确；429 同 IP 连续失败 5 次锁 10 分钟（附 `retryAfter` 秒）；500 `{ "error": "票据存储失败: …" }`
- 副作用：写 Redis 票据（12 小时）、写审计；幂等：否；限流：**是**（5 次失败锁 10 分钟 / IP）

### GET /api/admin/term/verify

- 鉴权：**仅本机**（来源 IP 必须为 `127.0.0.1`/`::1`；否则 403）
- 请求参数：query `ticket`（string，必填）
- curl：`curl -sS "$BASE_URL/api/admin/term/verify?ticket=<ticket>"`
- 成功 200：`{ "ok": true }`
- 错误码：400 缺 ticket（`{ "ok": false }`）；401 票据无效/过期；403 非本机；500 Redis 异常
- 副作用：无（只读 Redis）；幂等：是；限流：无

### GET /api/admin/term/sessions

- 鉴权：`authRequired`
- 请求参数：无
- curl：`curl -sS -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/term/sessions"`
- 成功 200：`{ "sessions": [ { "name": "term-abc", "attached": false, "activity": <epoch 秒> } ] }`（仅 `term-*` 白名单会话）
- 错误：500 `{ "error": "读取终端会话失败: …" }`
- 副作用：执行 `tmux list-sessions`；幂等：是；限流：无

### POST /api/admin/term/sessions/close

- 鉴权：`authRequired`
- 请求参数（body）：`{ "names": ["term-abc", …] }`（最多前 32 个；非白名单名称忽略）
- curl：`curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{"names":["term-abc"]}' "$BASE_URL/api/admin/term/sessions/close"`
- 成功 200：`{ "ok": true, "killed": ["term-abc"] }`
- 错误：无（单个失败不影响整体）
- 副作用：`tmux kill-session`、写审计；幂等：是；限流：无

### DELETE /api/admin/term/sessions/:name

- 鉴权：`authRequired`
- 请求参数：path `name`（string，须匹配 `^term-[a-z0-9][a-z0-9-]{0,31}$`）
- curl：`curl -sS -X DELETE -H "Authorization: Bearer $TOKEN" "$BASE_URL/api/admin/term/sessions/term-abc"`
- 成功 200：`{ "ok": true }`
- 错误码：400 非法会话名；500 `{ "error": "关闭终端会话失败: …" }`
- 副作用：`tmux kill-session`、写审计；幂等：是；限流：无
