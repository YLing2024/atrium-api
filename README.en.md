[English](README.en.md) | [简体中文](README.md)

# atrium-api

The API service for the personal site admin: system monitoring, files, terminal, apps and notifications.

## What it does

- **System status**: CPU (overall / per core), memory and swap, disk, disk IO, network rate, PSI pressure, load, uptime. `/api/admin/system` is a real-time snapshot; `/api/admin/system/history` returns the latest 120 sample points; `/api/admin/system/metrics` reads materialized aggregate buckets by `range` (`1h`/`6h`/`1d`/`7d`/`30d`) and `step` (`1m`/`5m`/`1h`/`1d`); `/api/admin/system/stream` pushes over SSE every second.
- **Versions and services**: `/api/admin/versions` (60s cache), `/api/admin/services` (up/down per service, plus process TOP15 and total CPU).
- **File area**: browse / upload (500MB) / download / create / rename / delete under the `ADMIN_FILE_DIR` root, plus time-limited share links (public entry `/s/:token`). There are also legacy endpoints `/api/admin/upload` (100MB) and `/api/admin/download`.
- **Web terminal**: secondary terminal password verification → 12-hour ticket → ttyd/tmux session listing and closing.
- **Apps panel**: a read-only registry plus live probing, see the next section.
- **Notification center**: writes, list filtering, unread marking, category registration, statistics and SSE push; archived in SQLite, retained 30 days.
- **Hermes history browsing**: read-only access to `~/.hermes/state.db`, opened → queried → closed within the request.
- **Login and TOTP**: mode probing, TOTP login / logout, current identity, TOTP reset forwarding, login device sessions, API tokens.

## Apps panel

A read-only panel: it presents the local apps in one place with live probing; it does not start or stop services or change configuration.

- Registry `data/apps.json` (overridden by `ADMIN_APPS_FILE`), **consumed read-only** and not generated when absent; re-read whenever the file `mtime` changes. See `apps.example.json` for a sample (placeholder values).
- `GET /api/admin/apps`: `?refresh=1` bypasses the 10s cache; concurrent requests reuse the same collection. Returns fields such as `categories[] / apps[] / discovered[] / notice / warning`.
- `GET /api/public/apps`: **public, read-only, no auth** (used by the independent-subdomain "app center"). It reuses the same collection logic and 10s cache / single-flight, but returns only public-safe fields: `categories[]` (`{id, name}`) and `apps[]` (whitelist `id / name / category / desc / url / icon / status / latencyMs / onDemand`), dropping `port / unit / container / probe / registryPath / registryMtime / notice / warning` and the unregistered `discovered[]`. `?refresh=1` is rate-limited by source IP (at most one real refresh per 10s window; beyond that reads from cache); response header `Cache-Control: no-store`; returns `503` when the backend is unavailable.
- **Multiple groups**: `categories[] = {id, name}` defines the groups; unknown categories fall into "other".
- **Probing**: priority `probe > container > unit > port`; status `up` / `auth` / `degraded` / `down` / `idle` / `unknown`. A single probe times out at 1500ms; all run in parallel and one failure does not affect the others.
- **On-demand wake-up**: an app with `onDemand: true` that does not respond to probing is reported as `idle`, not counted as down.
- **Unregistered discovery**: `ss -ltnp` takes `127.0.0.1` listening rows; `ignorePorts` excludes fixed ownerless ports, and `ignoreProcesses` uses process-name regexes to filter out tool listeners whose ports change every time.
- **Icons**: `icon` is an icon name (string); when absent or null the frontend falls back to the first character of the name.

## Quick start

```bash
npm install
npm start        # = node src/index.ts, listens on 0.0.0.0:3100 by default
```

No build (Node runs TS directly), no external test framework (`node:test`), ESLint does correctness checks only; restart the process for changes to take effect.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `PORT` / `HOST` | `3100` / `0.0.0.0` | Listening port and address; the systemd unit sets `HOST=127.0.0.1` |
| `AUTH_MODE` | `builtin` | Auth mode, see "Authentication and security" |
| `ADMIN_CONFIG_PATH` | `<repo>/config.json` | Configuration file (contains the initial password and TOTP secret, 0600) |
| `ADMIN_UPLOAD_DIR` | `<repo>/uploads` | Landing directory for the legacy upload endpoint |
| `ADMIN_FILE_DIR` | `/root/files/download` | File-area root; all paths are strictly confined to it |
| `ADMIN_APPS_FILE` | `<repo>/data/apps.json` | Apps registry |
| `ADMIN_AUDIT_LOG` | `<repo>/audit.log` | Audit log (appended JSON lines) |
| `HERMES_STATE_DB` | `~/.hermes/state.db` | History-browsing data source |
| `AUTH_CENTER_BASE_URL` | none | Auth center base URL; used for device sessions and TOTP forwarding, returns 502 when unset |
| `AUTH_CENTER_INTERNAL_TOKEN_FILE` | `../../auth-server/internal-token` | Auth center internal token file, read-only, not printed |
| `ADMIN_TERM_PW_FILE` | `~/.hermes/term_password` | Terminal password hash (`sha256$<salt>$<hash>`, 0600) |
| `ADMIN_TOTP_SECRET_FILE` | `<repo>/totp-secret.json` | TOTP secret persistence |
| `ADMIN_HISTORY_FILE` / `ADMIN_SAMPLER_LOCK` | system temp directory | History buffer and sampler lock (shared across instances; isolate in tests) |
| `ADMIN_METRICS_DB` / `ADMIN_NOTIFICATIONS_DB` | `<repo>/data/metrics.db` / `notifications.db` | Sample aggregate store / notification store |
| `ADMIN_SHARE_FILE` | `<repo>/data/file-shares.json` | Share link ledger |
| `ADMIN_SHARE_BASE_URL` | none | Share link base URL; derived from request headers when unset |
| `ADMIN_REDIS_PREFIX` | `admin:session:` | Redis session key prefix (test instance isolation) |

## Deployment

The systemd unit `admin-server.service` sets `WorkingDirectory` to the repo root, starts with `node src/index.ts`, and sets `HOST=127.0.0.1` in the unit.

```bash
systemctl restart admin-server
systemctl status admin-server
journalctl -u admin-server -n 100 --no-pager
```

nginx proxies `/api/admin/*` → `127.0.0.1:3100`; file-area uploads get a separate location (limit 512m), while the rest of `/api/admin/` is 100m. Requests over the limit are rejected by nginx first and return HTML rather than JSON.

## Authentication and security

| `AUTH_MODE` | Behavior |
|---|---|
| `builtin` (default) | built-in account: TOTP login; `authRequired` accepts `Authorization: Bearer <token>` or the HttpOnly cookie `admin_session` (a hit on Redis `admin:session:<token>` passes and slides the renewal); external `X-Auth-User` is ignored |
| `sso` | built-in passwords off; identity only from the `X-Auth-User` injected by the upstream auth layer; `login` / `logout` / `me` all return 404 |

- The client IP is always taken from `X-Real-IP` (this service listens on loopback only, so `req.ip` is always 127.0.0.1).
- The file-area root has two kinds of protection, applied only at the root level: one kind is **hidden and rejects writes to the whole subtree**; the other is shown normally but the root entry itself cannot be deleted or renamed. The specific lists come from deployment-time environment variables (not written into the repo). Directory listing skips symbolic links and special files to prevent escapes.
- The terminal ticket check `/api/admin/term/verify` is callable only from `127.0.0.1`; the terminal password and tickets are stored only as hashes.
- Notification writes: direct local connections skip login, everything else goes through `authRequired` or a writable API token (`canWrite: true`).
- Keys, passwords, internal tokens and private addresses are never put in the source; they come from config.json or environment variables. `config.json`, `data/`, `audit.log` and `totp-secret.json` are not committed.

## License

MIT
