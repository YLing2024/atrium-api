'use strict';

/**
 * admin-server 入口
 *  - REST 接口：登录 / 系统信息 / 上传 / 下载 / 修改密码
 *  - WebSocket 桥接：客户端 <-> Hermes(9119) 双向透传 JSON-RPC 帧
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { exec, execSync } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);
const crypto = require('crypto');
const express = require('express');
const http = require('http');
const net = require('net');
const Redis = require('ioredis');
const multer = require('multer');
const { WebSocketServer, WebSocket } = require('ws');
const { createTotpAuth } = require('totp-auth');
const config = require('./config');

const PORT = parseInt(process.env.PORT, 10) || 3100;
const HOST = process.env.HOST || '0.0.0.0';
const UPLOAD_DIR = process.env.ADMIN_UPLOAD_DIR || path.join(__dirname, '..', 'uploads'); // 上传文件目录
const HERMES_WS_URL = 'ws://127.0.0.1:9119/api/ws'; // Hermes WebSocket 网关
const HERMES_TOKEN_FILE = '/root/.hermes/dashboard_token'; // Hermes 访问令牌

// 多会话：Redis key 带 token 后缀（admin:session:<token>），每个会话独立，多端可同时登录
const SESSION_KEY_PREFIX = process.env.ADMIN_REDIS_PREFIX || 'admin:session:';
const SESSION_TTL = 43200; // 12 小时，每次请求校验通过后滑动续期

function sessionKey(token) {
  return SESSION_KEY_PREFIX + token;
}

// 登录失败锁定：内存 Map 按 IP 计数，连续失败 5 次锁 60 秒，锁定期登录返回 429
const LOGIN_MAX_FAILS = 5;
const LOGIN_LOCK_SECONDS = 60;
const loginFails = new Map(); // ip -> { count, lockUntil }

// 检查是否处于锁定状态；锁定过期则顺手清理，返回 { locked, remain? }
function loginRateCheck(ip) {
  const rec = loginFails.get(ip);
  if (rec && rec.lockUntil) {
    if (rec.lockUntil > Date.now()) {
      return { locked: true, remain: Math.ceil((rec.lockUntil - Date.now()) / 1000) };
    }
    loginFails.delete(ip);
  }
  return { locked: false };
}

// 记录一次失败；累计到上限即触发 60s 锁定，返回当前失败计数
function loginRateFail(ip) {
  const rec = loginFails.get(ip) || { count: 0, lockUntil: 0 };
  rec.count += 1;
  if (rec.count >= LOGIN_MAX_FAILS) {
    rec.lockUntil = Date.now() + LOGIN_LOCK_SECONDS * 1000;
  }
  loginFails.set(ip, rec);
  return rec;
}

// 登录成功清除该 IP 失败记录
function loginRateClear(ip) {
  loginFails.delete(ip);
}

// 审计日志：JSON 行追加写 /root/proj/admin-server/audit.log，写入失败不影响业务
const AUDIT_LOG_FILE =
  process.env.ADMIN_AUDIT_LOG || path.join(__dirname, '..', 'audit.log');

function auditLog(action, ip, ok, detail) {
  const line =
    JSON.stringify({
      ts: new Date().toISOString(),
      action,
      ip: ip || 'unknown',
      ok: !!ok,
      detail: detail || ''
    }) + '\n';
  try {
    fs.appendFileSync(AUDIT_LOG_FILE, line);
  } catch (e) {
    // 审计日志写入失败仅告警，不阻断业务
    console.error('[admin-server] 审计日志写入失败:', e.message);
  }
}

// 取客户端 IP：优先 req.ip（Express 已处理 X-Forwarded-For），退化为 socket 地址
function clientIp(req) {
  return req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
}

// 内部通知接口来源校验：设置 ADMIN_NOTIFY_KEY 后，携带匹配密钥的请求可从任意来源调用；
// 未设置时仅允许本机回环地址（::ffff:127.0.0.1 是 IPv4 映射 IPv6 的形式）
const ADMIN_NOTIFY_KEY = process.env.ADMIN_NOTIFY_KEY || '';

function isLoopbackAddr(addr) {
  const a = String(addr || '');
  return a === '127.0.0.1' || a === '::1' || a === '::ffff:127.0.0.1';
}

// Redis 连接，失败时启动报错退出
const redis = new Redis('redis://127.0.0.1:6379');
redis.on('error', (err) => {
  console.error('[admin-server] Redis 连接失败:', err.message);
  process.exit(1);
});

// 上传目录不存在则自动创建
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ============ 工具函数 ============ */

// SHA-256 后定时安全比较，避免时序攻击
function sha256(str) {
  return crypto.createHash('sha256').update(String(str)).digest();
}

function verifyPassword(input, stored) {
  const a = sha256(input);
  const b = sha256(stored);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

/* ============ TOTP 鉴权（独立模块 totp-auth） ============ */

// TOTP secret 持久化文件（可被 ADMIN_TOTP_SECRET_FILE 覆盖，测试实例独立隔离）
const TOTP_SECRET_FILE =
  process.env.ADMIN_TOTP_SECRET_FILE || path.join(__dirname, '..', 'totp-secret.json');

// 复用独立模块：TOTP 动态码验证 + JWT + 按 IP 阶梯限速 + secret 文件持久化
const auth = createTotpAuth({
  secretFile: TOTP_SECRET_FILE,
  issuer: 'HomeAdmin',
  jwtSecret: config.getOrCreateJwtSecret(),
  jwtExpiresIn: '12h',
  rateLimit: { maxFailures: 5, lockout: [60, 300, 900] },
});

// 认证中心地址：WS 鉴权与 SSO 兼容接口共用
const AUTH_CENTER_VERIFY_URL =
  process.env.AUTH_CENTER_VERIFY_URL || 'http://127.0.0.1:3200/api/verify';

// 调认证中心内部接口验证 token，返回是否通过
async function verifyAuthCenterToken(token) {
  try {
    const res = await fetch(
      `${AUTH_CENTER_VERIFY_URL}?token=${encodeURIComponent(token)}`,
      { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(3000) }
    );
    return res.ok;
  } catch (e) {
    return false;
  }
}

// 鉴权中间件：
//  主鉴权 —— 信任 Nginx 探针注入的 X-Auth-User header（认证中心已验证，内网可信），
//  存在且非空即通过，req.user 设为其值；
//  降级 —— header 缺失时回退旧 Redis 会话校验（过渡期兼容，支持 Bearer 与 query token）
async function authRequired(req, res, next) {
  const xAuthUser = req.get('x-auth-user');
  if (xAuthUser && String(xAuthUser).trim()) {
    req.user = { role: 'admin', name: String(xAuthUser).trim() };
    return next();
  }
  const header = req.headers.authorization || '';
  const headerToken = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
  const queryToken = req.query && req.query.token ? String(req.query.token) : null;
  const token = headerToken || queryToken;
  if (!token) {
    return res.status(401).json({ error: '未登录' });
  }
  try {
    const stored = await redis.get(sessionKey(token));
    if (!stored || stored !== token) {
      return res.status(401).json({ error: '未登录或会话已过期' });
    }
    await redis.expire(sessionKey(token), SESSION_TTL); // 滑动续期
    req.user = { role: 'admin' };
    next();
  } catch (e) {
    return res.status(500).json({ error: '会话服务异常' });
  }
}

/* ============ 系统信息采集 ============ */

// CPU 采样：累加各核 times
function cpuSample() {
  let idle = 0;
  let total = 0;
  for (const cpu of os.cpus()) {
    for (const t of Object.values(cpu.times)) total += t;
    idle += cpu.times.idle;
  }
  return { idle, total };
}

// 通过两次采样计算 CPU 使用率
// CPU 采样滑动平均（EMA）：抹平单核机器上 150ms 瞬时采样的 0%/100% 跳变
let cpuEma = null
const CPU_EMA_ALPHA = 0.4 // 新采样权重；越大响应越快、平滑越弱

function getCpuInfo() {
  const a = cpuSample();
  return new Promise((resolve) => {
    setTimeout(() => {
      const b = cpuSample();
      const totalDiff = b.total - a.total;
      const idleDiff = b.idle - a.idle;
      const usage = totalDiff > 0 ? ((totalDiff - idleDiff) / totalDiff) * 100 : 0;
      // EMA 平滑：cpuEma = cpuEma * (1-α) + usage * α
      cpuEma = cpuEma === null ? usage : cpuEma * (1 - CPU_EMA_ALPHA) + usage * CPU_EMA_ALPHA;
      const cpus = os.cpus();
      resolve({
        model: cpus[0] ? cpus[0].model.trim() : 'unknown',
        usage_percent: Math.round(cpuEma * 100) / 100,
        cores: cpus.length,
        loadavg: os.loadavg()
      });
    }, 300); // 采样窗口 150→300ms，配合 EMA 平滑
  });
}

// 磁盘：取 df -kP 中挂载点为 '/' 的行，仅统计总量，不做目录明细扫描（单位字节）
function getDisk() {
  const disk = { total: 0, used: 0, free: 0, percent: 0 };
  try {
    const out = execSync('df -kP', { encoding: 'utf-8' }).trim().split('\n');
    for (const line of out.slice(1)) {
      const cols = line.split(/\s+/);
      if (cols.length < 6 || cols.slice(5).join(' ') !== '/') continue;
      disk.total = parseInt(cols[1], 10) * 1024;
      disk.used = parseInt(cols[2], 10) * 1024;
      disk.free = parseInt(cols[3], 10) * 1024;
      disk.percent = parseInt(String(cols[4]).replace('%', ''), 10) || 0;
      break;
    }
  } catch (e) {
    // df 失败时保留全 0
  }

  return disk;
}

// 网速采样：累加 /proc/net/dev 所有接口的 rx_bytes / tx_bytes
function netSample() {
  let rx = 0;
  let tx = 0;
  try {
    const lines = fs.readFileSync('/proc/net/dev', 'utf-8').trim().split('\n');
    for (const line of lines.slice(2)) {
      const idx = line.indexOf(':');
      if (idx === -1) continue;
      const stats = line.slice(idx + 1).trim().split(/\s+/);
      if (stats.length < 9) continue;
      rx += parseInt(stats[0], 10) || 0;
      tx += parseInt(stats[8], 10) || 0;
    }
  } catch (e) {
    // /proc/net/dev 读取失败时保留 0
  }
  return { rx, tx };
}

// 磁盘 I/O 采样：读 /proc/diskstats，取主盘设备（sda/vda 等，不含分区），
// 扇区读/写字段（第 6、10 列）×512 得字节
function diskioSample() {
  let read = 0;
  let write = 0;
  try {
    const lines = fs.readFileSync('/proc/diskstats', 'utf-8').trim().split('\n');
    for (const line of lines) {
      const cols = line.trim().split(/\s+/);
      if (cols.length < 11) continue;
      const name = cols[2];
      // 主盘设备名形如 sd[a-z]/vd[a-z]/hd[a-z]（无分区数字后缀），分区 minor > 0 排除
      if (!/^(sd[a-z]|vd[a-z]|hd[a-z])$/.test(name)) continue;
      if (parseInt(cols[1], 10) !== 0) continue;
      read += parseInt(cols[5], 10) * 512 || 0;
      write += parseInt(cols[9], 10) * 512 || 0;
    }
  } catch (e) {
    // /proc/diskstats 读取失败时保留 0
  }
  return { read, write };
}

// 进程数：解析 /proc/loadavg 第 4 列 running/total
function getProcesses() {
  const proc = { running: 0, total: 0 };
  try {
    const cols = fs.readFileSync('/proc/loadavg', 'utf-8').trim().split(/\s+/);
    if (cols.length >= 4) {
      const m = cols[3].split('/');
      proc.running = parseInt(m[0], 10) || 0;
      proc.total = parseInt(m[1], 10) || 0;
    }
  } catch (e) {
    // 读取失败时保留 0
  }
  return proc;
}

// 模块级采样状态：保存上一次采样 { ts, ... } 用于计算速率
const netState = { ts: 0, rx: 0, tx: 0 };
const diskioState = { ts: 0, read: 0, write: 0 };

// 网络：本次采样与上次采样做差，按时间差换算字节/秒；首次请求速率返回 0
function getNetInfo() {
  const cur = netSample();
  const now = Date.now();
  const dt = (now - netState.ts) / 1000;
  const info = {
    rx_bytes: cur.rx,
    tx_bytes: cur.tx,
    rx_rate: 0,
    tx_rate: 0
  };
  if (netState.ts && dt > 0) {
    info.rx_rate = Math.max(0, (cur.rx - netState.rx) / dt);
    info.tx_rate = Math.max(0, (cur.tx - netState.tx) / dt);
  }
  netState.ts = now;
  netState.rx = cur.rx;
  netState.tx = cur.tx;
  return info;
}

// 磁盘 I/O：同上，返回读/写速率（字节/秒）
function getDiskIoInfo() {
  const cur = diskioSample();
  const now = Date.now();
  const dt = (now - diskioState.ts) / 1000;
  const info = {
    read_bytes: cur.read,
    write_bytes: cur.write,
    read_rate: 0,
    write_rate: 0
  };
  if (diskioState.ts && dt > 0) {
    info.read_rate = Math.max(0, (cur.read - diskioState.read) / dt);
    info.write_rate = Math.max(0, (cur.write - diskioState.write) / dt);
  }
  diskioState.ts = now;
  diskioState.read = cur.read;
  diskioState.write = cur.write;
  return info;
}

// 采集系统信息（CPU 需 ~150ms 双采样）
async function collectSystem() {
  const total = os.totalmem();
  const free = os.freemem();
  const used = total - free;
  return {
    cpu: await getCpuInfo(),
    memory: {
      total,
      used,
      free,
      percent: Math.round((used / total) * 1000) / 10
    },
    disk: getDisk(),
    network: getNetInfo(),
    disk_io: getDiskIoInfo(),
    processes: getProcesses(),
    uptime: os.uptime(),
    os: `${os.type()} ${os.release()} (${os.arch()})`,
    hostname: os.hostname()
  };
}

/* ============ 历史采样（模块级环形 buffer） ============ */

const HISTORY_MAX = 120; // 最多保留 120 个采样点
const HISTORY_INTERVAL_MS = 5000; // 每 5 秒采样一次
const historyBuffer = [];

// 历史数据落盘：多实例共享同一份数据（见 acquireSamplerLock），路由统一读文件返回
const HISTORY_FILE =
  process.env.ADMIN_HISTORY_FILE || path.join(os.tmpdir(), 'admin-server-history.json');

// 采样器锁文件：多个 admin-server 实例共存时只允许一个实例持有采样器，避免重复采样
const SAMPLER_LOCK_FILE =
  process.env.ADMIN_SAMPLER_LOCK || path.join(os.tmpdir(), 'admin-server-sampler.lock');

function isPidAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return !!(e && e.code === 'EPERM'); // 进程存在但当前用户无权限探测
  }
}

// 尝试获取采样器独占锁（返回是否持有）。锁文件记录持有者 pid，
// 若 pid 已失效（进程退出/崩溃遗留的陈旧锁）则视为可抢占
function acquireSamplerLock() {
  try {
    if (fs.existsSync(SAMPLER_LOCK_FILE)) {
      const holder = parseInt(fs.readFileSync(SAMPLER_LOCK_FILE, 'utf-8').trim(), 10);
      if (holder && holder !== process.pid && isPidAlive(holder)) {
        return false; // 已有活跃实例持有采样器
      }
    }
    fs.writeFileSync(SAMPLER_LOCK_FILE, String(process.pid));
    return true;
  } catch (e) {
    return false;
  }
}

// 原子写历史文件（先写临时文件再 rename，避免读端读到半截内容）
function persistHistory() {
  try {
    const tmp = HISTORY_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(historyBuffer));
    fs.renameSync(tmp, HISTORY_FILE);
  } catch (e) {
    // 落盘失败不影响内存 buffer
  }
}

// 读取历史：优先从文件（多实例共享），文件不可用则退回本进程内存 buffer
function readHistory() {
  try {
    const raw = fs.readFileSync(HISTORY_FILE, 'utf-8');
    const arr = JSON.parse(raw);
    if (Array.isArray(arr)) return arr.slice(-HISTORY_MAX);
  } catch (e) {
    // 文件尚未生成/不可读：退回内存 buffer
  }
  return historyBuffer.slice(-HISTORY_MAX);
}

// 采样器自身的上一次原始采样（用于计算两次采样之间的差值速率/使用率）
let histCpuPrev = null
let histCpuEma = null // history CPU 滑动平均;
let histNetPrev = null;
let histDiskioPrev = null;

// 内存使用率（百分比，一位小数）
function memPercent() {
  const total = os.totalmem();
  if (total <= 0) return 0;
  return Math.round(((total - os.freemem()) / total) * 1000) / 10;
}

// 每次采样：CPU/内存为百分比，网速与磁盘 I/O 为两次采样差值换算的速率（字节/秒）。
// 直接读原始计数（cpuSample/netSample/diskioSample），不扰动 /api/admin/system 的独立采样状态
function sampleHistory() {
  const now = Date.now();
  const cpu = cpuSample();
  const net = netSample();
  const io = diskioSample();

  let cpuPercent = 0;
  if (histCpuPrev && now > histCpuPrev.ts) {
    const totalDiff = cpu.total - histCpuPrev.total;
    const idleDiff = cpu.idle - histCpuPrev.idle;
    const raw = totalDiff > 0 ? ((totalDiff - idleDiff) / totalDiff) * 100 : 0;
    // history 采样同样走 EMA 平滑，避免趋势图跳变
    histCpuEma = histCpuEma === null ? raw : histCpuEma * (1 - CPU_EMA_ALPHA) + raw * CPU_EMA_ALPHA;
    cpuPercent = Math.round(histCpuEma * 10) / 10;
  }

  const dtNet = histNetPrev ? (now - histNetPrev.ts) / 1000 : 0;
  const dtIo = histDiskioPrev ? (now - histDiskioPrev.ts) / 1000 : 0;
  const netRxRate = histNetPrev && dtNet > 0 ? Math.max(0, (net.rx - histNetPrev.rx) / dtNet) : 0;
  const netTxRate = histNetPrev && dtNet > 0 ? Math.max(0, (net.tx - histNetPrev.tx) / dtNet) : 0;
  const ioReadRate =
    histDiskioPrev && dtIo > 0 ? Math.max(0, (io.read - histDiskioPrev.read) / dtIo) : 0;
  const ioWriteRate =
    histDiskioPrev && dtIo > 0 ? Math.max(0, (io.write - histDiskioPrev.write) / dtIo) : 0;

  histCpuPrev = { ts: now, idle: cpu.idle, total: cpu.total };
  histNetPrev = { ts: now, rx: net.rx, tx: net.tx };
  histDiskioPrev = { ts: now, read: io.read, write: io.write };

  historyBuffer.push({
    ts: now,
    cpu: cpuPercent,
    mem_percent: memPercent(),
    net_rx_rate: Math.round(netRxRate),
    net_tx_rate: Math.round(netTxRate),
    disk_io_read: Math.round(ioReadRate),
    disk_io_write: Math.round(ioWriteRate)
  });
  if (historyBuffer.length > HISTORY_MAX) historyBuffer.shift();

  persistHistory();
}

// 启动采样器：仅在持有锁的实例上运行（避免多实例重复采样）。
// 启动时立即采一次，之后每 HISTORY_INTERVAL_MS 采一次
if (acquireSamplerLock()) {
  sampleHistory();
  const historyTimer = setInterval(sampleHistory, HISTORY_INTERVAL_MS);
  historyTimer.unref?.();
  process.on('exit', () => {
    try {
      fs.unlinkSync(SAMPLER_LOCK_FILE);
    } catch (e) {
      // 忽略清理失败
    }
  });
  console.log(`[admin-server] 历史采样器已启动（每 ${HISTORY_INTERVAL_MS / 1000}s 一次，最多 ${HISTORY_MAX} 点）`);
}

/* ============ 服务状态检测 ============ */

// 待检测服务：端口监听判定 up/down。admin-server 为自身（恒 up，pid 为本进程）
const SERVICE_CHECKS = [
  { name: 'admin-server', port: PORT, self: true },
  { name: 'hermes-gateway', port: null, kind: 'systemd' },
  { name: 'hermes-serve', port: 9119 },
  { name: 'nginx', port: 80 },
  { name: 'redis', port: 6379 },
  { name: 'cloudreve', port: 5212 },
  { name: 'alist', port: 5244 },
  { name: 'blog', port: 4000 },
  { name: 'admin-test', port: 3101 }
];

// 尝试 TCP 连接目标端口，connect 成功即视为 up
function checkTcpPort(port, host = '127.0.0.1', timeout = 1500) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (ok) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(ok);
    };
    socket.setTimeout(timeout);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', () => finish(false));
    socket.connect(port, host);
  });
}

// 通过 ss -ltnp 反查监听端口的进程 pid（不可用/失败返回 null）
function pidByPort(port) {
  try {
    const out = execSync(
      `ss -ltnp 2>/dev/null | awk '$4 ~ /:${port}$/ {print $6}' | head -1`,
      { encoding: 'utf-8' }
    );
    const m = out.match(/pid=(\d+)/);
    return m ? Number(m[1]) : null;
  } catch (e) {
    return null;
  }
}

// 采集全部服务状态
async function collectServices() {
  const results = await Promise.all(
    SERVICE_CHECKS.map(async (svc) => {
      if (svc.self) {
        return { name: svc.name, status: 'up', pid: process.pid };
      }
      if (svc.kind === 'systemd') {
        // systemd 服务检测：无固定端口（如 hermes-gateway），用 systemctl is-active
        try {
          const out = require('child_process')
            .execSync(`systemctl is-active ${svc.name}.service`, { timeout: 3000 })
            .toString()
            .trim();
          const up = out === 'active';
          return { name: svc.name, status: up ? 'up' : 'down', pid: up ? pidByProcessName(svc.name) : null };
        } catch {
          return { name: svc.name, status: 'down', pid: null };
        }
      }
      const up = await checkTcpPort(svc.port);
      return {
        name: svc.name,
        status: up ? 'up' : 'down',
        pid: up ? pidByPort(svc.port) : null
      };
    })
  );
  return results;
}

// 按进程名反查 pid（systemd 服务用）
function pidByProcessName(name) {
  try {
    const out = require('child_process')
      .execSync(`pgrep -f "${name}" | head -1`, { timeout: 3000 })
      .toString()
      .trim();
    return out ? parseInt(out, 10) : null;
  } catch {
    return null;
  }
}

/* ============ REST 路由 ============ */

app.get('/', (req, res) => {
  res.json({ name: 'admin-server', status: 'ok' });
});

// 登录：TOTP 动态验证码比对（复用 totp-auth 模块的 verifyCode），成功后写入 Redis 独立会话
app.post('/api/admin/login', async (req, res) => {
  const { code } = req.body || {};
  const ip = clientIp(req);
  try {
    // 首次使用：secret 未配置时引导先设置
    const secret = auth.getSecret();
    if (!secret) {
      auditLog('login', ip, false, 'TOTP 未配置');
      return res
        .status(403)
        .json({ error: '首次使用：请先设置 TOTP', code: 'totp_setup_required' });
    }
    // 锁定检查：同一 IP 连续失败已达上限（60s 锁定内），直接 429 拒绝
    const rate = loginRateCheck(ip);
    if (rate.locked) {
      auditLog('login', ip, false, `锁定中（剩余 ${rate.remain}s）`);
      return res.status(429).json({
        error: `尝试过多，请 ${rate.remain} 秒后再试`,
        code: 'rate_limited',
        retryAfter: rate.remain
      });
    }
    if (!auth.verifyCode(secret, code)) {
      const rec = loginRateFail(ip);
      auditLog('login', ip, false, `验证码错误（第 ${rec.count}/${LOGIN_MAX_FAILS} 次）`);
      return res.status(401).json({ error: '验证码错误' });
    }
    // 登录成功：清除该 IP 失败计数，签发会话
    loginRateClear(ip);
    auditLog('login', ip, true, 'ok');
    const token = crypto.randomBytes(32).toString('hex');
    await redis.set(sessionKey(token), token, 'EX', SESSION_TTL);
    res.json({ token });
  } catch (e) {
    auditLog('login', ip, false, '会话服务异常');
    res.status(500).json({ error: '会话服务异常' });
  }
});

// SSO 验证（无鉴权，保留兼容：认证中心签发 token → 建立本地 Redis 会话）。
// 新前端不再调用（直接信任认证中心 token），此处仅服务过渡期/旧客户端。
app.post('/api/admin/sso/verify', async (req, res) => {
  const { token } = req.body || {};
  const ip = clientIp(req);
  if (typeof token !== 'string' || !token) {
    auditLog('sso_verify', ip, false, '缺少 token');
    return res.status(400).json({ error: '缺少 token' });
  }
  let verifyRes;
  try {
    verifyRes = await fetch(
      `${AUTH_CENTER_VERIFY_URL}?token=${encodeURIComponent(token)}`,
      { headers: { Accept: 'application/json' } }
    );
  } catch (e) {
    auditLog('sso_verify', ip, false, '认证中心不可达: ' + e.message);
    return res.status(502).json({ error: '认证中心不可达' });
  }
  if (!verifyRes.ok) {
    auditLog('sso_verify', ip, false, '认证中心拒绝验证');
    return res.status(401).json({ error: '认证中心 token 无效' });
  }
  try {
    // 认证通过：复用现有 session 创建逻辑，签发本地 Redis 会话
    const localToken = crypto.randomBytes(32).toString('hex');
    await redis.set(sessionKey(localToken), localToken, 'EX', SESSION_TTL);
    auditLog('sso_verify', ip, true, 'ok');
    res.json({ token: localToken });
  } catch (e) {
    auditLog('sso_verify', ip, false, '会话服务异常');
    res.status(500).json({ error: '会话服务异常' });
  }
});

// TOTP 重置 / 确认：转发到认证中心（带 Authorization 透传，认证中心校验 Redis 会话），
// 由认证中心执行标准两阶段重置（reset 生成 pending → confirm 验证转正）
const AUTH_CENTER_BASE_URL =
  process.env.AUTH_CENTER_BASE_URL || 'http://127.0.0.1:3200';

function forwardTotp(path) {
  return async (req, res) => {
    const ip = clientIp(req);
    const url = new URL(AUTH_CENTER_BASE_URL + path);
    const header = req.headers.authorization || '';
    const headerToken = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
    const queryToken = req.query && req.query.token ? String(req.query.token) : null;
    const token = headerToken || queryToken;
    if (token) url.searchParams.set('token', token); // 认证中心兼容 header / query 两种透传
    const headers = { Accept: 'application/json', 'Content-Type': 'application/json' };
    if (headerToken) headers.Authorization = header;
    try {
      const upstream = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(req.body || {}),
        signal: AbortSignal.timeout(5000)
      });
      const data = await upstream.json().catch(() => ({}));
      auditLog('totp_' + path.split('/').pop(), ip, upstream.ok, '转发认证中心');
      return res.status(upstream.status).json(data);
    } catch (e) {
      auditLog('totp_' + path.split('/').pop(), ip, false, '认证中心不可达: ' + e.message);
      return res.status(502).json({ error: '认证中心不可达' });
    }
  };
}

app.post('/api/admin/totp/reset', forwardTotp('/api/totp/reset'));
app.post('/api/admin/totp/confirm', forwardTotp('/api/totp/confirm'));

// TOTP 首次设置：挂载 totp-auth 模块路由（无鉴权，secret 已配置则 409）
app.use('/api/admin/totp', (req, res, next) => {
  const ip = clientIp(req);
  res.on('finish', () => {
    if (req.path === '/setup') {
      auditLog('totp_setup', ip, res.statusCode < 400, 'ok');
    }
  });
  next();
}, auth.router);

// 系统信息（需鉴权）。每次请求实时采集，无缓存
app.get('/api/admin/system', authRequired, async (req, res) => {
  try {
    const data = await collectSystem();
    // 请求驱动：每次实时采样也写入历史 buffer，趋势图与上方实时数据同源
    try {
      sampleHistory();
    } catch {
      /* 采样失败不影响主响应 */
    }
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: '获取系统信息失败: ' + e.message });
  }
});

// 历史采样（需鉴权）。返回环形 buffer 中的采样点（最多 120 点），多实例共享
app.get('/api/admin/system/history', authRequired, (req, res) => {
  res.json(readHistory());
});

// 软件版本监控（需鉴权）：只采集本地当前版本，不查外部 latest 接口
const NODE_BIN = '/root/.nvm/versions/node/v24.19.0/bin';

// 版本清洗：去 v/V 前缀、去开头的 epoch（形如 '5:8.0.2-3+deb13u2'，仅当最前为数字+冒号）、
// 取第一个 '-' 前的主版本段。例：'5:8.0.2-3+deb13u2' → '8.0.2'；'v24.19.0' → '24.19.0'
function stripVersion(v) {
  return String(v || '')
    .trim()
    .replace(/^[vV]/, '')
    .replace(/^\d+:/, '')
    .split('-')[0]
    .trim();
}

const VERSION_CHECKS = [
  { name: 'Node.js', category: 'runtime', cmd: `${NODE_BIN}/node --version` },
  { name: 'npm', category: 'runtime', cmd: `PATH=${NODE_BIN}:$PATH ${NODE_BIN}/npm --version` },
  { name: 'Python', category: 'runtime', cmd: "python3 --version 2>&1 | awk '{print $2}'" },
  { name: 'Hermes', category: 'service', cmd: "/usr/local/bin/hermes version 2>/dev/null | head -1 | grep -oE 'v[0-9.]+' | head -1 | sed 's/^v//'" },
  // opencode 当前版本直接读 package.json（opencode --version 需 4.5s，cat 毫秒级）
  { name: 'OpenCode', category: 'service', cmd: "cat /root/.nvm/versions/node/v24.19.0/lib/node_modules/opencode-ai/package.json | grep -m1 '\"version\"' | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+'" },
  // playwright cli 为 #!/usr/bin/env node，需带 PATH 前缀才能在 systemd 精简环境跑通；
  // --version 输出形如 'Version 1.62.1'，提取裸版本号与其他条目格式一致
  { name: 'Playwright', category: 'service', cmd: "PATH=/root/.nvm/versions/node/v24.19.0/bin:$PATH /root/.nvm/versions/node/v24.19.0/bin/playwright --version | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1" },
  { name: 'dida-cli', category: 'service', cmd: "cat /root/.nvm/versions/node/v24.19.0/lib/node_modules/@suibiji/dida-cli/package.json | grep -m1 \"version\" | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+'" },
  { name: 'Cloudreve', category: 'service', cmd: "curl -s --max-time 3 http://127.0.0.1:5212/api/v4/site/ping | python3 -c \"import json,sys; print('v'+json.load(sys.stdin)['data'])\"" },
  { name: 'Alist', category: 'service', cmd: "/root/proj/alist/alist version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | sed 's/^v//'" },
  { name: 'DeepTutor', category: 'service', cmd: '/root/proj/deeptutor/.venv/bin/pip show deeptutor | grep -m1 Version | awk \'{print $2}\'' },
];

// 版本结果缓存：1 秒轮询若每次都执行 VERSION_CHECKS 会堆积重命令进程（如 alist version ~70MB/次），
// 故缓存 60 秒，命中窗口内直接返回上次结果，不再重复执行命令
const VERSION_CACHE_TTL_MS = 60000;
const versionCache = { ts: 0, list: null };

// 并行执行所有本地当前版本命令（Promise.allSettled，单条失败不影响其余），
// 结果统一过 stripVersion 清洗（去 v 前缀、去 epoch、取 '-' 前主版本段）
async function getVersions() {
  const settled = await Promise.allSettled(
    VERSION_CHECKS.map(async (v) => {
      const { stdout } = await execAsync(v.cmd, { encoding: 'utf-8', timeout: 8000 });
      const version = stripVersion(String(stdout).trim().split('\n')[0]) || '未知';
      return { name: v.name, category: v.category, version, ok: true };
    })
  );
  return settled.map((s, i) =>
    s.status === 'fulfilled'
      ? s.value
      : {
          name: VERSION_CHECKS[i].name,
          category: VERSION_CHECKS[i].category,
          version: '未知',
          ok: false
        }
  );
}

// 版本列表（需鉴权）：缓存命中（60 秒内）直接返回，否则重新执行命令并写入缓存
app.get('/api/admin/versions', authRequired, async (req, res) => {
  try {
    const now = Date.now();
    if (!versionCache.list || now - versionCache.ts > VERSION_CACHE_TTL_MS) {
      versionCache.list = await getVersions();
      versionCache.ts = now;
    }
    res.json({ list: versionCache.list });
  } catch (e) {
    res.status(500).json({ error: '获取软件版本失败: ' + e.message });
  }
});

// 服务状态（需鉴权）。返回各服务 [{ name, status: up/down, pid? }]
app.get('/api/admin/services', authRequired, async (req, res) => {
  try {
    const [services, processes] = await Promise.all([collectServices(), collectProcesses()]);
    res.json({ services, processes });
  } catch (e) {
    res.status(500).json({ error: '获取服务状态失败: ' + e.message });
  }
});

// systemd 服务清单：进程识别以 systemctl MainPID 为准（避免命令行参数含服务名造成误判），
// 主 PID 非 0 则记录 pid → 服务名映射，供 collectProcesses 正规化命名
const SYSTEMD_SERVICES = [
  'admin-server',
  'admin-server-test',
  'blog-server',
  'auth-server',
  'deeptutor',
  'cloudreve',
  'alist',
  'nginx',
  'redis-server',
  'hermes-gateway',
  'hermes-serve'
];

// 采集 TOP 内存进程（单列进程排行）：ps 按 RSS 降序取前 15。
// 命名规则：pid 命中 systemd 主进程映射 → 服务名；未命中再按 comm/args 兜底分类
// （opencode / agent-browser / node / python / 其他 comm）
async function collectProcesses() {
  // 1. systemd 正规化：逐服务查 MainPID，非 0 则记录 pid→服务名映射
  const pidToService = new Map();
  await Promise.allSettled(
    SYSTEMD_SERVICES.map(async (svc) => {
      try {
        const { stdout } = await execAsync(`systemctl show ${svc} -p MainPID --value`, {
          encoding: 'utf-8',
          timeout: 3000
        });
        const pid = parseInt(stdout.trim(), 10);
        if (pid > 0) pidToService.set(pid, svc);
      } catch (e) {
        // 单位不存在/查询失败：跳过，该进程走兜底分类
      }
    })
  );

  try {
    const out = execSync(
      "ps -eo pid,comm,rss,pcpu,args --sort=-rss | head -16 | tail -15",
      { encoding: 'utf-8' }
    );
    return out
      .trim()
      .split('\n')
      .map((line) => {
        const m = line.trim().split(/\s+/);
        if (m.length < 5) return null;
        const pid = parseInt(m[0], 10);
        const comm = m[1];
        const args = m.slice(4).join(' ');
        // 进程命名：优先 systemd 主 PID 精确匹配，未命中按 comm/args 兜底分类
        let name;
        if (pidToService.has(pid)) {
          name = pidToService.get(pid);
        } else if (comm === 'opencode' || args.includes('opencode')) {
          name = 'opencode';
        } else if (comm === 'agent-browser' || args.includes('agent-browser')) {
          name = 'agent-browser';
        } else if (comm === 'node' || args.includes('node')) {
          name = 'node';
        } else if (/^python/.test(comm)) {
          name = 'python';
        } else {
          name = comm;
        }
        return {
          name,
          pid,
          mem_mb: Math.round((parseInt(m[2], 10) || 0) / 1024),
          cpu: Math.round((parseFloat(m[3]) || 0) * 10) / 10
        };
      })
      .filter(Boolean);
  } catch {
    return [];
  }
}

// 上传：保存到 uploads 目录，按时间戳命名，限制单文件 100MB
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '';
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

app.post('/api/admin/upload', authRequired, upload.single('file'), (req, res) => {
  if (!req.file) {
    auditLog('upload', clientIp(req), false, '未收到文件');
    return res.status(400).json({ error: '未收到文件（字段名应为 file）' });
  }
  auditLog('upload', clientIp(req), true, req.file.path); // 记录落盘路径
  res.json({ path: req.file.path }); // 返回绝对路径，供 image.attach / file.attach 使用
});

// 下载白名单根目录：AI 回复的文件可能落在 uploads、/root、/tmp、/home、/var/www 等位置
const DOWNLOAD_ALLOWED_BASES = [UPLOAD_DIR, '/root', '/tmp', '/home', '/var/www']
  .map((d) => path.resolve(d))
  .filter((d) => d.startsWith(path.sep));

// 下载：路径 resolve 后必须落在任一白名单目录内，再以附件形式返回
app.get('/api/admin/download', authRequired, (req, res) => {
  const p = req.query.path;
  if (!p || typeof p !== 'string') {
    return res.status(400).json({ error: '缺少 path 参数' });
  }
  // 支持官方 MEDIA:~/path 形态：~ 展开为 home 目录
  const expanded = p.startsWith('~/') ? path.join(os.homedir(), p.slice(2)) : p;
  const resolved = path.resolve(expanded);
  const allowed = DOWNLOAD_ALLOWED_BASES.some(
    (base) => resolved === base || resolved.startsWith(base + path.sep)
  );
  if (!allowed) {
    return res.status(400).json({ error: '路径不在允许范围内' });
  }
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
    return res.status(404).json({ error: '文件不存在' });
  }
  res.download(resolved);
});

// 修改密码（需鉴权）：验证旧密码后更新 config.json，并删除 Redis 会话使所有已登录会话失效
app.post('/api/admin/password', authRequired, async (req, res) => {
  const { old_password, new_password } = req.body || {};
  const ip = clientIp(req);
  if (!verifyPassword(old_password || '', config.get().admin_password)) {
    auditLog('password', ip, false, '旧密码错误');
    return res.status(400).json({ error: '旧密码错误' });
  }
  if (typeof new_password !== 'string' || new_password.length < 6) {
    return res.status(400).json({ error: '新密码至少 6 位' });
  }
  try {
    config.setAdminPassword(new_password);
    auditLog('password', ip, true, '修改密码');
    const keys = await redis.keys(SESSION_KEY_PREFIX + '*');
    if (keys.length) await redis.del(...keys);
    res.json({ ok: true, msg: '密码已修改，请重新登录' });
  } catch (e) {
    auditLog('password', ip, false, '会话服务异常');
    res.status(500).json({ error: '会话服务异常' });
  }
});

// 全局错误处理（multer 体积超限等）
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    return res.status(status).json({ error: '文件过大（上限 100MB）' });
  }
  console.error('[admin-server] 未捕获错误:', err);
  res.status(500).json({ error: '服务器内部错误' });
});

/* ============ WebSocket 桥接 ============ */

const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/api/admin/ws' });

// 从 query 或 Sec-WebSocket-Protocol 中取 token
function extractToken(req) {
  const url = new URL(req.url, 'http://localhost');
  const q = url.searchParams.get('token');
  if (q) return q;
  const proto = req.headers['sec-websocket-protocol'];
  if (proto) return proto.split(',')[0].trim();
  return null;
}

wss.on('connection', async (ws, req) => {
  // 1. 鉴权：优先用 query token 调认证中心 /api/verify 验证（通过即连接）；
  //    失败（token 非认证中心签发/认证中心不可达）降级回旧 Redis 会话校验，兼容过渡期
  const token = extractToken(req);
  if (!token) {
    ws.close(4001, 'missing token');
    return;
  }
  const authOk = await verifyAuthCenterToken(token);
  if (!authOk) {
    try {
      const stored = await redis.get(sessionKey(token));
      if (!stored || stored !== token) {
        ws.close(4001, 'invalid token');
        return;
      }
      await redis.expire(sessionKey(token), SESSION_TTL); // 滑动续期
    } catch (e) {
      ws.close(4001, 'redis error');
      return;
    }
  }

  // 2. 读取 Hermes 令牌并连接网关
  let hermesToken = '';
  try {
    hermesToken = fs.readFileSync(HERMES_TOKEN_FILE, 'utf-8').trim();
  } catch (e) {
    ws.close(5000, 'hermes token missing');
    return;
  }
  const hermes = new WebSocket(
    `${HERMES_WS_URL}?token=${encodeURIComponent(hermesToken)}`
  );

  // 3. 客户端消息缓冲队列：hermes 尚未 OPEN 时先入队，onopen 后按序 flush，
  //    避免客户端连接后立即发 JSON-RPC 请求被静默丢弃导致永久超时
  const pending = [];

  const sendToHermes = (raw) => {
    if (hermes.readyState === WebSocket.OPEN) {
      hermes.send(raw);
      return true;
    }
    return false;
  };

  // 按序 flush 缓冲队列（hermes 中途断开则停在原地，留给 onclose 兜底）
  const flushPending = () => {
    while (pending.length && sendToHermes(pending[0])) {
      pending.shift();
    }
  };

  // 尽量从原始帧中解析出 JSON-RPC id（解析失败视为通知帧，不回 error）
  const getRpcId = (raw) => {
    try {
      const m = JSON.parse(raw);
      return m && m.id != null ? m.id : undefined;
    } catch (e) {
      return undefined;
    }
  };

  // 上游连接失败/关闭：给缓冲中的请求逐个回 JSON-RPC error，避免客户端永久超时
  const failPending = (reason) => {
    let item;
    while ((item = pending.shift()) !== undefined) {
      const id = getRpcId(item);
      if (id !== undefined && ws.readyState === WebSocket.OPEN) {
        ws.send(
          JSON.stringify({ jsonrpc: '2.0', id, error: { code: -32000, message: reason } })
        );
      }
    }
  };

  // 4. 双向透传：JSON 行原样转发
  ws.on('message', (data) => {
    const raw = data.toString();
    if (!sendToHermes(raw)) {
      pending.push(raw); // hermes 未就绪：缓冲等待 flush
    }
  });
  hermes.on('message', (data) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data.toString());
    }
  });

  hermes.on('open', flushPending);

  // 5. 任一端断开即关闭对端
  const closeBoth = (reason) => {
    if (pending.length) failPending(reason || '上游连接已断开');
    if (ws.readyState === WebSocket.OPEN) ws.close();
    if (hermes.readyState === WebSocket.OPEN) hermes.close();
  };
  ws.on('close', () => closeBoth('客户端已断开'));
  ws.on('error', () => closeBoth('客户端连接异常'));
  hermes.on('close', () => closeBoth('Hermes 连接已关闭'));
  hermes.on('error', (err) =>
    closeBoth('Hermes 连接失败: ' + ((err && err.message) || '未知错误'))
  );
});

/* ============ 内部通知（外部平台消息实时通知） ============ */

// 向所有已连接的 WS 客户端广播事件帧（仅 OPEN 连接），返回送达连接数
function broadcastEvent(type, payload) {
  const frame = JSON.stringify({
    jsonrpc: '2.0',
    method: 'event',
    params: { type, payload }
  });
  let sent = 0;
  wss.clients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(frame);
      sent++;
    }
  });
  return sent;
}

// 内部通知接口：供 Hermes pre_gateway_dispatch hook 调用（本机回环 POST，无需 JWT）。
// 校验通过后向所有在线前端 WS 客户端广播 admin.external_message 事件。
app.post('/api/admin/notify', (req, res) => {
  const ip = clientIp(req);
  const remote = req.socket && req.socket.remoteAddress;
  const keyOk = !!ADMIN_NOTIFY_KEY && req.get('x-admin-notify-key') === ADMIN_NOTIFY_KEY;
  if (!isLoopbackAddr(remote) && !keyOk) {
    auditLog('notify', ip, false, '非本机来源被拒绝');
    return res.status(403).json({ error: '仅允许本机或携带共享密钥调用' });
  }
  const { platform, chat_id, text } = req.body || {};
  if (typeof chat_id !== 'string' || !chat_id || typeof text !== 'string') {
    return res.status(400).json({ error: '缺少 chat_id 或 text' });
  }
  const sent = broadcastEvent('admin.external_message', {
    platform: typeof platform === 'string' && platform ? platform : 'weixin',
    chat_id,
    text
  });
  auditLog('notify', ip, true, `platform=${platform} chat=${chat_id} sent=${sent}`);
  res.json({ ok: true, sent });
});

/* ============ 启动 ============ */

server.listen(PORT, HOST, () => {
  console.log(`[admin-server] 已启动，监听地址: ${HOST}:${PORT}`);
  console.log(`[admin-server] 上传目录: ${UPLOAD_DIR}`);
  console.log(`[admin-server] 配置文件: ${config.CONFIG_PATH}`);
  console.log(`[admin-server] 提示: 登录使用 TOTP 动态验证码，secret 见 config.json 的 totp_secret 字段`);
});
