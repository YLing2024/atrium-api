'use strict';

/**
 * admin-server 入口
 *  - REST 接口：登录 / 系统信息 / 上传 / 下载 / 修改密码 / 历史记录浏览（只读）
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { exec, execSync } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);
const crypto = require('crypto');
const express = require('express');
const net = require('net');
const Redis = require('ioredis');
const multer = require('multer');
const { DatabaseSync } = require('node:sqlite');
const { createTotpAuth } = require('totp-auth');
const config = require('./config');

const PORT = parseInt(process.env.PORT, 10) || 3100;
const HOST = process.env.HOST || '0.0.0.0';
const UPLOAD_DIR = process.env.ADMIN_UPLOAD_DIR || path.join(__dirname, '..', 'uploads'); // 上传文件目录
// Hermes 会话数据库（只读浏览历史记录用）；默认取本机 Hermes state.db，可被环境变量覆盖（测试实例隔离）
const HERMES_STATE_DB =
  process.env.HERMES_STATE_DB || path.join(os.homedir(), '.hermes', 'state.db');

// 多会话：Redis key 带 token 后缀（admin:session:<token>），每个会话独立，多端可同时登录
const SESSION_KEY_PREFIX = process.env.ADMIN_REDIS_PREFIX || 'admin:session:';
const SESSION_TTL = 43200; // 12 小时，每次请求校验通过后滑动续期

// 接口令牌：Redis key 前缀 api:token:<sha256(token)>，只存哈希不存明文。
// 固定过期不滑动、绝不进 SESSION_INDEX_SET、不写设备元数据 → 与登录设备管理完全隔离
const API_TOKEN_PREFIX = 'api:token:';
const API_TOKEN_MAX_DAYS = 365;

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

// 十六进制 sha256（接口令牌 key 用：api:token:<sha256(token)>，只存哈希不存明文）
function sha256hex(str) {
  return crypto.createHash('sha256').update(String(str)).digest('hex');
}

// 通用 EMA（指数移动平均）平滑：所有 CPU 值统一走此函数，同参数结果一致。
// prev 为 null/undefined（首次）时直接取 current，避免冷启动跳变
function ema(prev, current, alpha) {
  return prev == null ? current : prev * (1 - alpha) + current * alpha;
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

// 认证中心地址：SSO 兼容接口（/api/admin/sso/verify）校验用
const AUTH_CENTER_VERIFY_URL =
  process.env.AUTH_CENTER_VERIFY_URL || 'http://127.0.0.1:3200/api/verify';

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
      // Redis 会话校验未通过：回退查接口令牌（固定过期、不滑动续期，直连场景也可用）
      const apiKey = API_TOKEN_PREFIX + sha256hex(token);
      const raw = await redis.get(apiKey);
      if (!raw) return res.status(401).json({ error: '未登录或会话已过期' });
      let meta;
      try {
        meta = JSON.parse(raw);
      } catch (e) {
        return res.status(401).json({ error: '未登录或会话已过期' });
      }
      if (!meta || typeof meta.name !== 'string' || !meta.name) {
        return res.status(401).json({ error: '未登录或会话已过期' });
      }
      req.user = { role: 'admin', name: meta.name, via: 'api-token' };
      return next();
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

// 系统卡片 CPU = 全部进程瞬时 CPU 合计（进程合计占用，不含内核/IO），与进程排行同一套算法
function getCpuInfo() {
  const cpus = os.cpus();
  const { totalPct } = collectAllProcCpu();
  return {
    model: cpus[0] ? cpus[0].model.trim() : 'unknown',
    usage_percent: totalPct,
    cores: cpus.length,
    loadavg: os.loadavg()
  };
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

// 解析 /proc/meminfo（单位 kB → bytes）。任一字段缺失回退 os.*，整体失败回退全部 os.*。
// 现文件若干函数直接读 /proc，此处同样直接读文件（fs.existsSync + try/catch 容错，代价可忽略）。
// 返回 { total, used, free, available, buffCache, swapTotal, swapUsed, swapFree, swapPercent }
// 其中 used = 真实占用（= total − available），不含内核可回收的页缓存/缓冲；
// 过去用的 total − free 会把页缓存算成已用，导致面板虚高（本机实测 90% vs 真实 71%）。
function readMeminfo() {
  let info = {};
  try {
    if (fs.existsSync('/proc/meminfo')) {
      const text = fs.readFileSync('/proc/meminfo', 'utf-8');
      for (const line of text.split('\n')) {
        const m = line.match(/^(\w+):\s+(\d+)\s*kB/);
        if (m) info[m[1]] = parseInt(m[2], 10) * 1024;
      }
    }
  } catch (e) {
    info = {};
  }
  const fallbackTotal = os.totalmem();
  const fallbackFree = os.freemem();
  const total = info.MemTotal || fallbackTotal;
  const free = info.MemFree != null ? info.MemFree : fallbackFree;
  const available = info.MemAvailable != null ? info.MemAvailable : null;
  const buffCache =
    info.Buffers != null && info.Cached != null ? info.Buffers + info.Cached : null;
  const swapTotal = info.SwapTotal != null ? info.SwapTotal : 0;
  const swapFree = info.SwapFree != null ? info.SwapFree : 0;
  // used 优先取 total − MemAvailable：MemAvailable 已扣除可回收的页缓存/缓冲，
  // 是内核给出的"还能给新进程用多少"的估算；缺失时回退旧口径 total − free。
  const used = available != null ? total - available : total - free;
  const swapUsed = swapTotal - swapFree;
  return {
    total,
    used,
    free,
    available,
    buffCache,
    swapTotal,
    swapUsed,
    swapFree,
    swapPercent: swapTotal > 0 ? Math.round((swapUsed / swapTotal) * 1000) / 10 : 0
  };
}

// zram 明细：扫描 /sys/block/zram*，磁盘挂 zram 设备时返回首选压缩设备（zram0），
// 其余（zram1/zram2…）仅并入总 swap（来自 /proc/meminfo）。无 zram 返回 null，不影响主流程。
function getZram() {
  try {
    const blocks = fs.readdirSync('/sys/block');
    const zramDevs = blocks.filter((name) => /^zram\d+$/.test(name)).sort();
    if (!zramDevs.length) return null;

    const comp = zramDevs[0]; // 主压缩设备（zram0）
    const readInt = (f) => {
      try {
        return parseInt(fs.readFileSync(`/sys/block/${comp}/${f}`, 'utf-8').trim(), 10) || 0;
      } catch (e) {
        return 0;
      }
    };
    let algorithm = null;
    try {
      const raw = fs
        .readFileSync(`/sys/block/${comp}/comp_algorithm`, 'utf-8')
        .trim();
      const mm = raw.match(/\[([^\]]+)\]/);
      algorithm = (mm ? mm[1] : raw.trim()) || null;
    } catch (e) {
      // 读取失败则 algorithm 保持 null
    }
    // mm_stat 的列定义（Linux zram 文档）：orig_data_size compr_data_size mem_used_total mem_limit
    // mem_used_limit mem_used_max same_pages pages_compacted huge_pages。内核版本差异时 try/catch 兜底为 0。
    let orig = 0;
    let compr = 0;
    let used = 0;
    try {
      const cols = fs.readFileSync(`/sys/block/${comp}/mm_stat`, 'utf-8').trim().split(/\s+/);
      if (cols.length >= 3) {
        orig = parseInt(cols[0], 10) || 0;
        compr = parseInt(cols[1], 10) || 0;
        used = parseInt(cols[2], 10) || 0;
      }
    } catch (e) {
      orig = 0;
      compr = 0;
      used = 0;
    }
    // comprSize：有 mm_stat 用 compr_data_size；老内核无该文件时回退 mem_used_total（含元数据，近似值）
    const comprSize = compr || readInt('mem_used_total') || used;
    return {
      total: readInt('disksize') || 0,
      used,
      origSize: orig || 0,
      comprSize,
      algorithm
    };
  } catch (e) {
    return null;
  }
}

// 解析单个 /proc/pressure/<type> 文件（格式：`some avg10=.. avg60=.. avg300=.. total=..` + full 行）。
// 文件不存在/解析失败（老内核或容器无 PSI）返回 null，不影响主流程。
function parsePressureFile(type) {
  try {
    if (!fs.existsSync(`/proc/pressure/${type}`)) return null;
    const text = fs.readFileSync(`/proc/pressure/${type}`, 'utf-8');
    const res = {};
    for (const line of text.split('\n')) {
      const m = line
        .trim()
        .match(/^(some|full)\s+avg10=([\d.]+)\s+avg60=([\d.]+)\s+avg300=([\d.]+)\s+total=(\d+)/);
      if (!m) continue;
      res[m[1]] = {
        avg10: parseFloat(m[2]),
        avg60: parseFloat(m[3]),
        avg300: parseFloat(m[4]),
        total: parseInt(m[5], 10)
      };
    }
    return res.some && res.full ? res : null;
  } catch (e) {
    return null;
  }
}

// PSI（Pressure Stall Information）：进程因等内存/CPU/IO 被 stall 的时间占比。
// some=至少一个任务被 stall，full=所有任务都被 stall（更严重）；avg 为滑动平均百分比，total 为累计微秒。
// 返回 { memory, cpu, io }，各自 { some, full } 或 null（无 PSI 的资源）
function readPressure() {
  return {
    memory: parsePressureFile('memory'),
    cpu: parsePressureFile('cpu'),
    io: parsePressureFile('io')
  };
}

// 采集系统信息（CPU 需 ~1s 双采样）
async function collectSystem() {
  const mem = readMeminfo();
  // 内存 percent = 真实占用 (total − available) / total，口径与 free -h 的 available 一致，
  // 不再把可回收的页缓存算成已用；历史曲线会因此整体下移（预期变化）。
  const percent = mem.total > 0 ? Math.round((mem.used / mem.total) * 1000) / 10 : 0;
  return {
    cpu: getCpuInfo(),
    memory: {
      total: mem.total,
      used: mem.used,
      free: mem.free,
      percent,
      buffCache: mem.buffCache,
      available: mem.available,
      swapTotal: mem.swapTotal,
      swapUsed: mem.swapUsed,
      swapFree: mem.swapFree,
      swapPercent: mem.swapPercent,
      zram: getZram()
    },
    disk: getDisk(),
    network: getNetInfo(),
    disk_io: getDiskIoInfo(),
    processes: getProcesses(),
    psi: readPressure(),
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

const CPU_EMA_ALPHA = 0.4; // 统一 EMA 平滑系数：系统卡片 / 进程排行 / 历史趋势全走同一函数同一参数

// 内存使用率（百分比，一位小数）—— 真实占用口径：total − MemAvailable
// 与 collectSystem()/free -h 的 available 一致（不含可回收的页缓存）
function memPercent() {
  try {
    const text = fs.readFileSync('/proc/meminfo', 'utf-8');
    const kv = {};
    for (const line of text.split('\n')) {
      const m = line.match(/^(\w+):\s+(\d+)\s*kB/);
      if (m) kv[m[1]] = parseInt(m[2], 10) * 1024;
    }
    if (kv.MemTotal > 0 && kv.MemAvailable != null) {
      return Math.round(((kv.MemTotal - kv.MemAvailable) / kv.MemTotal) * 1000) / 10;
    }
  } catch (e) {
    // /proc/meminfo 不可读时走下面回退
  }
  const total = os.totalmem();
  if (total <= 0) return 0;
  return Math.round(((total - os.freemem()) / total) * 1000) / 10;
}

// swap 使用率（百分比，一位小数）：/proc/meminfo SwapTotal/SwapFree（含 zram+file+分区）；
// 解析失败或总 swap 为 0 返回 0，不影响历史采样
function swapPercent() {
  try {
    const info = {};
    const text = fs.readFileSync('/proc/meminfo', 'utf-8');
    for (const line of text.split('\n')) {
      const m = line.match(/^(\w+):\s+(\d+)\s*kB/);
      if (m) info[m[1]] = parseInt(m[2], 10) * 1024;
    }
    const total = info.SwapTotal || 0;
    const free = info.SwapFree != null ? info.SwapFree : 0;
    if (total <= 0) return 0;
    return Math.round(((total - free) / total) * 1000) / 10;
  } catch (e) {
    return 0;
  }
}

// PSI 历史取值：memory/cpu/io 的 some avg10（percent，native 已是滑动均值）
function psiHistPoint() {
  const p = readPressure();
  const avg = (o) => (o && o.some && Number.isFinite(o.some.avg10) ? o.some.avg10 : null);
  return { psi_mem_avg10: avg(p.memory), psi_cpu_avg10: avg(p.cpu), psi_io_avg10: avg(p.io) };
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
    // history 采样同样走统一 EMA 平滑，避免趋势图跳变
    histCpuEma = ema(histCpuEma, raw, CPU_EMA_ALPHA);
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

  const psi = psiHistPoint();

  historyBuffer.push({
    ts: now,
    cpu: cpuPercent,
    mem_percent: memPercent(),
    swap_percent: swapPercent(),
    psi_mem_avg10: psi.psi_mem_avg10,
    psi_cpu_avg10: psi.psi_cpu_avg10,
    psi_io_avg10: psi.psi_io_avg10,
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

// 已登录设备管理：转发到认证中心 /api/sessions*（列表 / 重命名 / 删除）。
// 方法/query/Authorization 透传；GET 无 body，PUT/DELETE 带 JSON body；
// token 同时拼到 query（认证中心兼容 header / query 两种透传）
function forwardSessions(req, res) {
  const ip = clientIp(req);
  const url = new URL(AUTH_CENTER_BASE_URL + '/api/sessions' + req.path);
  const header = req.headers.authorization || '';
  const headerToken = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
  const queryToken = req.query && req.query.token ? String(req.query.token) : null;
  const token = headerToken || queryToken;
  if (token) url.searchParams.set('token', token); // 认证中心兼容 header / query 两种透传
  const headers = { Accept: 'application/json' };
  if (headerToken) headers.Authorization = header;
  const opts = { method: req.method, headers, signal: AbortSignal.timeout(5000) };
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(req.body || {});
  }
  const action =
    req.method === 'GET' ? 'list' : req.method === 'PUT' ? 'rename' : req.method === 'DELETE' ? 'delete' : req.method.toLowerCase();
  fetch(url, opts)
    .then(async (upstream) => {
      const data = await upstream.json().catch(() => ({}));
      auditLog('sessions_' + action, ip, upstream.ok, '转发认证中心');
      return res.status(upstream.status).json(data);
    })
    .catch((e) => {
      auditLog('sessions_' + action, ip, false, '认证中心不可达: ' + e.message);
      return res.status(502).json({ error: '认证中心不可达' });
    });
}

app.use('/api/admin/sessions', authRequired, forwardSessions);

/* ============ 接口令牌管理（API Token，与登录设备会话完全隔离） ============ */

function apiTokenKey(id) {
  return API_TOKEN_PREFIX + id;
}

// 解析 api:token: 值的 JSON；返回 null 表示数据异常
function parseApiTokenMeta(raw) {
  if (!raw) return null;
  try {
    const meta = JSON.parse(raw);
    if (!meta || typeof meta.id !== 'string' || typeof meta.name !== 'string') return null;
    return meta;
  } catch (e) {
    return null;
  }
}

// GET /api/admin/api-tokens —— 列表（绝不含 token 明文），按 createdAt 倒序
app.get('/api/admin/api-tokens', authRequired, async (req, res) => {
  const ip = clientIp(req);
  try {
    const keys = await redis.keys(API_TOKEN_PREFIX + '*');
    const tokens = [];
    for (const key of keys) {
      const meta = parseApiTokenMeta(await redis.get(key));
      if (!meta) continue;
      tokens.push({
        id: meta.id,
        name: meta.name,
        note: meta.note || '',
        createdAt: Number(meta.createdAt) || 0,
        expiresAt: Number(meta.expiresAt) || 0,
        lastUsedAt: Number(meta.lastUsedAt) || 0
      });
    }
    tokens.sort((a, b) => b.createdAt - a.createdAt);
    auditLog('api_tokens_list', ip, true, `count=${tokens.length}`);
    return res.json({ tokens });
  } catch (e) {
    auditLog('api_tokens_list', ip, false, e.message);
    return res.status(500).json({ error: '获取接口令牌失败' });
  }
});

// POST /api/admin/api-tokens —— 生成令牌；明文仅此一次返回
app.post('/api/admin/api-tokens', authRequired, async (req, res) => {
  const ip = clientIp(req);
  const name = String((req.body && req.body.name) || '').trim();
  const note = String((req.body && req.body.note) || '').trim();
  const rawDays = req.body && req.body.expiresInDays != null ? req.body.expiresInDays : 30;
  const days = Number(rawDays);
  if (!name) {
    return res.status(400).json({ error: '令牌名称不能为空' });
  }
  if (!Number.isInteger(days) || days < 1 || days > API_TOKEN_MAX_DAYS) {
    return res.status(400).json({ error: '有效期需为 1~365 天的整数' });
  }
  try {
    const token = crypto.randomBytes(32).toString('hex'); // 64 位 hex 明文，仅此一次展示
    const id = sha256hex(token); // id = sha256 全文
    const now = Date.now();
    const expiresAt = now + days * 86400000;
    const meta = { id, name, note, createdAt: now, expiresAt, lastUsedAt: 0 };
    await redis.set(apiTokenKey(id), JSON.stringify(meta), 'EX', days * 86400); // 固定过期，不滑动
    auditLog('api_tokens_create', ip, true, `id=${id} name=${name} days=${days}`);
    return res.json({ id, token, meta });
  } catch (e) {
    auditLog('api_tokens_create', ip, false, e.message);
    return res.status(500).json({ error: '生成接口令牌失败' });
  }
});

// PATCH /api/admin/api-tokens/:id —— 改名 / 改备注 / 重设有效期（重设则 TTL 一并刷新）
app.patch('/api/admin/api-tokens/:id', authRequired, async (req, res) => {
  const ip = clientIp(req);
  const id = req.params.id;
  try {
    const meta = parseApiTokenMeta(await redis.get(apiTokenKey(id)));
    if (!meta) {
      return res.status(404).json({ error: '接口令牌不存在或已过期' });
    }
    const body = req.body || {};
    if (body.name != null) {
      const name = String(body.name).trim();
      if (!name) return res.status(400).json({ error: '令牌名称不能为空' });
      meta.name = name;
    }
    if (body.note != null) meta.note = String(body.note).trim();
    if (body.expiresInDays != null) {
      const days = Number(body.expiresInDays);
      if (!Number.isInteger(days) || days < 1 || days > API_TOKEN_MAX_DAYS) {
        return res.status(400).json({ error: '有效期需为 1~365 天的整数' });
      }
      meta.expiresAt = Date.now() + days * 86400000; // 重设有效期：expiresAt = now + days
    }
    const ttl = Math.max(1, Math.floor((Number(meta.expiresAt) - Date.now()) / 1000));
    await redis.set(apiTokenKey(id), JSON.stringify(meta), 'EX', ttl);
    auditLog('api_tokens_update', ip, true, `id=${id}`);
    return res.json({
      id: meta.id,
      name: meta.name,
      note: meta.note,
      createdAt: Number(meta.createdAt),
      expiresAt: Number(meta.expiresAt),
      lastUsedAt: Number(meta.lastUsedAt)
    });
  } catch (e) {
    auditLog('api_tokens_update', ip, false, e.message);
    return res.status(500).json({ error: '更新接口令牌失败' });
  }
});

// DELETE /api/admin/api-tokens/:id —— 吊销，立即失效
app.delete('/api/admin/api-tokens/:id', authRequired, async (req, res) => {
  const ip = clientIp(req);
  const id = req.params.id;
  try {
    await redis.del(apiTokenKey(id));
    auditLog('api_tokens_delete', ip, true, `id=${id}`);
    return res.json({ ok: true });
  } catch (e) {
    auditLog('api_tokens_delete', ip, false, e.message);
    return res.status(500).json({ error: '吊销接口令牌失败' });
  }
});

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

// 组装系统信息（REST 端点与 SSE 快照共用）：实时采集系统信息，
// 请求驱动同步写入历史 buffer，保证趋势图与上方实时数据同源
async function buildSystemPayload() {
  const data = await collectSystem();
  try {
    sampleHistory();
  } catch {
    /* 采样失败不影响主响应 */
  }
  return data;
}

// 组装服务状态（REST 端点与 SSE 快照共用）
async function buildServicesPayload() {
  const [services, result] = await Promise.all([collectServices(), collectProcesses()]);
  return { services, processes: result.processes, total_cpu: result.total_cpu };
}

// 系统信息（需鉴权）。每次请求实时采集，无缓存
app.get('/api/admin/system', authRequired, async (req, res) => {
  try {
    res.json(await buildSystemPayload());
  } catch (e) {
    res.status(500).json({ error: '获取系统信息失败: ' + e.message });
  }
});

// 历史采样（需鉴权）。返回环形 buffer 中的采样点（最多 120 点），多实例共享
app.get('/api/admin/system/history', authRequired, (req, res) => {
  res.json(readHistory());
});

// SSE 实时快照（需鉴权）：系统信息 + 服务状态 + 历史采样合并推送。
// 前端「系统」Tab 激活时才建连、切走即断开（req close 停表），替代前端三组 1s 轮询。
app.get('/api/admin/system/stream', authRequired, (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no' // 禁 nginx 缓冲，保证实时
  });
  res.flushHeaders();

  let tick = 0;
  let pushing = false;

  // 单条 snapshot：system / services / history 一次组装推送；
  // pushing 防抖避免采集慢于推送间隔时 setInterval 重叠堆积
  async function push() {
    if (pushing) return;
    pushing = true;
    try {
      const [system, services, history] = await Promise.all([
        buildSystemPayload(),
        buildServicesPayload(),
        Promise.resolve(readHistory())
      ]);
      res.write(
        'event: snapshot\ndata: ' + JSON.stringify({ system, services, history }) + '\n\n'
      );
      tick += 1;
      // 每 10 tick（约 30s）补一条注释行，防代理超时
      if (tick % 10 === 0) res.write(': ping\n\n');
    } catch (e) {
      // 单次采集失败不中断流，下个 tick 重试
    } finally {
      pushing = false;
    }
  }

  // 连接建立后立即推送第一条，之后每 1s 推送
  push();
  const timer = setInterval(push, 1000);

  // 客户端断开 / 切走 Tab：停表，不再推送
  req.on('close', () => clearInterval(timer));
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
  // 2.0 起包名由 opencode-ai 改为 @opencode/cli（全局安装路径随包名变）
  { name: 'OpenCode', category: 'service', cmd: "cat /root/.nvm/versions/node/v24.19.0/lib/node_modules/@opencode/cli/package.json | grep -m1 '\"version\"' | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+'" },
  // codex CLI 版本直接读 package.json（codex --version 输出 'codex-cli x.y.z' 格式，cat 更稳）
  { name: 'Codex', category: 'service', cmd: "cat /root/.nvm/versions/node/v24.19.0/lib/node_modules/@openai/codex/package.json | grep -m1 '\"version\"' | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+'" },
  // playwright cli 为 #!/usr/bin/env node，需带 PATH 前缀才能在 systemd 精简环境跑通；
  // --version 输出形如 'Version 1.62.1'，提取裸版本号与其他条目格式一致
  { name: 'Playwright', category: 'service', cmd: "PATH=/root/.nvm/versions/node/v24.19.0/bin:$PATH /root/.nvm/versions/node/v24.19.0/bin/playwright --version | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1" },
  { name: 'dida-cli', category: 'service', cmd: "cat /root/.nvm/versions/node/v24.19.0/lib/node_modules/@suibiji/dida-cli/package.json | grep -m1 \"version\" | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+'" },
  { name: 'Cloudreve', category: 'service', cmd: "curl -s --max-time 3 http://127.0.0.1:5212/api/v4/site/ping | python3 -c \"import json,sys; print('v'+json.load(sys.stdin)['data'])\"" },
  { name: 'DeepTutor', category: 'service', cmd: '/root/proj/deeptutor/.venv/bin/pip show deeptutor | grep -m1 Version | awk \'{print $2}\'' },
];

// 版本结果缓存：1 秒轮询若每次都执行 VERSION_CHECKS 会堆积重命令进程，
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

// 服务状态（需鉴权）。返回各服务 [{ name, status: up/down, pid? }]、
// 进程排行 TOP15 与全部进程瞬时 CPU 合计 total_cpu（与系统卡片同口径）。
// collectProcesses 内部做单次 /proc 全量遍历，进程 cpu 与 total_cpu 同源同基准
app.get('/api/admin/services', authRequired, async (req, res) => {
  try {
    res.json(await buildServicesPayload());
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
  'nginx',
  'redis-server',
  'hermes-gateway',
  'hermes-serve'
];

// 模块级进程瞬时 CPU 采样状态：pid -> { cpu, total }（上次 /proc 采样值，单位 clock ticks）
const procCpuSample = new Map();

// 进程 CPU 与总占用 CPU 的 EMA 平滑状态（pid -> 上次平滑值；totalEmaPrev -> 总占用平滑值）
const procCpuEma = new Map();
let totalEmaPrev = null;

// 读 /proc/<pid>/stat，返回进程已用 CPU ticks（utime+stime，字段 14/15）；
// 进程名可能含空格，取最后一个 ')' 后的字段再按空格分割，字段 3 起偏移 3
function procCpuTicks(pid) {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf-8');
    const close = stat.lastIndexOf(')');
    if (close === -1) return null;
    const rest = stat.slice(close + 1).trim().split(/\s+/);
    // rest[0]=字段3(state)，字段14 utime → rest[11]，字段15 stime → rest[12]
    const utime = parseInt(rest[11], 10) || 0;
    const stime = parseInt(rest[12], 10) || 0;
    return utime + stime;
  } catch (e) {
    return null; // /proc/<pid> 不存在或读取失败
  }
}

// 读 /proc/stat 第一行（cpu 开头），字段 2-5 user+nice+system+idle 求和为系统总时间
function procTotalTicks() {
  try {
    const first = fs.readFileSync('/proc/stat', 'utf-8').split('\n')[0];
    const cols = first.trim().split(/\s+/);
    if (cols[0] !== 'cpu' || cols.length < 5) return null;
    return (
      (parseInt(cols[1], 10) || 0) +
      (parseInt(cols[2], 10) || 0) +
      (parseInt(cols[3], 10) || 0) +
      (parseInt(cols[4], 10) || 0)
    );
  } catch (e) {
    return null;
  }
}

// 单次遍历 /proc/[pid]（仅数字目录），对每个 pid 用 procCpuSample Map 做差分（复用
// procCpuTicks/procTotalTicks）得到原始瞬时值后，perPid 与 totalPct 均走统一 EMA 平滑
// （ema(prev,current,CPU_EMA_ALPHA)），输出保留一位小数，避免 0/100 跳变。
// 首次采样（pid 无上一轮状态）无差值：pct 记为 0（collectProcesses 对不在遍历结果内的
// pid 再用 ps pcpu 兜底）。返回值 { perPid: Map<pid, pct>, totalPct }。
function collectAllProcCpu() {
  const curTotal = procTotalTicks();
  const perPid = new Map();
  if (curTotal === null) return { perPid, totalPct: 0 };
  let names;
  try {
    names = fs.readdirSync('/proc');
  } catch (e) {
    return { perPid, totalPct: 0 };
  }
  let sumTicks = 0;
  let dTotal = 0;
  let hasPrev = false;
  for (const name of names) {
    if (!/^\d+$/.test(name)) continue; // 仅数字目录（进程 pid）
    const pid = parseInt(name, 10);
    const curCpu = procCpuTicks(pid);
    if (curCpu === null) {
      procCpuSample.delete(pid); // 进程已退出：清采样与平滑缓存
      procCpuEma.delete(pid);
      continue;
    }
    const last = procCpuSample.get(pid);
    let pct = 0;
    if (last && curTotal > last.total) {
      const dCpu = curCpu - last.cpu;
      if (dCpu >= 0) {
        sumTicks += dCpu;
        if (!dTotal) dTotal = curTotal - last.total; // 系统总时间差值，本轮全局一致
        pct = (dCpu / dTotal) * 100; // 原始瞬时占用（未舍入）
        hasPrev = true;
      }
    }
    procCpuSample.set(pid, { cpu: curCpu, total: curTotal });
    // 每个 pid 走统一 EMA 平滑（同函数同 alpha），输出保留一位小数
    const smoothed = ema(procCpuEma.get(pid), pct, CPU_EMA_ALPHA);
    procCpuEma.set(pid, smoothed);
    perPid.set(pid, Math.round(smoothed * 10) / 10);
  }
  let totalPct = 0;
  if (hasPrev && dTotal > 0) {
    // 总占用走统一 EMA（对原始瞬时总占用平滑，与各进程同函数同 alpha）
    const smoothed = ema(totalEmaPrev, (sumTicks / dTotal) * 100, CPU_EMA_ALPHA);
    totalEmaPrev = smoothed;
    totalPct = Math.round(smoothed * 10) / 10;
  }
  return { perPid, totalPct };
}

// 采集 TOP 内存进程（单列进程排行）：ps 按 RSS 降序取前 15。
// 命名规则：pid 命中 systemd 主进程映射 → 服务名；未命中再按 comm/args 兜底分类
// （opencode / agent-browser / node / python / 其他 comm）。
// CPU 统一走 collectAllProcCpu() 的单次 /proc 全量遍历：各进程 cpu 直接取 perPid.get(pid)，
// total_cpu 取 totalPct，同一请求内两者同源、同差分基准，不再各自采样。
// 返回 { processes: [...], total_cpu }。
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

  // 2. 单次遍历 /proc 全部进程差分：perPid 与 totalPct 同源（此后再不单独差分）
  const { perPid, totalPct } = collectAllProcCpu();

  try {
    const out = execSync(
      "ps -eo pid,comm,rss,pcpu,args --sort=-rss | head -16 | tail -15",
      { encoding: 'utf-8' }
    );
    const processes = out
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
        // 进程瞬时 CPU：直接用本轮 collectAllProcCpu 的 perPid（与 total_cpu 同一次遍历、
        // 同一差分基准）；pid 不在遍历结果内（/proc/<pid>/stat 读取失败的极端情况）用 ps pcpu 兜底
        const pct = perPid.get(pid);
        const cpu =
          pct != null ? pct : Math.round((parseFloat(m[3]) || 0) * 10) / 10;
        return {
          name,
          pid,
          mem_mb: Math.round((parseInt(m[2], 10) || 0) / 1024),
          cpu
        };
      })
      .filter(Boolean);
    return { processes, total_cpu: totalPct };
  } catch {
    return { processes: [], total_cpu: totalPct };
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

/* ============ 历史记录浏览（只读） ============ */

// 只读历史会话列表：数据源为 Hermes state.db（以 readOnly 打开），
// 每次请求独立 open → query → close，避免长期占用 WAL 锁（Hermes 网关并发写同一库）。
// 数据库不可用仅影响本接口，不影响其它接口与进程启动
app.get('/api/admin/history', authRequired, (req, res) => {
  const ip = clientIp(req);
  let db;
  try {
    db = new DatabaseSync(HERMES_STATE_DB, { readOnly: true });
  } catch (e) {
    auditLog('history_list', ip, false, '数据库不可用: ' + e.message);
    return res.status(503).json({ error: '历史记录暂不可用' });
  }
  try {
    const rows = db
      .prepare(
        `SELECT id, title, display_name, started_at, last_activity_at, message_count, session_key
         FROM sessions ORDER BY last_activity_at DESC`
      )
      .all();
    const sessions = rows.map((r) => {
      const title = r.title || r.display_name || r.id;
      const raw = r.last_activity_at != null ? r.last_activity_at : r.started_at;
      return {
        id: r.id,
        title,
        time: raw != null ? Math.round(raw * 1000) : null,
        message_count: r.message_count
      };
    });
    auditLog('history_list', ip, true, `sessions=${sessions.length}`);
    res.json({ sessions });
  } catch (e) {
    auditLog('history_list', ip, false, e.message);
    res.status(500).json({ error: '获取历史会话失败' });
  } finally {
    try {
      db.close();
    } catch (e) {
      // 关闭失败忽略
    }
  }
});

// 只读单个会话消息：仅保留 user/assistant 角色，按 id 升序
app.get('/api/admin/history/:id', authRequired, (req, res) => {
  const ip = clientIp(req);
  const id = req.params.id;
  let db;
  try {
    db = new DatabaseSync(HERMES_STATE_DB, { readOnly: true });
  } catch (e) {
    auditLog('history_messages', ip, false, '数据库不可用: ' + e.message);
    return res.status(503).json({ error: '历史记录暂不可用' });
  }
  try {
    const session = db
      .prepare(`SELECT id, title, display_name FROM sessions WHERE id = ?`)
      .get(id);
    if (!session) {
      auditLog('history_messages', ip, false, '会话不存在: ' + id);
      return res.status(404).json({ error: '会话不存在' });
    }
    const rows = db
      .prepare(
        `SELECT role, content, timestamp FROM messages
         WHERE session_id = ? AND role IN ('user','assistant') ORDER BY id ASC`
      )
      .all(id);
    const messages = rows.map((r) => ({
      role: r.role,
      content: r.content,
      ts: r.timestamp != null ? Math.round(r.timestamp * 1000) : null
    }));
    auditLog('history_messages', ip, true, `session=${id} messages=${messages.length}`);
    res.json({
      session: { id: session.id, title: session.title || session.display_name || session.id },
      messages
    });
  } catch (e) {
    auditLog('history_messages', ip, false, e.message);
    res.status(500).json({ error: '获取会话消息失败' });
  } finally {
    try {
      db.close();
    } catch (e) {
      // 关闭失败忽略
    }
  }
});

/* ============ 启动 ============ */

app.listen(PORT, HOST, () => {
  console.log(`[admin-server] 已启动，监听地址: ${HOST}:${PORT}`);
  console.log(`[admin-server] 上传目录: ${UPLOAD_DIR}`);
  console.log(`[admin-server] 配置文件: ${config.CONFIG_PATH}`);
  console.log(`[admin-server] 提示: 登录使用 TOTP 动态验证码，secret 见 config.json 的 totp_secret 字段`);
});
