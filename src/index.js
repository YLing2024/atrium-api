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
// 文件区：admin「文件」Tab 的上传落点。独立于 uploads/，专用于把文件传给 Hermes（保留原始文件名）
const FILE_DIR = process.env.ADMIN_FILE_DIR || '/root/files/download';
const FILE_MAX_BYTES = 500 * 1024 * 1024; // 单文件上限 500MB（与 /api/admin/upload 的 100MB 相互独立）
// 文件区根目录这一层的保护名单，分两类：
//  · FILE_ROOT_PROTECTED —— 系统文件，不展示、也不允许任何写操作命中其整棵子树（swapfile / lost+found / cache）
//  · FILE_ROOT_READONLY  —— 收纳目录，正常展示、可浏览，但「根这一层的那一项」不允许被删/改名/移动，子路径照常读写
// 两者都只作用于根目录这一层：子目录中的同名文件（如 <root>/backup/swapfile）不受影响。
const FILE_ROOT_PROTECTED = new Set(['swapfile', 'lost+found', 'cache']);
const FILE_ROOT_READONLY = new Set(['toolchains', 'apps', 'build', 'www', 'files', 'backups', 'siyuan']);
try {
  fs.mkdirSync(FILE_DIR, { recursive: true });
} catch (e) {
  console.error('[admin-server] 文件区目录创建失败:', e.message);
}
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
  // nginx 统一注入 X-Real-IP（admin-server 只监听 127.0.0.1，客户端无法伪造）；
  // 不读它的话 req.ip 恒为 127.0.0.1 —— 限流会退化成全局限流、审计日志也丢来源 IP
  const xr = req.headers['x-real-ip'];
  if (xr && String(xr).trim()) return String(xr).trim();
  const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  if (xf) return xf;
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

// 鉴权中间件：
//   用户身份只认 Auth Gateway 注入的请求头 `X-Auth-User`（网关会先剥掉客户端伪造的同名头）。
//   存在且非空 → 通过并把 req.user 设为其值；缺失/为空 → 401（不 302、不 500）。
//   兼容旧客户端/自动化脚本所需的本地会话与接口令牌已不再作为本中间件的凭证来源。
async function authRequired(req, res, next) {
  const xAuthUser = req.get('x-auth-user');
  if (xAuthUser && String(xAuthUser).trim()) {
    req.user = { role: 'admin', name: String(xAuthUser).trim(), via: 'gateway' };
    return next();
  }
  return res.status(401).json({ error: '未登录' });
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

// 每核 CPU 展示上限：最多返回 MAX_CORES 项（超出截断；cores 字段仍报真实核数）
const MAX_CORES = 8;

// 每核采样状态：保存上一次 /proc/stat 各核累计值，用于两次采样做差（首次无样本时该核返回 0）
let cpuPerCoreState = null;

// 每核 CPU 占用：读 /proc/stat 的 cpuN 行，累加 user/nice/system/idle/iowait/irq/softirq/steal，
// 与上次采样做差按 (Δtotal − Δidle) / Δtotal × 100 计算（内核口径，含内核与 IO 等待时间）。
// 读取失败时返回空数组，不影响接口。
function cpuPerCoreSample() {
  const cores = [];
  try {
    const lines = fs.readFileSync('/proc/stat', 'utf-8').split('\n');
    const cur = [];
    for (const line of lines) {
      if (!/^cpu\d+\s/.test(line)) continue;
      const cols = line.trim().split(/\s+/);
      const fields = cols.slice(1).map((v) => parseInt(v, 10) || 0);
      if (fields.length < 8) continue;
      cur.push({
        id: parseInt(cols[0].slice(3), 10),
        total: fields.slice(0, 8).reduce((a, b) => a + b, 0),
        idle: fields[3] + fields[4] // idle + iowait
      });
    }
    for (const c of cur.slice(0, MAX_CORES)) {
      let usage = 0;
      const prev = cpuPerCoreState && cpuPerCoreState[c.id];
      const dt = prev ? c.total - prev.total : 0;
      if (dt > 0) usage = ((dt - (c.idle - prev.idle)) / dt) * 100;
      usage = Math.max(0, Math.min(100, usage));
      cores.push({ id: c.id, usage_percent: Math.round(usage * 10) / 10 });
    }
    cpuPerCoreState = {};
    for (const c of cur) cpuPerCoreState[c.id] = c;
  } catch (e) {
    // /proc/stat 读取失败时返回空数组
    return [];
  }
  return cores;
}

// 系统卡片 CPU = 全部进程瞬时 CPU 合计（进程合计占用，不含内核/IO），与进程排行同一套算法
function getCpuInfo() {
  const cpus = os.cpus();
  const { totalPct } = collectAllProcCpu();
  return {
    model: cpus[0] ? cpus[0].model.trim() : 'unknown',
    usage_percent: totalPct,
    cores: cpus.length,
    per_core: cpuPerCoreSample(),
    loadavg: os.loadavg()
  };
}

// 磁盘（多盘）：解析 df -kP，返回所有真实挂载的设备盘（filesystem 以 /dev/ 开头，
// 排除 tmpfs/udev/overlay 等伪文件系统），跳过 /boot、/boot/efi 系统分区；
// 单位字节，df 失败时返回空数组。
function getDisks() {
  const disks = [];
  try {
    const out = execSync('df -kP', { encoding: 'utf-8' }).trim().split('\n');
    for (const line of out.slice(1)) {
      const cols = line.split(/\s+/);
      if (cols.length < 6) continue;
      const filesystem = cols[0];
      const mount = cols.slice(5).join(' '); // 挂载点可能含空格
      if (!filesystem.startsWith('/dev/')) continue;
      if (mount === '/boot' || mount === '/boot/efi') continue;
      disks.push({
        filesystem,
        mount,
        total: parseInt(cols[1], 10) * 1024,
        used: parseInt(cols[2], 10) * 1024,
        free: parseInt(cols[3], 10) * 1024,
        percent: parseInt(String(cols[4]).replace('%', ''), 10) || 0
      });
    }
  } catch (e) {
    // df 失败时返回空数组
  }

  return disks;
}

// 磁盘（单盘兼容）：旧字段 disk 只取挂载点为 '/' 的盘，内部复用 getDisks()，
// 找不到时保持全 0（该字段/形状可能被前端旧代码与其它分支引用）。
function getDisk() {
  const disk = { total: 0, used: 0, free: 0, percent: 0 };
  const root = getDisks().find((d) => d.mount === '/');
  if (root) {
    disk.total = root.total;
    disk.used = root.used;
    disk.free = root.free;
    disk.percent = root.percent;
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
    disks: getDisks(),
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

/* ============ 长期留样（独立 SQLite）+ 粒度聚合 ============ */

// 长期留样数据库：独立文件，绝不与 Hermes 的 state.db 混用（ADMIN_METRICS_DB 可覆盖，便于测试隔离）
const METRICS_DB_FILE =
  process.env.ADMIN_METRICS_DB || path.join(__dirname, '..', 'data', 'metrics.db');
const METRICS_RETENTION_SECONDS = 30 * 24 * 3600; // raw 5s 点保留 30 天（用户规则：30 天前数据不保留）
const METRICS_1M_RETENTION_SECONDS = 90 * 24 * 3600; // 分钟桶保留 90 天
// 小时桶 / 天桶长期保留：不随 raw 过期而删除（超 30 天、raw 已删的桶直接用物化值）

// 留样点与旧 history 点同构（键名沿用采样器现有键名，保证前端图表无需改结构）
const METRIC_KEYS = [
  'cpu',
  'mem_percent',
  'mem_used',
  'mem_total',
  'swap_percent',
  'psi_mem_avg10',
  'psi_cpu_avg10',
  'psi_io_avg10',
  'net_rx_rate',
  'net_tx_rate',
  'disk_io_read',
  'disk_io_write'
];

// 物化聚合表：每行 = 该桶内 raw 5s 样本按档位口径（分钟 Max / 小时 P90 / 天 P99）计算的值，
// 绝不是对下层聚合结果再聚合。
// - metrics_1m 分钟桶（保留 90 天）；metrics_1h 小时桶 / metrics_1d 天桶（长期保留）
// - 三者都直接从 raw `metrics` 计算：1h / 1d 严禁由 1m 递归聚合
// 分档口径（用户 2026-09-18 定稿）：分钟 = Max（峰值）、小时 = P90、天 = P99。
// 三者一律从 raw 5s 样本直接计算，严禁由细粒度桶递归聚合；调整口径只改这里的 pct。
// pct = 100 时取桶内最大值（等价 Max）；其余为最近秩分位 ceil(pct/100 * N)。
const AGG_TABLES = {
  '1m': { table: 'metrics_1m', stepSec: 60, retentionSec: METRICS_1M_RETENTION_SECONDS, pct: 100, label: 'max' },
  '1h': { table: 'metrics_1h', stepSec: 3600, retentionSec: null, pct: 90, label: 'p90' },
  '1d': { table: 'metrics_1d', stepSec: 86400, retentionSec: null, pct: 99, label: 'p99' }
};
const AGG_TABLE_LIST = Object.values(AGG_TABLES);

// 物化值的小数位：与旧 AVG 查询保持一致，前端展示不变
const METRIC_ROUND = {
  cpu: 1,
  mem_percent: 1,
  mem_used: 0,
  mem_total: 0,
  swap_percent: 1,
  psi_mem_avg10: 2,
  psi_cpu_avg10: 2,
  psi_io_avg10: 2,
  net_rx_rate: 0,
  net_tx_rate: 0,
  disk_io_read: 0,
  disk_io_write: 0
};
const AGG_COLUMNS = METRIC_KEYS.join(', ');
const AGG_COLUMNS_CREATE = METRIC_KEYS.map((k) => `${k} REAL`).join(', ');

// 可写打开 node:sqlite（懒加载 + 单例）。打开/建表失败只降级为「无长期留样」，
// 绝不抛出到调用方，避免影响内存采样与 SSE。
let metricsDb = null;
function openMetricsDb() {
  if (metricsDb) return metricsDb;
  try {
    fs.mkdirSync(path.dirname(METRICS_DB_FILE), { recursive: true });
    const db = new DatabaseSync(METRICS_DB_FILE);
    // 并发保护：采样每 5s 写一次，聚合补算会连续写大量分片。
    // 不开 WAL / busy_timeout 时两者相撞会直接 SQLITE_BUSY（"database is locked"）导致整批聚合放弃。
    try {
      db.exec('PRAGMA journal_mode=WAL');
      db.exec('PRAGMA busy_timeout=8000');
      db.exec('PRAGMA synchronous=NORMAL');
    } catch (e) {
      console.warn('[admin-server] metrics.db PRAGMA 设置失败（继续运行）:', e.message);
    }
    db.exec(
      'CREATE TABLE IF NOT EXISTS metrics (' +
        'ts INTEGER PRIMARY KEY,' +
        'cpu REAL, mem_percent REAL, mem_used REAL, mem_total REAL, swap_percent REAL,' +
        'psi_mem_avg10 REAL, psi_cpu_avg10 REAL, psi_io_avg10 REAL,' +
        'net_rx_rate REAL, net_tx_rate REAL, disk_io_read REAL, disk_io_write REAL' +
        ')'
    );
    // 物化聚合表：字段与 raw 一致 + bucket_start(Unix 秒) / sample_count / updated_at
    for (const t of AGG_TABLE_LIST) {
      db.exec(
        'CREATE TABLE IF NOT EXISTS ' + t.table + ' (' +
          'bucket_start INTEGER PRIMARY KEY,' +
          AGG_COLUMNS_CREATE + ',' +
          'sample_count INTEGER,' +
          'updated_at INTEGER' +
          ')'
      );
    }
    metricsDb = db;
  } catch (e) {
    console.warn('[admin-server] metrics.db 打开失败，长期留样停用:', e.message);
    metricsDb = null;
  }
  return metricsDb;
}

// 写入一个 raw 采样点（ts 用 epoch 秒）。任何异常只 warn，不抛出：
// 写库失败不能拖累现有 SSE 与内存采样。
function persistMetricPoint(point) {
  const db = openMetricsDb();
  if (!db) return;
  try {
    db.prepare(
      'INSERT OR REPLACE INTO metrics (' +
        'ts, cpu, mem_percent, mem_used, mem_total, swap_percent,' +
        'psi_mem_avg10, psi_cpu_avg10, psi_io_avg10,' +
        'net_rx_rate, net_tx_rate, disk_io_read, disk_io_write' +
        ') VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(
      Math.floor(point.ts / 1000),
      point.cpu,
      point.mem_percent,
      point.mem_used,
      point.mem_total,
      point.swap_percent,
      point.psi_mem_avg10,
      point.psi_cpu_avg10,
      point.psi_io_avg10,
      point.net_rx_rate,
      point.net_tx_rate,
      point.disk_io_read,
      point.disk_io_write
    );
    // 保留策略：每次写入顺手清理超过 3 天的 raw 点（ts 是主键，走 rowid 顺序，代价极低）
    db.prepare('DELETE FROM metrics WHERE ts < ?').run(
      Math.floor(Date.now() / 1000) - METRICS_RETENTION_SECONDS
    );
  } catch (e) {
    console.warn('[admin-server] metrics.db 写入失败:', e.message);
  }
}

// 粒度/区间白名单：未知参数回退默认（range=1d & step=1m），并正常返回 200
const METRICS_STEP_SECONDS = { '1m': 60, '5m': 300, '1h': 3600, '1d': 86400 };
const METRICS_RANGE_SECONDS = {
  '1h': 3600,
  '6h': 6 * 3600,
  '1d': 86400,
  '7d': 7 * 86400,
  '30d': 30 * 86400
};

// 分档分位分桶（窗口函数，绝不把 raw 全量拉进 Node）：桶内 12 个指标各自独立排序，
// 取「最近秩」第 ceil(pct/100 * N) 个样本（整数除法实现）；pct=100 即桶内最大值（Max）。
// 分钟桶 pct=100、小时桶 pct=90、天桶 pct=99 —— 三者全部直接来自 raw，绝不递归。
// 返回 [{bucket, sample_count, <metrics>}]。
function computeAggRows(stepSec, pct, sinceSec, untilSec) {
  const db = openMetricsDb();
  if (!db) return [];
  const rank = `(${pct} * cnt + 99) / 100`;
  const rowNums = METRIC_KEYS.map(
    (k) => `ROW_NUMBER() OVER (PARTITION BY bucket ORDER BY ${k}) AS r_${k}`
  ).join(', ');
  const p99 = METRIC_KEYS.map(
    (k) => `ROUND(MAX(CASE WHEN r_${k} = ${rank} THEN ${k} END), ${METRIC_ROUND[k]}) AS ${k}`
  ).join(', ');
  const sql =
    'WITH base AS (' +
      'SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, ' + AGG_COLUMNS + ' ' +
      'FROM metrics WHERE ts >= ? AND ts < ?' +
    '), ranked AS (' +
      'SELECT bucket, COUNT(*) OVER (PARTITION BY bucket) AS cnt, ' + rowNums + ', ' + AGG_COLUMNS + ' ' +
      'FROM base' +
    ') SELECT bucket, MAX(cnt) AS sample_count, ' + p99 + ' FROM ranked GROUP BY bucket ORDER BY bucket';
  return db.prepare(sql).all(stepSec, stepSec, sinceSec, untilSec);
}

// 物化表 upsert（INSERT OR REPLACE，幂等：已存在的桶覆盖更新）
const aggStmtCache = new Map();
function aggUpsertStmt(db, table) {
  let stmt = aggStmtCache.get(table);
  if (stmt) return stmt;
  const placeholders = ['?', ...METRIC_KEYS.map(() => '?'), '?', '?'].join(', ');
  stmt = db.prepare(
    'INSERT OR REPLACE INTO ' + table +
      ' (bucket_start, ' + AGG_COLUMNS + ', sample_count, updated_at) VALUES (' + placeholders + ')'
  );
  aggStmtCache.set(table, stmt);
  return stmt;
}

// 计算并写入 [sinceSec, untilSec) 内的完整桶（必须与 step 对齐）
function materializeRange(key, sinceSec, untilSec) {
  const def = AGG_TABLES[key];
  if (!def || untilSec <= sinceSec) return 0;
  const rows = computeAggRows(def.stepSec, def.pct, sinceSec, untilSec);
  if (!rows.length) return 0;
  const db = openMetricsDb();
  if (!db) return 0;
  const stmt = aggUpsertStmt(db, def.table);
  const now = Math.floor(Date.now() / 1000);
  for (const r of rows) {
    stmt.run(r.bucket, ...METRIC_KEYS.map((k) => r[k]), r.sample_count, now);
  }
  return rows.length;
}

// 补算「最近 N 个完整桶」（默认 1 个）。周期性任务回看多个桶实现自愈：
// 幂等 upsert，重复计算代价极低；某次失败留下的空洞会在下一次回看时自动补上。
function aggregateLastComplete(key, lookback = 1) {
  const def = AGG_TABLES[key];
  const nowSec = Math.floor(Date.now() / 1000);
  const end = Math.floor(nowSec / def.stepSec) * def.stepSec; // 当前桶起点 = 完整桶上界（不含）
  const start = Math.max(0, end - def.stepSec * Math.max(1, lookback));
  if (end <= 0 || end <= start) return 0;
  return materializeRange(key, start, end);
}

// 分钟桶过期清理（小时/天桶长期保留，不清理）
function cleanupExpiredAggregates() {
  const def = AGG_TABLES['1m'];
  const db = openMetricsDb();
  if (!db) return;
  db.prepare('DELETE FROM ' + def.table + ' WHERE bucket_start < ?').run(
    Math.floor(Date.now() / 1000) - def.retentionSec
  );
}

// 启动补齐规划：只挑「raw 有数据但聚合表缺失」的桶，按连续区间分片；
// 已有的桶一律跳过，绝不在启动时全表重算。
const BACKFILL_CHUNK_BUCKETS = 512;
function planBackfillJobs() {
  const jobs = [];
  const db = openMetricsDb();
  if (!db) return jobs;
  const raw = db.prepare('SELECT MIN(ts) mn FROM metrics').get();
  if (!raw || raw.mn == null) return jobs;
  const nowSec = Math.floor(Date.now() / 1000);
  for (const [key, def] of Object.entries(AGG_TABLES)) {
    try {
      const end = Math.floor(nowSec / def.stepSec) * def.stepSec; // 完整桶上界（不含）
      const floorStart = Math.floor(raw.mn / def.stepSec) * def.stepSec;
      if (floorStart >= end) continue;
      const have = new Set(
        db
          .prepare('SELECT bucket_start FROM ' + def.table + ' WHERE bucket_start >= ? AND bucket_start < ?')
          .all(floorStart, end)
          .map((r) => r.bucket_start)
      );
      const rawBuckets = db
        .prepare(
          'SELECT DISTINCT CAST(ts / ? AS INTEGER) * ? AS b FROM metrics ' +
            'WHERE ts >= ? AND ts < ? ORDER BY b'
        )
        .all(def.stepSec, def.stepSec, floorStart, end);
      const ranges = [];
      let rangeStart = null;
      let prev = null;
      for (const r of rawBuckets) {
        const b = r.b;
        if (have.has(b)) {
          if (rangeStart != null) {
            ranges.push([rangeStart, prev]);
            rangeStart = null;
          }
          continue;
        }
        if (rangeStart == null) rangeStart = b;
        else if (b !== prev + def.stepSec) {
          ranges.push([rangeStart, prev]);
          rangeStart = b;
        }
        prev = b;
      }
      if (rangeStart != null) ranges.push([rangeStart, prev]);
      const chunk = def.stepSec * BACKFILL_CHUNK_BUCKETS;
      for (const [rs, re] of ranges) {
        for (let s = rs; s <= re; s += chunk) {
          jobs.push({ key, start: s, end: Math.min(re + def.stepSec, s + chunk) });
        }
      }
    } catch (e) {
      console.warn('[admin-server] 聚合补算规划失败(' + key + '):', e.message);
    }
  }
  return jobs;
}

// 分片执行补算：每片之间 setImmediate 让出事件循环，避免长时间阻塞采样/SSE
function runBackfill(jobs, idx) {
  if (idx >= jobs.length) {
    if (jobs.length) console.log('[admin-server] 聚合启动补算完成，共 ' + jobs.length + ' 个分片');
    return;
  }
  const job = jobs[idx];
  try {
    materializeRange(job.key, job.start, job.end);
  } catch (e) {
    console.warn('[admin-server] 聚合补算失败(' + job.key + '):', e.message);
  }
  setImmediate(() => runBackfill(jobs, idx + 1));
}

// 聚合调度（仅在持有采样锁的实例上启动）：
// - 启动补齐缺失桶（幂等，只补缺的）
// - 每分钟补上一个完整分钟桶；每小时/每天各补一个完整桶（均直接读 raw 算 P99）
// 每次聚合最外层 try/catch + warn，失败绝不影响采样与 SSE
let aggregationScheduled = false;
function startAggregationScheduler() {
  if (aggregationScheduled) return;
  aggregationScheduled = true;
  setTimeout(() => {
    try {
      runBackfill(planBackfillJobs(), 0);
    } catch (e) {
      console.warn('[admin-server] 聚合启动补算失败，不影响采样/SSE:', e.message);
    }
  }, 1500).unref?.();
  setInterval(() => {
    try {
      aggregateLastComplete('1m', 10); // 回看 10 个分钟桶：单次失败留下的空洞下次自动补上
      cleanupExpiredAggregates();
    } catch (e) {
      console.warn('[admin-server] 分钟桶聚合失败，不影响采样/SSE:', e.message);
    }
  }, 60 * 1000).unref?.();
  setInterval(() => {
    try {
      aggregateLastComplete('1h', 3); // 回看 3 个小时桶
    } catch (e) {
      console.warn('[admin-server] 小时桶聚合失败，不影响采样/SSE:', e.message);
    }
  }, 60 * 60 * 1000).unref?.();
  setInterval(() => {
    try {
      aggregateLastComplete('1d', 2); // 回看 2 个天桶
    } catch (e) {
      console.warn('[admin-server] 天桶聚合失败，不影响采样/SSE:', e.message);
    }
  }, 24 * 60 * 60 * 1000).unref?.();
}

// 粒度查询：1m/1h/1d 读对应物化聚合表；5m 未物化，退回查询时对 raw 现算 P99（兼容旧参数）。
// points 与旧 /history 同构；无数据返回空数组 + 完整 meta，绝不抛 500、绝不返回 null。
function queryMetricPoints(range, step) {
  const stepSec = METRICS_STEP_SECONDS[step];
  const rangeSec = METRICS_RANGE_SECONDS[range];
  const nowSec = Math.floor(Date.now() / 1000);
  const since = nowSec - rangeSec;
  const db = openMetricsDb();
  const meta = { step, range, bucketCount: 0, firstBucket: null, lastBucket: null, recordedSeconds: 0 };
  if (!db) return { points: [], meta };
  const def = AGG_TABLES[step];
  const rows = def
    ? db
        .prepare(
          'SELECT bucket_start AS bucket, ' + AGG_COLUMNS + ' FROM ' + def.table +
            ' WHERE bucket_start >= ? ORDER BY bucket_start'
        )
        .all(since)
    : computeAggRows(stepSec, 95, since, nowSec + 1); // 未物化的档位（如 5m）现算，口径取 P95
  const points = rows.map((r) => {
    const p = { ts: r.bucket * 1000 };
    for (const k of METRIC_KEYS) p[k] = r[k];
    return p;
  });
  const raw = db.prepare('SELECT MIN(ts) mn FROM metrics').get();
  if (raw && raw.mn != null) meta.recordedSeconds = Math.max(0, nowSec - raw.mn);
  meta.bucketCount = points.length;
  meta.firstBucket = points.length ? points[0].ts : null;
  meta.lastBucket = points.length ? points[points.length - 1].ts : null;
  return { points, meta };
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
  const mem = readMeminfo(); // 长期留样额外记录内存绝对量（mem_used / mem_total）

  // 内存 buffer / 旧 history 接口的结构保持不变（不加任何新键）
  const point = {
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
  };

  historyBuffer.push(point);
  if (historyBuffer.length > HISTORY_MAX) historyBuffer.shift();

  persistHistory();
  // 同步长期留样（写库失败只 warn，不影响上面的内存 buffer 与 SSE）
  persistMetricPoint({ ...point, mem_used: mem.used, mem_total: mem.total });
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
  // 聚合调度与采样器同锁：仅主实例补算/物化聚合表，失败只 warn，绝不拖累采样与 SSE
  startAggregationScheduler();
}

/* ============ 通知中心（notifications） ============ */
// 与飞书并存的「归档 + 工作台」：飞书负责叫醒，这里负责能看、能筛、能标已读。
// 独立 SQLite（与 metrics.db 分开，ADMIN_NOTIFICATIONS_DB 可覆盖，便于测试隔离）。
// ts / read_at 均为 epoch 秒（与 metrics 表口径一致；SSE 心跳同样用秒）。

const NOTIFICATIONS_DB_FILE =
  process.env.ADMIN_NOTIFICATIONS_DB || path.join(__dirname, '..', 'data', 'notifications.db');
const NOTIFICATIONS_RETENTION_SECONDS = 30 * 24 * 3600; // 保留 30 天（与日志保留策略一致）
const NOTIFICATIONS_DEDUP_WINDOW_SECONDS = 10 * 60; // 同一 dedupKey 10 分钟内只保留一条
const NOTIFICATIONS_HEARTBEAT_MS = 25000; // SSE 心跳 25s（需求区间 20~30s）
const NOTIFICATION_LEVELS = new Set(['urgent', 'normal', 'digest']);

// 可写打开 node:sqlite（懒加载 + 单例）。打开/建表失败只降级，绝不抛到调用方。
let notificationsDb = null;
function openNotificationsDb() {
  if (notificationsDb) return notificationsDb;
  try {
    fs.mkdirSync(path.dirname(NOTIFICATIONS_DB_FILE), { recursive: true });
    const db = new DatabaseSync(NOTIFICATIONS_DB_FILE);
    // 与 metrics.db 同样的并发保护：写入与清理可能交叉
    try {
      db.exec('PRAGMA journal_mode=WAL');
      db.exec('PRAGMA busy_timeout=8000');
      db.exec('PRAGMA synchronous=NORMAL');
    } catch (e) {
      console.warn('[admin-server] notifications.db PRAGMA 设置失败（继续运行）:', e.message);
    }
    db.exec(
      'CREATE TABLE IF NOT EXISTS notifications (' +
        'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
        'ts INTEGER NOT NULL,' +
        'level TEXT NOT NULL,' +
        'source TEXT NOT NULL,' +
        'title TEXT NOT NULL,' +
        'body TEXT,' +
        'link TEXT,' +
        'dedup_key TEXT,' +
        'read_at INTEGER' +
        ')'
    );
    db.exec('CREATE INDEX IF NOT EXISTS idx_notifications_ts ON notifications(ts DESC)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_notifications_read_at ON notifications(read_at)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_notifications_dedup_key ON notifications(dedup_key)');
    // 统计/按来源筛选用（仅加索引，不改列）
    db.exec('CREATE INDEX IF NOT EXISTS idx_notifications_source ON notifications(source)');
    // 通知类别注册表：类别由服务端定义，客户端只拉取渲染（客户端不得内置任何类别清单）。
    // 软删用 archived_at（不物理删除，避免历史通知失去归属）。
    db.exec(
      'CREATE TABLE IF NOT EXISTS notification_types (' +
        'key TEXT PRIMARY KEY,' +
        'label TEXT NOT NULL,' +
        'description TEXT,' +
        'default_level TEXT,' +
        'sort INTEGER DEFAULT 0,' +
        'enabled INTEGER DEFAULT 1,' +
        'archived_at INTEGER' +
        ')'
    );
    // 通知行增加类别列：历史库没有该列 → 加列；旧行按「type 缺省用 source」回填，
    // 保证旧数据也能按类别查到（不改 source 语义）。
    const notifCols = db.prepare('PRAGMA table_info(notifications)').all();
    if (!notifCols.some((c) => c.name === 'type')) {
      db.exec('ALTER TABLE notifications ADD COLUMN type TEXT');
      db.exec('UPDATE notifications SET type = source WHERE type IS NULL');
    }
    db.exec('CREATE INDEX IF NOT EXISTS idx_notifications_type ON notifications(type)');
    // 预置类别（仅缺省时插入，绝不覆盖后台已改的 label / 排序 / 停用状态）：
    // watchdog=看门狗、monitor=站点监控、cron=定时播报、hermes=Hermes、admin=管理后台。
    const seedType = db.prepare(
      'INSERT OR IGNORE INTO notification_types (key, label, description, default_level, sort, enabled, archived_at) ' +
        'VALUES (?, ?, NULL, ?, ?, 1, NULL)'
    );
    seedType.run('watchdog', '看门狗', 'urgent', 10);
    seedType.run('monitor', '站点监控', 'normal', 20);
    seedType.run('cron', '定时播报', 'normal', 30);
    seedType.run('hermes', 'Hermes', 'normal', 40);
    seedType.run('admin', '管理后台', 'normal', 50);
    notificationsDb = db;
  } catch (e) {
    console.warn('[admin-server] notifications.db 打开失败，通知中心停用:', e.message);
    notificationsDb = null;
  }
  return notificationsDb;
}

// 库内行 → 接口契约 item（字段名严格固定；dedup_key 不外泄）
// type 为类别维度（可历史缺失，回退 source），source 字段保留不变，既有客户端不受影响。
function notificationView(row) {
  return {
    id: Number(row.id),
    ts: Number(row.ts),
    level: row.level,
    source: row.source,
    type: row.type || row.source,
    title: row.title,
    body: row.body,
    link: row.link,
    readAt: row.read_at == null ? null : Number(row.read_at)
  };
}

// 未注册类别自动注册：key 当 label、enabled=1。任何新写入方第一次发通知就自动出现在筛选器里。
// 失败只 warn，绝不阻断写入（注册表出问题也不能丢通知）。
function ensureNotificationType(db, key) {
  if (!key) return;
  try {
    db.prepare(
      'INSERT OR IGNORE INTO notification_types (key, label, description, default_level, sort, enabled, archived_at) ' +
        'VALUES (?, ?, NULL, NULL, 0, 1, NULL)'
    ).run(key, key);
  } catch (e) {
    console.warn('[admin-server] 通知类别自动注册失败（不影响写入）:', e.message);
  }
}

// 取类别默认级别：default_level 合法才用，否则 normal（写入方显式给级别时不走这里）。
function notificationDefaultLevel(db, key) {
  try {
    const row = db.prepare('SELECT default_level FROM notification_types WHERE key = ?').get(key);
    const lvl = row && row.default_level;
    return NOTIFICATION_LEVELS.has(lvl) ? lvl : 'normal';
  } catch (e) {
    return 'normal';
  }
}

// 清理 30 天前的通知。启动时一次 + 每小时一次；失败只 warn，不影响其它接口。
function cleanupNotifications() {
  const db = openNotificationsDb();
  if (!db) return;
  try {
    const cutoff = Math.floor(Date.now() / 1000) - NOTIFICATIONS_RETENTION_SECONDS;
    db.prepare('DELETE FROM notifications WHERE ts < ?').run(cutoff);
  } catch (e) {
    console.warn('[admin-server] 通知清理失败（不影响其它接口）:', e.message);
  }
}

function startNotificationMaintenance() {
  cleanupNotifications();
  const timer = setInterval(cleanupNotifications, 60 * 60 * 1000);
  timer.unref?.();
}

startNotificationMaintenance();

// SSE 订阅者集合：新通知入库后立即广播；连接断开必须移除（不泄漏监听器）
const notificationClients = new Set();

function broadcastNotification(item) {
  const frame = 'event: notification\ndata: ' + JSON.stringify(item) + '\n\n';
  for (const res of notificationClients) {
    try {
      res.write(frame);
    } catch (e) {
      notificationClients.delete(res);
    }
  }
}

// 写入接口鉴权：仅「直连回环地址」的本机脚本免 SSO。
// 注意 admin-server 只监听 127.0.0.1，经 nginx 反代的请求 socket 也是回环，
// 但 nginx 必然注入 X-Real-IP / X-Forwarded-For；据此把它们继续交给 authRequired，
// 避免把写入接口做成事实上的完全公开。
function isDirectLoopback(req) {
  const addr = ((req.socket && req.socket.remoteAddress) || '').replace(/^::ffff:/, '');
  if (addr !== '127.0.0.1' && addr !== '::1') return false;
  if (req.headers['x-real-ip'] || req.headers['x-forwarded-for']) return false;
  return true;
}

// 从请求中提取 API 令牌明文：Authorization: Bearer 优先，兼容 X-Quotahub-Token 与 ?token=
// （仅用于通知写入等独立令牌通道；/api/admin/* 主鉴权只认网关注入的 X-Auth-User）
function requestApiToken(req) {
  const header = req.headers.authorization || '';
  if (header.startsWith('Bearer ')) {
    const t = header.slice(7).trim();
    if (t) return t;
  }
  const alias = req.get('x-quotahub-token');
  if (alias && String(alias).trim()) return String(alias).trim();
  const queryToken = req.query && req.query.token ? String(req.query.token) : null;
  return queryToken && queryToken.trim() ? queryToken.trim() : null;
}

async function notificationsWriteAuth(req, res, next) {
  if (isDirectLoopback(req)) return next();
  // 显式识别「本次请求是否用 API Token」：经网关的请求带 X-Auth-User，authRequired 会走
  // 「信任头部」路径、req.user 无 via/canWrite，只读令牌会绕过闸门，故这里独立查令牌表。
  const token = requestApiToken(req);
  if (token) {
    let meta;
    try {
      meta = await lookupApiTokenMeta(token);
    } catch (e) {
      return res.status(500).json({ error: '会话服务异常' });
    }
    if (meta) {
      // 命中 API 令牌表：只有 canWrite=true 才放行，否则 403（沿用原中文文案）
      if (meta.canWrite === true) return next();
      return res.status(403).json({ error: '该接口令牌为只读，无权写入通知' });
    }
  }
  // 不是 API 令牌（SSO 会话 / 其它）→ 走原有鉴权逻辑，不受影响
  return authRequired(req, res, next);
}

/* ============ 服务状态检测 ============ */

// 待检测服务：端口监听判定 up/down。admin-server 为自身（恒 up，pid 为本进程）
const SERVICE_CHECKS = [
  { name: 'admin-server', port: PORT, self: true },
  { name: 'hermes-gateway', port: null, kind: 'systemd' },
  { name: 'hermes-serve', port: 9119 },
  { name: 'nginx', port: 80 },
  { name: 'redis', port: 6379 },
  { name: 'blog', port: 4000 },
  { name: 'admin-test', port: 3101 },
  { name: 'aionui', port: 3010 }
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

// 认证中心基址：只从环境变量或本地配置（config.json，不入库）读取；
// 源码不硬编码任何私有地址（含回环地址）。未配置时各转发接口返回 502。
function authCenterBaseUrl() {
  const configured =
    process.env.AUTH_CENTER_BASE_URL || (config.get() && config.get().auth_center_base_url);
  return configured ? String(configured).replace(/\/+$/, '') : '';
}

// 认证中心共享内部令牌（0600）：只读，绝不打印、绝不返回给客户端。
const AUTH_CENTER_INTERNAL_TOKEN_FILE =
  process.env.AUTH_CENTER_INTERNAL_TOKEN_FILE ||
  path.join(__dirname, '..', '..', 'auth-server', 'internal-token');

function readInternalToken() {
  return fs.readFileSync(AUTH_CENTER_INTERNAL_TOKEN_FILE, 'utf8').trim();
}

// TOTP 重置 / 确认：身份只取网关注入的 X-Auth-User，带共享内部令牌调用认证中心内部接口
// /api/internal/totp/reset|confirm?sub=<用户名>，**不再转发任何客户端凭证**
// （浏览器通道无 token；App 通道带的是 JWT access_token，认证中心 SSO 会话都认不出，会 401）。
// 两阶段语义（reset 只写 pending → confirm 验证转正）由认证中心内部实现，此处仅透传。
// 认证中心不可达 → 502；内部令牌文件缺失/为空 → 500（日志写明原因），绝不静默成功。
function forwardTotp(action) {
  return async (req, res) => {
    const ip = clientIp(req);
    const sub = String((req.user && req.user.name) || req.get('x-auth-user') || '').trim();
    if (!sub) {
      auditLog('totp_' + action, ip, false, '缺少 X-Auth-User');
      return res.status(401).json({ error: '未登录' });
    }
    const base = authCenterBaseUrl();
    if (!base) {
      auditLog('totp_' + action, ip, false, '认证中心地址未配置');
      console.error('[admin-server] AUTH_CENTER_BASE_URL 未配置，无法转发 TOTP 请求');
      return res.status(502).json({ error: '认证中心不可达' });
    }
    let internalToken;
    try {
      internalToken = readInternalToken();
    } catch (e) {
      auditLog('totp_' + action, ip, false, '内部令牌文件不可读');
      console.error(
        `[admin-server] 读取认证中心内部令牌失败（${AUTH_CENTER_INTERNAL_TOKEN_FILE}）: ${e.message}`
      );
      return res.status(500).json({ error: '服务未正确配置' });
    }
    if (!internalToken) {
      auditLog('totp_' + action, ip, false, '内部令牌文件为空');
      console.error(`[admin-server] 认证中心内部令牌文件为空: ${AUTH_CENTER_INTERNAL_TOKEN_FILE}`);
      return res.status(500).json({ error: '服务未正确配置' });
    }
    const url = new URL(base + '/api/internal/totp/' + action);
    url.searchParams.set('sub', sub);
    const headers = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-Internal-Token': internalToken
    };
    try {
      const upstream = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(req.body || {}),
        signal: AbortSignal.timeout(5000)
      });
      const data = await upstream.json().catch(() => ({}));
      auditLog('totp_' + action, ip, upstream.ok, '内部接口');
      return res.status(upstream.status).json(data);
    } catch (e) {
      auditLog('totp_' + action, ip, false, '认证中心不可达: ' + e.message);
      return res.status(502).json({ error: '认证中心不可达' });
    }
  };
}

app.post('/api/admin/totp/reset', authRequired, forwardTotp('reset'));
app.post('/api/admin/totp/confirm', authRequired, forwardTotp('confirm'));

// 已登录设备管理：用户身份只取网关注入的 X-Auth-User（authRequired 已保证存在），
// 用共享内部令牌（X-Internal-Token）调用认证中心内部接口 /api/internal/sessions*，
// **不再转发任何客户端凭证**（浏览器无 token；App 带的是 JWT access_token，认证中心 SSO 会话认不出）。
// GET 列表 / PUT :id/name 重命名 / DELETE :id 踢下线，路径与语义与旧转发一致。
function forwardSessions(req, res) {
  const ip = clientIp(req);
  const action =
    req.method === 'GET' ? 'list' : req.method === 'PUT' ? 'rename' : req.method === 'DELETE' ? 'delete' : req.method.toLowerCase();
  const sub = (req.user && req.user.name) || req.get('x-auth-user') || '';
  const base = authCenterBaseUrl();
  if (!base) {
    auditLog('sessions_' + action, ip, false, '认证中心地址未配置');
    console.error('[admin-server] AUTH_CENTER_BASE_URL 未配置，无法转发设备会话请求');
    return res.status(502).json({ error: '认证中心不可达' });
  }
  let internalToken;
  try {
    internalToken = readInternalToken();
  } catch (e) {
    auditLog('sessions_' + action, ip, false, '内部令牌文件不可读');
    console.error(
      `[admin-server] 读取认证中心内部令牌失败（${AUTH_CENTER_INTERNAL_TOKEN_FILE}）: ${e.message}`
    );
    return res.status(500).json({ error: '服务未正确配置' });
  }
  if (!internalToken) {
    auditLog('sessions_' + action, ip, false, '内部令牌文件为空');
    console.error(`[admin-server] 认证中心内部令牌文件为空: ${AUTH_CENTER_INTERNAL_TOKEN_FILE}`);
    return res.status(500).json({ error: '服务未正确配置' });
  }
  // req.path 在 app.use 挂载点下已是相对路径：GET → '/'，PUT → '/:id/name'，DELETE → '/:id'
  const relPath = req.path === '/' ? '' : req.path;
  const url = new URL(base + '/api/internal/sessions' + relPath);
  url.searchParams.set('sub', String(sub));
  const headers = { Accept: 'application/json', 'X-Internal-Token': internalToken };
  const opts = { method: req.method, headers, signal: AbortSignal.timeout(5000) };
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(req.body || {});
  }
  fetch(url, opts)
    .then(async (upstream) => {
      const data = await upstream.json().catch(() => ({}));
      auditLog('sessions_' + action, ip, upstream.ok, '内部接口');
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

// 按明文 token 查 API 令牌表：命中返回 meta，未命中/数据异常返回 null。
// authRequired 的降级分支与 notificationsWriteAuth 的 canWrite 闸门共用此函数（唯一比对入口）。
// 注意：不在此吞掉 Redis 异常，交由各自调用方 try/catch 决定 500 还是 401。
async function lookupApiTokenMeta(token) {
  if (!token) return null;
  const raw = await redis.get(API_TOKEN_PREFIX + sha256hex(token));
  const meta = parseApiTokenMeta(raw);
  if (!meta || typeof meta.name !== 'string' || !meta.name) return null;
  return meta;
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
        lastUsedAt: Number(meta.lastUsedAt) || 0,
        // 老令牌无此字段 → 只读（false），行为与新增前一致
        canWrite: meta.canWrite === true
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
    // canWrite：新增的可写标志（只加字段，不改已有字段）；默认 false = 只读
    const canWrite = req.body && req.body.canWrite === true;
    const meta = { id, name, note, createdAt: now, expiresAt, lastUsedAt: 0, canWrite };
    await redis.set(apiTokenKey(id), JSON.stringify(meta), 'EX', days * 86400); // 固定过期，不滑动
    auditLog('api_tokens_create', ip, true, `id=${id} name=${name} days=${days} canWrite=${canWrite}`);
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
    if (body.canWrite != null) meta.canWrite = body.canWrite === true;
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
      lastUsedAt: Number(meta.lastUsedAt),
      canWrite: meta.canWrite === true
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

// 历史采样（需鉴权）。返回环形 buffer 中的采样点（最多 120 点），多实例共享。
// 行为保持不变：只读内存/文件 buffer，不涉及新增的 metrics.db。
app.get('/api/admin/system/history', authRequired, (req, res) => {
  res.json(readHistory());
});

// 粒度聚合（需鉴权）：1m/1h/1d 分别读物化聚合表（桶内 raw 5s 样本 P99），
// points 与旧 /history 同构；额外返回 meta。未知 range/step 回退默认（1d/1m）并返回 200；
// 无数据/单点也返回结构完整的 200（points 可为空、可为单点），绝不 500。
app.get('/api/admin/system/metrics', authRequired, (req, res) => {
  const range = METRICS_RANGE_SECONDS[req.query.range] ? String(req.query.range) : '1d';
  const step = METRICS_STEP_SECONDS[req.query.step] ? String(req.query.step) : '1m';
  let points = [];
  let meta = { step, range, bucketCount: 0, firstBucket: null, lastBucket: null, recordedSeconds: 0 };
  try {
    const r = queryMetricPoints(range, step);
    points = r.points;
    meta = r.meta;
  } catch (e) {
    // 查询失败不 500：降级为空数组 + 完整 meta，前端保持上一帧，不影响页面其余部分
    console.warn('[admin-server] metrics 查询失败:', e.message);
  }
  res.json({ step, range, points, meta });
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

/* ============ 通知中心 · REST / SSE 路由 ============ */

// 写入通知（本机脚本免 SSO；其余来源走 authRequired）。
// body: { level?, type?, source, title, body?, link?, dedupKey? } → 201 { id, ts }
// - type 可选；缺省用 source 当类别键（兼容既有写入方）。
// - type 未注册 → 自动注册（key 当 label、enabled=1）；enabled=0 的类别仍接受写入。
// - level 缺省 → 用该类别的 default_level，再没有则 normal。
app.post('/api/admin/notifications', notificationsWriteAuth, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  const ip = clientIp(req);
  const b = req.body || {};
  const levelInput = typeof b.level === 'string' ? b.level.trim() : '';
  const source = typeof b.source === 'string' ? b.source.trim() : '';
  const typeInput = typeof b.type === 'string' ? b.type.trim() : '';
  const typeKey = typeInput || source; // 缺省用 source 兼容既有写入方
  const title = typeof b.title === 'string' ? b.title.trim() : '';
  const body = typeof b.body === 'string' && b.body !== '' ? b.body : null;
  const link = typeof b.link === 'string' && b.link !== '' ? b.link : null;
  const dedupKey = typeof b.dedupKey === 'string' && b.dedupKey !== '' ? b.dedupKey : null;
  if (levelInput && !NOTIFICATION_LEVELS.has(levelInput)) {
    return res.status(400).json({ error: 'level 必须是 urgent / normal / digest' });
  }
  if (!source || !title) {
    return res.status(400).json({ error: 'source 与 title 不能为空' });
  }
  const now = Math.floor(Date.now() / 1000);
  try {
    // 未注册类别自动注册；已注册（含 enabled=0）不动，照常接受写入
    ensureNotificationType(db, typeKey);
    const level = levelInput || notificationDefaultLevel(db, typeKey);
    if (dedupKey) {
      // 同一 dedupKey 10 分钟内只保留一条：更新 ts 与内容，不新增；重新置为未读
      const existing = db
        .prepare(
          'SELECT id FROM notifications WHERE dedup_key = ? AND ts >= ? ORDER BY id DESC LIMIT 1'
        )
        .get(dedupKey, now - NOTIFICATIONS_DEDUP_WINDOW_SECONDS);
      if (existing) {
        db.prepare(
          'UPDATE notifications SET ts=?, level=?, source=?, type=?, title=?, body=?, link=?, read_at=NULL WHERE id=?'
        ).run(now, level, source, typeKey, title, body, link, existing.id);
        const item = notificationView(
          db.prepare('SELECT * FROM notifications WHERE id = ?').get(existing.id)
        );
        broadcastNotification(item);
        auditLog(
          'notification_write',
          ip,
          true,
          `dedup id=${existing.id} level=${level} source=${source} type=${typeKey}`
        );
        return res.status(201).json({ id: Number(existing.id), ts: now });
      }
    }
    const info = db
      .prepare(
        'INSERT INTO notifications (ts, level, source, type, title, body, link, dedup_key, read_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)'
      )
      .run(now, level, source, typeKey, title, body, link, dedupKey);
    const id = Number(info.lastInsertRowid);
    const item = notificationView(db.prepare('SELECT * FROM notifications WHERE id = ?').get(id));
    broadcastNotification(item);
    auditLog('notification_write', ip, true, `id=${id} level=${level} source=${source} type=${typeKey}`);
    return res.status(201).json({ id, ts: now });
  } catch (e) {
    auditLog('notification_write', ip, false, e.message);
    return res.status(500).json({ error: '写入通知失败' });
  }
});

// 列表（需鉴权）：支持 limit / before / level / source / type / unread；unread 与 total 为全库计数
// type 为类别维度（命中该类别下全部通知），与 source 并存、互不替代。
app.get('/api/admin/notifications', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  try {
    const limitRaw = parseInt(req.query.limit, 10);
    const limit = Number.isFinite(limitRaw) ? Math.min(200, Math.max(1, limitRaw)) : 50;
    const beforeRaw = parseInt(req.query.before, 10);
    const before = Number.isFinite(beforeRaw) ? beforeRaw : null;
    const level = NOTIFICATION_LEVELS.has(String(req.query.level || ''))
      ? String(req.query.level)
      : null;
    const source =
      req.query.source && String(req.query.source).trim() ? String(req.query.source).trim() : null;
    const type = req.query.type && String(req.query.type).trim() ? String(req.query.type).trim() : null;
    const unreadOnly = String(req.query.unread || '') === '1';

    const where = [];
    const args = [];
    if (level) {
      where.push('level = ?');
      args.push(level);
    }
    if (source) {
      where.push('source = ?');
      args.push(source);
    }
    if (type) {
      where.push('type = ?');
      args.push(type);
    }
    if (before != null) {
      where.push('id < ?');
      args.push(before);
    }
    if (unreadOnly) where.push('read_at IS NULL');
    const sql =
      'SELECT * FROM notifications' +
      (where.length ? ' WHERE ' + where.join(' AND ') : '') +
      ' ORDER BY id DESC LIMIT ?';
    args.push(limit);
    const items = db.prepare(sql).all(...args).map(notificationView);
    const unread = Number(
      db.prepare('SELECT COUNT(*) AS n FROM notifications WHERE read_at IS NULL').get().n
    );
    const total = Number(db.prepare('SELECT COUNT(*) AS n FROM notifications').get().n);
    res.json({ items, unread, total });
  } catch (e) {
    res.status(500).json({ error: '获取通知失败' });
  }
});

// 通知类别列表（需鉴权）：类别由服务端定义，客户端据此动态渲染筛选器（不得内置清单）。
// 返回 count/unread 为当前库内统计（仅供参考）；按 sort、label 排序；软删（archived_at）的不返回。
app.get('/api/admin/notifications/types', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  try {
    const rows = db
      .prepare(
        'SELECT t.key, t.label, t.description, t.default_level, t.sort, t.enabled, ' +
          '(SELECT COUNT(*) FROM notifications n WHERE n.type = t.key) AS count, ' +
          '(SELECT COUNT(*) FROM notifications n WHERE n.type = t.key AND n.read_at IS NULL) AS unread ' +
          'FROM notification_types t WHERE t.archived_at IS NULL ' +
          'ORDER BY t.sort ASC, t.label ASC'
      )
      .all();
    const types = rows.map((r) => ({
      key: r.key,
      label: r.label,
      description: r.description,
      defaultLevel: r.default_level,
      sort: Number(r.sort) || 0,
      enabled: Number(r.enabled) === 1 ? 1 : 0,
      count: Number(r.count) || 0,
      unread: Number(r.unread) || 0
    }));
    res.json({ types });
  } catch (e) {
    res.status(500).json({ error: '获取通知类别失败' });
  }
});

// 修改通知类别（需鉴权）：body { label?, description?, defaultLevel?, sort?, enabled? } → { ok: true }
// 表即配置；只有传入的字段被更新，未传字段保持原值。
app.patch('/api/admin/notifications/types/:key', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  const key = String(req.params.key || '').trim();
  if (!key) return res.status(400).json({ error: '无效的类别' });
  const b = req.body || {};
  const sets = [];
  const args = [];
  if (typeof b.label === 'string') {
    const label = b.label.trim();
    if (!label) return res.status(400).json({ error: 'label 不能为空' });
    sets.push('label = ?');
    args.push(label);
  }
  if (typeof b.description === 'string') {
    sets.push('description = ?');
    args.push(b.description);
  }
  if (typeof b.defaultLevel === 'string') {
    const dl = b.defaultLevel.trim();
    if (dl && !NOTIFICATION_LEVELS.has(dl)) {
      return res.status(400).json({ error: 'defaultLevel 必须是 urgent / normal / digest' });
    }
    sets.push('default_level = ?');
    args.push(dl || null);
  }
  if (b.sort !== undefined && b.sort !== null && b.sort !== '') {
    const s = parseInt(b.sort, 10);
    if (!Number.isFinite(s)) return res.status(400).json({ error: 'sort 必须是整数' });
    sets.push('sort = ?');
    args.push(s);
  }
  if (b.enabled !== undefined && b.enabled !== null) {
    const en = b.enabled === true || b.enabled === 1 || b.enabled === '1' ? 1 : 0;
    sets.push('enabled = ?');
    args.push(en);
  }
  if (!sets.length) return res.status(400).json({ error: '没有可修改的字段' });
  try {
    const info = db
      .prepare('UPDATE notification_types SET ' + sets.join(', ') + ' WHERE key = ?')
      .run(...args, key);
    if (Number(info.changes) === 0) return res.status(404).json({ error: '类别不存在' });
    auditLog('notification_type_update', clientIp(req), true, `key=${key} fields=${sets.length}`);
    res.json({ ok: true });
  } catch (e) {
    return res.status(500).json({ error: '修改通知类别失败' });
  }
});

// 单条已读（需鉴权）
app.post('/api/admin/notifications/:id/read', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: '无效的 id' });
  try {
    db.prepare('UPDATE notifications SET read_at = ? WHERE id = ? AND read_at IS NULL').run(
      Math.floor(Date.now() / 1000),
      id
    );
    auditLog('notification_read', clientIp(req), true, `id=${id}`);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: '标记已读失败' });
  }
});

// 全部已读（需鉴权）→ { ok: true, count: N }
app.post('/api/admin/notifications/read-all', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  try {
    const info = db
      .prepare('UPDATE notifications SET read_at = ? WHERE read_at IS NULL')
      .run(Math.floor(Date.now() / 1000));
    const count = Number(info.changes);
    auditLog('notification_read_all', clientIp(req), true, `count=${count}`);
    res.json({ ok: true, count });
  } catch (e) {
    res.status(500).json({ error: '全部已读失败' });
  }
});

// 删除（需鉴权）
app.delete('/api/admin/notifications/:id', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: '无效的 id' });
  try {
    db.prepare('DELETE FROM notifications WHERE id = ?').run(id);
    auditLog('notification_delete', clientIp(req), true, `id=${id}`);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: '删除通知失败' });
  }
});

// 批量删除（需鉴权）：按筛选一次删除多条。
// body: { level?, source?, unreadOnly?, readOnly?, dryRun? } → { ok: true, count: N }
// dryRun=true 只统计、不删除，供前端二次确认时拿到准确条数（新增可选字段）。
// 注意：不带任何条件即「全部删除」；审计只记条数与筛选，绝不记 body。
app.post('/api/admin/notifications/bulk-delete', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  const b = req.body || {};
  const level = NOTIFICATION_LEVELS.has(String(b.level || '')) ? String(b.level) : null;
  const source = typeof b.source === 'string' && b.source.trim() ? b.source.trim() : null;
  const unreadOnly = b.unreadOnly === true;
  const readOnly = b.readOnly === true;
  const dryRun = b.dryRun === true;
  // 未读与已读互斥：同时给出时不匹配任何行，避免误删
  if (unreadOnly && readOnly) return res.json({ ok: true, count: 0 });
  const where = [];
  const args = [];
  if (level) {
    where.push('level = ?');
    args.push(level);
  }
  if (source) {
    where.push('source = ?');
    args.push(source);
  }
  if (unreadOnly) where.push('read_at IS NULL');
  if (readOnly) where.push('read_at IS NOT NULL');
  const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';
  try {
    let count;
    if (dryRun) {
      count = Number(db.prepare('SELECT COUNT(*) AS n FROM notifications' + whereSql).get(...args).n);
    } else {
      const info = db.prepare('DELETE FROM notifications' + whereSql).run(...args);
      count = Number(info.changes);
      auditLog(
        'notification_bulk_delete',
        clientIp(req),
        true,
        `count=${count} level=${level || '-'} source=${source || '-'} unreadOnly=${unreadOnly} readOnly=${readOnly}`
      );
    }
    res.json({ ok: true, count });
  } catch (e) {
    auditLog('notification_bulk_delete', clientIp(req), false, e.message);
    res.status(500).json({ error: '批量删除失败' });
  }
});

// 统计（需鉴权）→ { total, unread, sources: [{ source, count }] }
// sources 按条数降序（来源相同时按字典序），前端只展示 Top 5。
app.get('/api/admin/notifications/stats', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  try {
    const total = Number(db.prepare('SELECT COUNT(*) AS n FROM notifications').get().n);
    const unread = Number(
      db.prepare('SELECT COUNT(*) AS n FROM notifications WHERE read_at IS NULL').get().n
    );
    const sources = db
      .prepare(
        'SELECT source, COUNT(*) AS count FROM notifications GROUP BY source ORDER BY count DESC, source ASC'
      )
      .all()
      .map((r) => ({ source: r.source, count: Number(r.count) }));
    res.json({ total, unread, sources });
  } catch (e) {
    res.status(500).json({ error: '获取通知统计失败' });
  }
});

// SSE 实时流（需鉴权）：另开一条，绝不复用系统指标 /system/stream。
// event: notification（新通知 item） / heartbeat（每 25s）
app.get('/api/admin/notifications/stream', authRequired, (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.flushHeaders();
  res.write('retry: 5000\n\n');

  notificationClients.add(res);
  // 广播时可能遇到已断开的 socket，兜底吞掉 error，避免进程级未捕获异常
  res.on('error', () => notificationClients.delete(res));
  const hb = setInterval(() => {
    try {
      res.write('event: heartbeat\ndata: ' + JSON.stringify({ ts: Math.floor(Date.now() / 1000) }) + '\n\n');
    } catch (e) {
      notificationClients.delete(res);
    }
  }, NOTIFICATIONS_HEARTBEAT_MS);
  hb.unref?.();

  // 客户端断开：停心跳并移除订阅者，不泄漏监听器
  req.on('close', () => {
    clearInterval(hb);
    notificationClients.delete(res);
  });
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
  // pi coding agent 版本（2026-09-12 接替 opencode 成为编码 subagent；opencode 已退役）
  { name: 'pi', category: 'service', cmd: "cat /root/.nvm/versions/node/v24.19.0/lib/node_modules/@earendil-works/pi-coding-agent/package.json | grep -m1 '\"version\"' | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+'" },
  // codex CLI 版本直接读 package.json（codex --version 输出 'codex-cli x.y.z' 格式，cat 更稳）
  { name: 'Codex', category: 'service', cmd: "cat /root/.nvm/versions/node/v24.19.0/lib/node_modules/@openai/codex/package.json | grep -m1 '\"version\"' | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+'" },
  // playwright cli 为 #!/usr/bin/env node，需带 PATH 前缀才能在 systemd 精简环境跑通；
  // --version 输出形如 'Version 1.62.1'，提取裸版本号与其他条目格式一致
  { name: 'Playwright', category: 'service', cmd: "PATH=/root/.nvm/versions/node/v24.19.0/bin:$PATH /root/.nvm/versions/node/v24.19.0/bin/playwright --version | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+' | head -1" },
  { name: 'dida-cli', category: 'service', cmd: "cat /root/.nvm/versions/node/v24.19.0/lib/node_modules/@suibiji/dida-cli/package.json | grep -m1 \"version\" | grep -oE '[0-9]+\\.[0-9]+\\.[0-9]+'" },
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

/* ---------- Web 终端会话（ttyd + tmux） ---------- */
// 会话名白名单：term- 前缀 + 小写字母/数字/短横，长度受限 —— 杜绝 tmux 命令注入
const TERM_SESSION_RE = /^term-[a-z0-9][a-z0-9-]{0,31}$/;

// 列出 ttyd/tmux 的终端会话（只暴露本系统创建的 term-* 会话）
function listTermSessions() {
  const out = execSync(
    "tmux list-sessions -F '#{session_name}|#{session_attached}|#{session_activity}' 2>/dev/null || true",
    { encoding: 'utf-8' }
  );
  return out
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const [name, attached, activity] = line.split('|');
      return { name, attached: attached === '1', activity: Number(activity) || 0 };
    })
    .filter((s) => TERM_SESSION_RE.test(s.name));
}

/* ---------- 终端二次验证（口令 → 短期票） ---------- */
// 口令只存哈希：/root/.hermes/term_password 内容 "sha256$<salt>$<hash>"（600，不入库）
const TERM_PW_FILE = process.env.ADMIN_TERM_PW_FILE || path.join(os.homedir(), '.hermes', 'term_password');
const TERM_TICKET_PREFIX = 'term:ticket:';
const TERM_TICKET_TTL = 12 * 3600; // 12 小时
const TERM_UNLOCK_MAX_FAILS = 5;
const TERM_UNLOCK_LOCKOUT_MS = 10 * 60 * 1000; // 连续失败 5 次锁 10 分钟
const termUnlockState = new Map(); // ip -> { fails, until }

function termPasswordOk(pw) {
  try {
    const raw = fs.readFileSync(TERM_PW_FILE, 'utf-8').trim();
    const [algo, salt, hash] = raw.split('$');
    if (algo !== 'sha256' || !salt || !hash) return false;
    const got = crypto.createHash('sha256').update(salt + ':' + String(pw)).digest('hex');
    const a = Buffer.from(got, 'hex');
    const b = Buffer.from(hash, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch (e) {
    return false; // 文件缺失/损坏一律拒绝
  }
}

// 终端口令校验 → 下发短期票（前端拿票去开终端会话）
app.post('/api/admin/term/unlock', authRequired, async (req, res) => {
  const ip = clientIp(req);
  const st = termUnlockState.get(ip) || { fails: 0, until: 0 };
  const now = Date.now();
  if (st.until > now) {
    return res.status(429).json({ error: '尝试过多，请稍后再试', retryAfter: Math.ceil((st.until - now) / 1000) });
  }
  const pw = String((req.body && req.body.password) || '');
  if (!termPasswordOk(pw)) {
    st.fails += 1;
    if (st.fails >= TERM_UNLOCK_MAX_FAILS) {
      st.until = now + TERM_UNLOCK_LOCKOUT_MS;
      st.fails = 0;
    }
    termUnlockState.set(ip, st);
    auditLog('term_unlock_fail', ip, false, `fails=${st.fails}`);
    return res.status(401).json({ error: '口令不正确' });
  }
  termUnlockState.set(ip, { fails: 0, until: 0 });
  const ticket = crypto.randomBytes(32).toString('hex');
  try {
    await redis.set(TERM_TICKET_PREFIX + sha256hex(ticket), '1', 'EX', TERM_TICKET_TTL);
  } catch (e) {
    return res.status(500).json({ error: '票据存储失败: ' + e.message });
  }
  auditLog('term_unlock_ok', ip, true, '');
  res.json({ ticket, expiresIn: TERM_TICKET_TTL });
});

// 票据校验（供服务端 wrapper 起 shell 前调用；只允许本机）
app.get('/api/admin/term/verify', async (req, res) => {
  const ip = clientIp(req);
  if (!(ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1')) {
    return res.status(403).json({ ok: false });
  }
  const ticket = String((req.query && req.query.ticket) || '');
  if (!ticket) return res.status(400).json({ ok: false });
  try {
    const v = await redis.get(TERM_TICKET_PREFIX + sha256hex(ticket));
    if (!v) return res.status(401).json({ ok: false });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ ok: false });
  }
});

// 终端会话列表（需鉴权）
app.get('/api/admin/term/sessions', authRequired, (req, res) => {
  try {
    res.json({ sessions: listTermSessions() });
  } catch (e) {
    res.status(500).json({ error: '读取终端会话失败: ' + e.message });
  }
});

// 批量关闭终端会话（需鉴权）：浏览器关窗/关标签时前端用 sendBeacon 调用，
// 避免会话与连接残留在服务端。names 不在白名单内的一律忽略（不做注入面）。
app.post('/api/admin/term/sessions/close', authRequired, (req, res) => {
  const body = req.body || {};
  const names = Array.isArray(body.names) ? body.names : [];
  const killed = [];
  for (const raw of names.slice(0, 32)) {
    const name = String(raw || '');
    if (!TERM_SESSION_RE.test(name)) continue;
    try {
      execSync(`tmux kill-session -t '${name}' 2>/dev/null || true`, { encoding: 'utf-8' });
      killed.push(name);
    } catch (e) {
      /* 单个失败不影响整体 */
    }
  }
  if (killed.length) auditLog('term_sessions_close', clientIp(req), true, killed.join(','));
  res.json({ ok: true, killed });
});

// 关闭指定终端会话（需鉴权）：admin 里关掉标签页时调用
app.delete('/api/admin/term/sessions/:name', authRequired, (req, res) => {
  const name = String(req.params.name || '');
  if (!TERM_SESSION_RE.test(name)) return res.status(400).json({ error: '非法会话名' });
  try {
    execSync(`tmux kill-session -t '${name}' 2>/dev/null || true`, { encoding: 'utf-8' });
    auditLog('term_session_kill', clientIp(req), true, name);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: '关闭终端会话失败: ' + e.message });
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
  'nginx',
  'redis-server',
  'hermes-gateway',
  'hermes-serve',
  'aionui-web'
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
        } else if (
          comm === 'pi' ||
          args.includes('pi-coding-agent') ||
          /(^|\/)pi(\.js)?$/.test(args.trim())
        ) {
          // pi coding agent（@earendil-works/pi-coding-agent）：启动后会把进程标题改写成纯 "pi"，
          // 故优先按 comm 判定；另保留包名/裸命令两种兜底形态
          name = 'pi';
        } else if (comm === 'aioncore' || args.includes('aioncore') || args.includes('aionui-src')) {
          // AionUi WebUI：主进程是 bun 包装器 + node(tsx/cross-env) + aioncore 后端 + esbuild 子进程，
          // 不归类的话在榜单里会被拆成一堆无名 node/aioncore，看不出是同一个项目
          name = 'aionui';
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

/* ============ 文件区（admin「文件」Tab：目录浏览 / 上传 / 下载 / 新建 / 重命名 / 删除） ============ */
// 根目录 = FILE_DIR，所有路径严格限制在其内部；跳过符号链接，防逃逸。

// 还原原始文件名：busboy 按 latin1 解码 Content-Disposition，中文名会变乱码；按 latin1→utf8 还原
function decodeOriginalName(raw) {
  const name = String(raw || '');
  try {
    const utf8 = Buffer.from(name, 'latin1').toString('utf8');
    if (!utf8.includes('\uFFFD')) return utf8;
  } catch (e) {
    // 落到下面的原值
  }
  return name;
}

// 单个文件/目录名：去分隔符与控制字符，拒绝 . / .. / 空
function sanitizeSegment(raw) {
  const base = path
    .basename(decodeOriginalName(raw))
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/[\\/]/g, '')
    .trim();
  if (!base || base === '.' || base === '..') return '';
  return base;
}

// 重名不覆盖：notes.7z → notes-2.7z → notes-3.7z
function uniqueFileName(dir, raw) {
  const name = sanitizeSegment(raw) || 'unnamed';
  if (!fs.existsSync(path.join(dir, name))) return name;
  const ext = path.extname(name);
  const stem = name.slice(0, name.length - ext.length) || 'file';
  for (let i = 2; i < 10000; i += 1) {
    const candidate = `${stem}-${i}${ext}`;
    if (!fs.existsSync(path.join(dir, candidate))) return candidate;
  }
  return `${stem}-${Date.now()}${ext}`;
}

// 外部传入的相对路径 → FILE_DIR 内的绝对路径；越界/非法返回 null
function resolveFileRel(rel) {
  let decoded;
  try {
    decoded = decodeURIComponent(String(rel == null ? '' : rel));
  } catch (e) {
    return null;
  }
  const full = path.resolve(FILE_DIR, decoded.replace(/^\/+/, ''));
  if (full !== FILE_DIR && !full.startsWith(FILE_DIR + path.sep)) return null;
  return full;
}

// 判断一个（已经过 resolveFileRel 的）绝对路径是否命中文件区根目录保护名单。
// 规则：取相对 FILE_DIR 的第一段，命中 FILE_ROOT_PROTECTED 才算保护；根目录自身不受保护。
// 只匹配根目录这一层——真实路径比较，不做字符串模糊匹配（my-swapfile.txt 不会被误伤）。
function isProtectedPath(full) {
  if (full === FILE_DIR) return false;
  const rel = path.relative(FILE_DIR, full);
  if (!rel || rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel)) return false;
  const parts = rel.split(path.sep);
  if (FILE_ROOT_PROTECTED.has(parts[0])) return true; // 整棵子树都不可写
  return parts.length === 1 && FILE_ROOT_READONLY.has(parts[0]); // 只挡根这一层那一项
}

// 是否属于「连列表里都不展示」的那一类：只用于列目录过滤，不参与写操作判定
function isHiddenRootPath(full) {
  if (full === FILE_DIR) return false;
  const rel = path.relative(FILE_DIR, full);
  if (!rel || rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel)) return false;
  return FILE_ROOT_PROTECTED.has(rel.split(path.sep)[0]);
}

// 绝对路径 → 相对 FILE_DIR 的路径（用 / 分隔）；根目录为 ''
function relFromFull(full) {
  const rel = path.relative(FILE_DIR, full);
  return rel === '' ? '' : rel.split(path.sep).join('/');
}

const fileStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = resolveFileRel(req.query && req.query.path);
    if (!dir) return cb(new Error('目标路径非法'));
    // 目标目录不存在时按需创建（拖拽文件夹上传时会带上相对路径）
    try {
      fs.mkdirSync(dir, { recursive: true });
    } catch (e) {
      return cb(new Error('创建目标目录失败：' + e.message));
    }
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const dir = resolveFileRel(req.query && req.query.path);
    cb(null, uniqueFileName(dir || FILE_DIR, file.originalname));
  }
});
const fileUpload = multer({ storage: fileStorage, limits: { fileSize: FILE_MAX_BYTES } });

// 上传：错误在本层处理，避免落到底部通用 multer 处理器（那里写死了 100MB 文案）
app.post('/api/admin/files/upload', authRequired, (req, res) => {
  fileUpload.single('file')(req, res, (err) => {
    if (err) {
      const tooLarge = err.code === 'LIMIT_FILE_SIZE';
      const msg = tooLarge
        ? `文件超过 ${Math.round(FILE_MAX_BYTES / 1024 / 1024)}MB 上限`
        : `上传失败：${err.message}`;
      auditLog('upload', clientIp(req), false, msg);
      return res.status(tooLarge ? 413 : 400).json({ error: msg });
    }
    if (!req.file) {
      auditLog('upload', clientIp(req), false, '未收到文件');
      return res.status(400).json({ error: '未收到文件（字段名应为 file）' });
    }
    // 文件区根目录保护名单：multer 已落盘，按最终路径判定；命中则删除已写入文件并拒绝
    if (isProtectedPath(path.resolve(req.file.path))) {
      try {
        fs.rmSync(req.file.path, { force: true });
      } catch (e) {
        // 清理失败不影响返回
      }
      auditLog('upload', clientIp(req), false, `${req.file.filename}: 受保护路径`);
      return res.status(403).json({ error: '该文件受保护，不允许操作' });
    }
    auditLog('upload', clientIp(req), true, `${req.file.filename} (${req.file.size}B)`);
    res.json({ name: req.file.filename, size: req.file.size, path: req.file.path });
  });
});

// 列目录：目录在前，同类按名称排序（中文用拼音序）
app.get('/api/admin/files', authRequired, (req, res) => {
  const dir = resolveFileRel(req.query.path);
  if (!dir) return res.status(400).json({ error: '路径非法' });
  let st;
  try {
    st = fs.lstatSync(dir);
  } catch (e) {
    return res.status(404).json({ error: '目录不存在' });
  }
  if (!st.isDirectory()) return res.status(400).json({ error: '不是目录' });
  try {
    const entries = fs
      .readdirSync(dir, { withFileTypes: true })
      .map((d) => {
        let s;
        try {
          s = fs.lstatSync(path.join(dir, d.name));
        } catch (e) {
          return null;
        }
        const isDir = s.isDirectory();
        // 跳过符号链接与特殊文件（防逃逸）
        if (!isDir && !s.isFile()) return null;
        // 根目录保护名单（swapfile / lost+found / cache）不展示
        if (isHiddenRootPath(path.join(dir, d.name))) return null;
        return {
          name: d.name,
          type: isDir ? 'dir' : 'file',
          size: isDir ? 0 : s.size,
          mtime: s.mtimeMs
        };
      })
      .filter(Boolean)
      .sort((a, b) => {
        if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
        return a.name.localeCompare(b.name, 'zh-Hans-CN');
      });
    const rel = relFromFull(dir);
    const parent = rel === '' ? null : rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '';
    res.json({ path: rel, parent, entries });
  } catch (e) {
    res.status(500).json({ error: '读取目录失败：' + e.message });
  }
});

// 下载单个文件
app.get('/api/admin/files/download', authRequired, (req, res) => {
  const full = resolveFileRel(req.query.path);
  if (!full) return res.status(400).json({ error: '路径非法' });
  if (isProtectedPath(full)) return res.status(403).json({ error: '该文件受保护，不允许操作' });
  let st;
  try {
    st = fs.lstatSync(full);
  } catch (e) {
    return res.status(404).json({ error: '文件不存在' });
  }
  if (!st.isFile()) return res.status(400).json({ error: '不是普通文件' });
  res.download(full, path.basename(full));
});

// 新建文件夹
app.post('/api/admin/files/mkdir', authRequired, (req, res) => {
  const dir = resolveFileRel(req.body && req.body.path);
  if (!dir) return res.status(400).json({ error: '路径非法' });
  const name = sanitizeSegment(req.body && req.body.name);
  if (!name) return res.status(400).json({ error: '名称非法' });
  const target = path.join(dir, name);
  if (!target.startsWith(FILE_DIR + path.sep)) return res.status(400).json({ error: '路径非法' });
  if (isProtectedPath(target)) return res.status(403).json({ error: '该文件受保护，不允许操作' });
  if (fs.existsSync(target)) return res.status(409).json({ error: '同名已存在' });
  try {
    fs.mkdirSync(target);
  } catch (e) {
    auditLog('mkdir', clientIp(req), false, `${name}: ${e.message}`);
    return res.status(500).json({ error: '创建失败：' + e.message });
  }
  auditLog('mkdir', clientIp(req), true, relFromFull(target));
  res.json({ ok: true, path: relFromFull(target) });
});

// 重命名（文件或目录）
app.post('/api/admin/files/rename', authRequired, (req, res) => {
  const full = resolveFileRel(req.body && req.body.path);
  if (!full || full === FILE_DIR) return res.status(400).json({ error: '路径非法' });
  const name = sanitizeSegment(req.body && req.body.name);
  if (!name) return res.status(400).json({ error: '名称非法' });
  const target = path.join(path.dirname(full), name);
  if (!target.startsWith(FILE_DIR + path.sep)) return res.status(400).json({ error: '路径非法' });
  // 源路径或目标路径命中根目录保护名单都拒绝（防止改名躲过保护 / 改名占位）
  if (isProtectedPath(full) || isProtectedPath(target)) {
    return res.status(403).json({ error: '该文件受保护，不允许操作' });
  }
  if (!fs.existsSync(full)) return res.status(404).json({ error: '文件不存在' });
  if (target !== full && fs.existsSync(target)) return res.status(409).json({ error: '同名已存在' });
  try {
    fs.renameSync(full, target);
  } catch (e) {
    auditLog('rename', clientIp(req), false, `${relFromFull(full)}: ${e.message}`);
    return res.status(500).json({ error: '重命名失败：' + e.message });
  }
  auditLog('rename', clientIp(req), true, `${relFromFull(full)} → ${relFromFull(target)}`);
  res.json({ ok: true, path: relFromFull(target) });
});

// 删除（目录递归）
app.delete('/api/admin/files', authRequired, (req, res) => {
  const full = resolveFileRel(req.query.path);
  if (!full || full === FILE_DIR) return res.status(400).json({ error: '路径非法' });
  if (isProtectedPath(full)) return res.status(403).json({ error: '该文件受保护，不允许操作' });
  let st;
  try {
    st = fs.lstatSync(full);
  } catch (e) {
    return res.status(404).json({ error: '文件不存在' });
  }
  const rel = relFromFull(full);
  try {
    fs.rmSync(full, { recursive: st.isDirectory(), force: false });
  } catch (e) {
    auditLog('delete', clientIp(req), false, `${rel}: ${e.message}`);
    return res.status(500).json({ error: '删除失败：' + e.message });
  }
  auditLog('delete', clientIp(req), true, rel);
  res.json({ ok: true });
});

/* ============ 文件区 · 临时链接（限时分享 /s/:token） ============ */
// 语义对齐 v2link（server/src/lib/expiry.ts、services/linkService.ts）：
//   · expiresAt === 0 为「永久有效」哨兵（单字段表达，不引入第二个 permanent 布尔列）；
//   · 状态机 active → expired | revoked；revoked 不可逆，仅 active 可改期；
//   · 改期改的是「过期时刻」本身（不是"延长 N 小时"），过去时刻一律 400，立即失效走 revoked。
// 账本为本地 JSON（data/file-shares.json，可用 ADMIN_SHARE_FILE 覆盖）；status 不落盘，
// 读取时按 revokedAt / expiresAt 推导，避免两份事实。

const SHARE_FILE =
  process.env.ADMIN_SHARE_FILE || path.join(__dirname, '..', 'data', 'file-shares.json');
// 分享链接基址：优先环境变量（去掉末尾斜杠）；未设置时按请求头推导（见 shareBaseUrl）
const SHARE_BASE_URL = String(process.env.ADMIN_SHARE_BASE_URL || '').replace(/\/+$/, '');
const SHARE_PERMANENT = 0; // expiresAt 哨兵：永久有效
const SHARE_DEFAULT_TTL_HOURS = 24;
const SHARE_MIN_TTL_HOURS = 1;
const SHARE_MAX_TTL_HOURS = 8760; // 365 天
const SHARE_REVOKED_KEEP_MS = 30 * 24 * 3600 * 1000; // revoked 记录保留 30 天
const SHARE_EXPIRED_KEEP_MS = 90 * 24 * 3600 * 1000; // expired 记录保留 90 天

// 是否永久有效（expiresAt 为哨兵 0）；所有比较/展示统一走此函数，禁止裸写 === 0
function isPermanentExpiry(expiresAt) {
  return Number(expiresAt) === SHARE_PERMANENT;
}

// 状态推导（不落盘）：revoked 优先，其次永久，其次按到期时刻判定
function shareStatus(rec, now) {
  if (rec && rec.revokedAt) return 'revoked';
  if (isPermanentExpiry(rec && rec.expiresAt)) return 'active';
  return Number(rec && rec.expiresAt) <= now ? 'expired' : 'active';
}

// 读取账本原始数组：文件不存在视为空，损坏则回退空（不阻断服务）
function readSharesRaw() {
  try {
    const raw = fs.readFileSync(SHARE_FILE, 'utf-8');
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch (e) {
    return [];
  }
}

// 原子写账本（临时文件 + rename，避免读端读到半截内容；与 persistHistory 写法一致）
function writeShares(list) {
  try {
    fs.mkdirSync(path.dirname(SHARE_FILE), { recursive: true });
    const tmp = SHARE_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(list, null, 2));
    fs.renameSync(tmp, SHARE_FILE);
  } catch (e) {
    console.error('[admin-server] 分享账本写入失败:', e.message);
  }
}

// 读取账本并惰性清理：revoked 超 30 天 / expired 超 90 天自动删除（有变化才写回）
function readShares() {
  const now = Date.now();
  const list = readSharesRaw();
  const kept = list.filter((rec) => {
    if (!rec || typeof rec !== 'object') return false;
    const st = shareStatus(rec, now);
    if (st === 'revoked') {
      return !(rec.revokedAt && now - rec.revokedAt > SHARE_REVOKED_KEEP_MS);
    }
    if (st === 'expired') {
      const exp = Number(rec.expiresAt);
      return !(exp > 0 && now - exp > SHARE_EXPIRED_KEEP_MS);
    }
    return true;
  });
  if (kept.length !== list.length) writeShares(kept);
  return kept;
}

// 分享基址：环境变量优先；否则 X-Forwarded-Proto + Host 推导（禁止硬编码域名）
function shareBaseUrl(req) {
  if (SHARE_BASE_URL) return SHARE_BASE_URL;
  const proto =
    String((req.headers['x-forwarded-proto'] || '').split(',')[0].trim()) || 'http';
  const host =
    String(req.headers['x-forwarded-host'] || req.headers.host || '')
      .split(',')[0]
      .trim() || `127.0.0.1:${PORT}`;
  return `${proto}://${host}`;
}

// 分享路径规范化：仅接受 FILE_DIR 内的相对路径（绝对路径 / 越界 / 含 .. 一律拒绝）
// 创建入参用此函数（内部复用现有 resolveFileRel），账本已存 relPath 用 shareFullFromRel 还原
function resolveSharePath(raw) {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  let decoded;
  try {
    decoded = decodeURIComponent(trimmed);
  } catch (e) {
    return null;
  }
  // 绝对路径（/etc/passwd、C:\...）一律拒绝：文件区路径只允许相对 FILE_DIR
  if (/^[/\\]/.test(decoded) || /^[a-zA-Z]:[\\/]/.test(decoded)) return null;
  if (decoded.split(/[\\/]/).some((seg) => seg === '..')) return null;
  const full = resolveFileRel(trimmed);
  if (!full || full === FILE_DIR) return null;
  return full;
}

// 账本 relPath（不含 URL 编码）→ 绝对路径；越界返回 null（防账本被篡改）
function shareFullFromRel(rel) {
  if (typeof rel !== 'string' || !rel) return null;
  const full = path.resolve(FILE_DIR, rel);
  if (full !== FILE_DIR && !full.startsWith(FILE_DIR + path.sep)) return null;
  return full;
}

// lstat 判定：file / dir / other（符号链接等特殊文件）/ missing
function shareFileInfo(full) {
  if (!full) return { kind: 'missing', size: 0 };
  try {
    const st = fs.lstatSync(full);
    if (st.isFile()) return { kind: 'file', size: st.size };
    if (st.isDirectory()) return { kind: 'dir', size: 0 };
    return { kind: 'other', size: 0 };
  } catch (e) {
    return { kind: 'missing', size: 0 };
  }
}

// 记录 → 列表视图（存储字段 + 计算字段 url / status / remainingMs / fileExists）
function toShareView(rec, req, now) {
  const status = shareStatus(rec, now);
  const remainingMs =
    status === 'active'
      ? isPermanentExpiry(rec.expiresAt)
        ? null
        : Math.max(0, Number(rec.expiresAt) - now)
      : 0;
  const full = shareFullFromRel(rec.relPath);
  return {
    id: rec.id,
    token: rec.token,
    relPath: rec.relPath,
    size: rec.size,
    note: rec.note || '',
    createdAt: rec.createdAt,
    expiresAt: rec.expiresAt,
    revokedAt: rec.revokedAt || null,
    downloads: rec.downloads || 0,
    lastAccessAt: rec.lastAccessAt || null,
    lastAccessIp: rec.lastAccessIp || null,
    url: `${shareBaseUrl(req)}/s/${rec.token}`,
    status,
    remainingMs,
    fileExists: shareFileInfo(full).kind === 'file'
  };
}

// 创建临时链接：body { path, expiresAt? | ttlHours?, note? }
//   path      —— 文件区相对路径（必须是普通文件、非受保护路径）
//   expiresAt —— 绝对到期 epoch ms；0 = 永久；必须为将来时刻，二选一优先于 ttlHours
//   ttlHours  —— 相对时长（夹紧 1~8760 小时）；都不给默认 24 小时
app.post('/api/admin/files/shares', authRequired, (req, res) => {
  const ip = clientIp(req);
  const body = req.body || {};
  const full = resolveSharePath(body.path);
  if (!full) return res.status(400).json({ error: '路径非法' });
  if (isProtectedPath(full)) {
    return res.status(403).json({ error: '该文件受保护，不允许分享' });
  }
  const info = shareFileInfo(full);
  if (info.kind === 'missing') return res.status(404).json({ error: '文件不存在' });
  if (info.kind === 'dir') return res.status(400).json({ error: '暂不支持分享目录' });
  if (info.kind !== 'file') return res.status(400).json({ error: '不是普通文件' });

  const now = Date.now();
  let expiresAt;
  const hasAbs =
    body.expiresAt !== undefined && body.expiresAt !== null && body.expiresAt !== '';
  if (hasAbs) {
    const at = Number(body.expiresAt);
    if (!Number.isFinite(at) || !Number.isInteger(at) || at < 0) {
      return res.status(400).json({ error: 'expiresAt 须为 epoch 毫秒整数（0 表示永久）' });
    }
    if (at !== SHARE_PERMANENT && at <= now) {
      return res
        .status(400)
        .json({ error: 'expiresAt 须为将来时刻（0 表示永久；立即失效请用撤销）' });
    }
    expiresAt = at;
  } else if (body.ttlHours !== undefined && body.ttlHours !== null && body.ttlHours !== '') {
    const h = Number(body.ttlHours);
    if (!Number.isFinite(h)) return res.status(400).json({ error: 'ttlHours 须为数字' });
    const clamped = Math.min(SHARE_MAX_TTL_HOURS, Math.max(SHARE_MIN_TTL_HOURS, h));
    expiresAt = now + clamped * 3600 * 1000;
  } else {
    expiresAt = now + SHARE_DEFAULT_TTL_HOURS * 3600 * 1000;
  }

  const note = typeof body.note === 'string' ? body.note.trim().slice(0, 500) : '';
  const rec = {
    id: crypto.randomBytes(6).toString('base64url'), // 随机 8 位短 id
    token: crypto.randomBytes(24).toString('base64url'),
    relPath: relFromFull(full), // 相对 FILE_DIR，用 / 分隔
    size: info.size,
    note,
    createdAt: now,
    expiresAt,
    revokedAt: null,
    downloads: 0,
    lastAccessAt: null,
    lastAccessIp: null
  };
  const list = readShares();
  list.push(rec);
  writeShares(list);
  auditLog(
    'share-create',
    ip,
    true,
    `id=${rec.id} path=${rec.relPath} expiresAt=${rec.expiresAt}`
  );
  res.status(201).json(toShareView(rec, req, now));
});

// 临时链接列表：按 createdAt 倒序，含计算字段（url / status / remainingMs / fileExists）
app.get('/api/admin/files/shares', authRequired, (req, res) => {
  const now = Date.now();
  const list = readShares().sort((a, b) => (Number(b.createdAt) || 0) - (Number(a.createdAt) || 0));
  res.json({ shares: list.map((r) => toShareView(r, req, now)) });
});

// 改期 / 转永久 / 改备注 / 撤销：body { expiresAt?, note?, revoked? }
//   expiresAt: 0 → 转永久；>0 → 直接设为该绝对到期时刻（须为将来时刻）
//   revoked: true → 撤销（不可逆）；仅 active 记录可操作
app.patch('/api/admin/files/shares/:id', authRequired, (req, res) => {
  const ip = clientIp(req);
  const id = req.params.id;
  const body = req.body || {};
  const now = Date.now();

  const list = readShares();
  const idx = list.findIndex((r) => r && r.id === id);
  if (idx === -1) return res.status(404).json({ error: '链接不存在' });
  const rec = list[idx];

  if (body.revoked !== undefined && typeof body.revoked !== 'boolean') {
    return res.status(400).json({ error: 'revoked 须为布尔值' });
  }
  if (body.revoked === false) {
    return res.status(400).json({ error: '撤销不可逆，无法恢复' });
  }
  const wantsRevoke = body.revoked === true;
  const hasExpiry =
    body.expiresAt !== undefined && body.expiresAt !== null && body.expiresAt !== '';
  const hasNote = body.note !== undefined;
  if (!wantsRevoke && !hasExpiry && !hasNote) {
    return res.status(400).json({ error: '没有可更新的字段' });
  }

  // 状态机：仅 active 可改期 / 撤销（expired / revoked 不可再操作）
  const status = shareStatus(rec, now);
  if (status !== 'active') {
    return res.status(400).json({ error: `仅有效链接可操作（当前 ${status}）` });
  }

  if (wantsRevoke) rec.revokedAt = now;
  if (hasExpiry) {
    const at = Number(body.expiresAt);
    if (!Number.isFinite(at) || !Number.isInteger(at) || at < 0) {
      return res.status(400).json({ error: 'expiresAt 须为 epoch 毫秒整数（0 表示永久）' });
    }
    if (at !== SHARE_PERMANENT && at <= now) {
      return res
        .status(400)
        .json({ error: 'expiresAt 须为将来时刻（0 表示永久；立即失效请用撤销）' });
    }
    rec.expiresAt = at;
  }
  if (hasNote) {
    rec.note = typeof body.note === 'string' ? body.note.trim().slice(0, 500) : '';
  }

  list[idx] = rec;
  writeShares(list);
  auditLog(
    'share-update',
    ip,
    true,
    `id=${id} revoked=${wantsRevoke ? 1 : 0} expiresAt=${rec.expiresAt}`
  );
  res.json(toShareView(rec, req, now));
});

// 删除记录（不动磁盘文件）
app.delete('/api/admin/files/shares/:id', authRequired, (req, res) => {
  const ip = clientIp(req);
  const id = req.params.id;
  const list = readShares();
  const idx = list.findIndex((r) => r && r.id === id);
  if (idx === -1) return res.status(404).json({ error: '链接不存在' });
  const removed = list.splice(idx, 1)[0];
  writeShares(list);
  auditLog('share-delete', ip, true, `id=${id} path=${removed.relPath}`);
  res.json({ ok: true });
});

// 公开下载（免鉴权）：只认 token，不接受任何路径参数，不做目录列举。
//   命中且 active → 流式返回附件（文件名按 RFC 5987 编码，见 res.download）
//   token 不存在 / 文件已删 → 404；已撤销 / 已过期 → 410 Gone
//   三个失败分支共用同一张极简 HTML 提示页，不回显服务器路径
app.get('/s/:token', (req, res) => {
  const ip = clientIp(req);
  const now = Date.now();
  const fail = (status, text) => {
    res
      .status(status)
      .type('html')
      .send(
        '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">' +
          '<meta name="viewport" content="width=device-width,initial-scale=1">' +
          `<title>${text}</title></head>` +
          '<body style="margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;' +
          'font-family:system-ui,-apple-system,\'Segoe UI\',sans-serif;background:#0f1115;color:#c9d1d9">' +
          `<main style="text-align:center"><p style="font-size:15px;letter-spacing:.05em">${text}</p></main>` +
          '</body></html>'
      );
  };

  const token = String(req.params.token || '');
  if (!token) return fail(404, '链接不存在');

  const list = readShares();
  const rec = list.find((r) => r && r.token === token);
  if (!rec) return fail(404, '链接不存在');

  const status = shareStatus(rec, now);
  if (status === 'revoked' || status === 'expired') return fail(410, '链接已失效');

  const full = shareFullFromRel(rec.relPath);
  const info = shareFileInfo(full);
  if (info.kind !== 'file') return fail(404, '链接不存在');

  // 成功下载：计数 + 记录最后访问（IP 用 clientIp），并写审计
  rec.downloads = (rec.downloads || 0) + 1;
  rec.lastAccessAt = now;
  rec.lastAccessIp = ip;
  writeShares(list);
  auditLog('share-download', ip, true, rec.relPath);
  res.download(full, path.basename(full), (err) => {
    if (err && !res.headersSent) {
      console.error('[admin-server] 分享下载失败:', err.message);
    }
  });
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
