'use strict';

/**
 * 应用面板（Apps Panel）后端 —— 应用登记表读取 + 探活采集
 *
 * 数据源：应用登记表 `data/apps.json`（覆盖：环境变量 ADMIN_APPS_FILE）。
 * 只读消费：文件不存在不自动生成；mtime 变化即重读（改登记表无需重启服务）。
 * 本模块为 CommonJS，由 src/index.js require；不新增任何依赖。
 *
 * 探活优先级：probe > container > unit > port(tcp) > 无（status = unknown）。
 * 状态语义：
 *   up       http 2xx/3xx 或 expect 命中 / systemd active / docker running / tcp 通
 *   auth     http 401 / 403
 *   degraded http 5xx 或超时 / systemd activating|reloading / docker restarting|paused
 *   down     连接被拒 / 解析失败 / systemd 非 active / docker exited|dead
 *   unknown  没有可用的探活方式
 */

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');

const execFileAsync = promisify(execFile);

const TTL_SECONDS = 10;
const TTL_MS = TTL_SECONDS * 1000;
const PROBE_TIMEOUT_MS = 1500; // 单条探活超时
const MAX_DISCOVERED = 30; // 未登记发现上限
const ID_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const OTHER_CATEGORY = { id: 'other', name: '其他' };

// 登记表路径：每次调用读取 env（测试实例可用 ADMIN_APPS_FILE 隔离）
function registryPath() {
  return process.env.ADMIN_APPS_FILE || path.join(__dirname, '..', 'data', 'apps.json');
}

// 登记表 mtime 缓存：命中同 mtime 直接复用解析结果
const registryCache = { path: null, mtimeMs: -1, data: null };

/**
 * 读取登记表。
 * @returns {{ exists:boolean, data:object|null, mtimeMs:number|null }}
 * @throws 解析失败时抛错（message 以「应用登记表解析失败: 」开头）
 */
function readRegistry() {
  const p = registryPath();
  let st;
  try {
    st = fs.statSync(p);
  } catch (e) {
    registryCache.path = p;
    registryCache.mtimeMs = -1;
    registryCache.data = null;
    return { exists: false, data: null, mtimeMs: null };
  }
  if (
    registryCache.path === p &&
    registryCache.data !== null &&
    registryCache.mtimeMs === st.mtimeMs
  ) {
    return { exists: true, data: registryCache.data, mtimeMs: st.mtimeMs };
  }
  const raw = fs.readFileSync(p, 'utf-8');
  let data;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    throw new Error('应用登记表解析失败: ' + e.message);
  }
  registryCache.path = p;
  registryCache.mtimeMs = st.mtimeMs;
  registryCache.data = data;
  return { exists: true, data, mtimeMs: st.mtimeMs };
}

function truncate(s, n) {
  const str = String(s == null ? '' : s);
  return str.length > n ? str.slice(0, n) : str;
}

// 推导/规范化探活方式；返回 null 表示无可用探活（status = unknown）
function normalizeProbe(app) {
  const p = app && app.probe;
  if (p && typeof p === 'object' && p.type) {
    const t = String(p.type).toLowerCase();
    if (t === 'http' && p.target) {
      return {
        type: 'http',
        target: String(p.target),
        expect: Array.isArray(p.expect) ? p.expect.map(Number) : null
      };
    }
    if (t === 'systemd') {
      const unit = p.unit || app.unit;
      if (unit) return { type: 'systemd', unit: String(unit) };
    }
    if (t === 'docker') {
      const container = p.container || app.container;
      if (container) return { type: 'docker', container: String(container) };
    }
    if (t === 'tcp') {
      const port = Number(p.port || app.port);
      if (Number.isFinite(port) && port > 0) return { type: 'tcp', port };
    }
  }
  // probe 缺省时自动推导
  if (app.container) return { type: 'docker', container: String(app.container) };
  if (app.unit) return { type: 'systemd', unit: String(app.unit) };
  const port = Number(app.port);
  if (Number.isFinite(port) && port > 0) return { type: 'tcp', port };
  return null;
}

// HTTP 探活：fetch + AbortController(1500ms)，redirect: 'manual'
async function probeHttp(target, expect) {
  const start = Date.now();
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), PROBE_TIMEOUT_MS);
  try {
    const resp = await fetch(target, {
      method: 'GET',
      redirect: 'manual',
      signal: ctrl.signal
    });
    const latencyMs = Date.now() - start;
    const code = resp.status;
    let status;
    if (Array.isArray(expect) && expect.includes(code)) status = 'up';
    else if (code >= 200 && code < 400) status = 'up';
    else if (code === 401 || code === 403) status = 'auth';
    else if (code >= 500) status = 'degraded';
    else status = 'down';
    return { status, latencyMs, detail: `HTTP ${code}`, error: null };
  } catch (e) {
    const latencyMs = Date.now() - start;
    const timedOut = !!(e && (e.name === 'AbortError' || ctrl.signal.aborted));
    const code = e && e.cause && e.cause.code;
    if (timedOut) {
      return {
        status: 'degraded',
        latencyMs,
        detail: 'HTTP 超时',
        error: `探活超时（>${PROBE_TIMEOUT_MS}ms）`
      };
    }
    return {
      status: 'down',
      latencyMs,
      detail: 'HTTP 不可达',
      error: String((code ? code + ': ' : '') + ((e && e.message) || e))
    };
  } finally {
    clearTimeout(timer);
  }
}

// systemd 探活：execFile systemctl is-active <unit>
async function probeSystemd(unit) {
  const start = Date.now();
  try {
    const { stdout } = await execFileAsync('systemctl', ['is-active', unit], {
      timeout: PROBE_TIMEOUT_MS
    });
    const out = String(stdout).trim();
    let status;
    if (out === 'active') status = 'up';
    else if (out === 'activating' || out === 'reloading') status = 'degraded';
    else status = 'down';
    return { status, latencyMs: Date.now() - start, detail: `systemd ${out}`, error: null };
  } catch (e) {
    // is-active 对非 active 单元退出码非 0，stdout 仍可能是 inactive/failed
    const out = String((e && e.stdout) || '').trim();
    let status;
    if (out === 'activating' || out === 'reloading') status = 'degraded';
    else status = 'down';
    return {
      status,
      latencyMs: Date.now() - start,
      detail: out ? `systemd ${out}` : 'systemd 不可用',
      error: out ? null : '无法执行 systemctl'
    };
  }
}

// docker 探活：execFile docker inspect -f '{{.State.Status}}' <container>
async function probeDocker(container) {
  const start = Date.now();
  try {
    const { stdout } = await execFileAsync(
      'docker',
      ['inspect', '-f', '{{.State.Status}}', container],
      { timeout: PROBE_TIMEOUT_MS }
    );
    const out = String(stdout).trim();
    let status;
    if (out === 'running') status = 'up';
    else if (out === 'restarting' || out === 'paused') status = 'degraded';
    else status = 'down';
    return { status, latencyMs: Date.now() - start, detail: `docker ${out}`, error: null };
  } catch (e) {
    // 容器不存在 / docker 不可用 → down
    return {
      status: 'down',
      latencyMs: Date.now() - start,
      detail: 'docker 不可用',
      error: String((e && e.message) || e)
    };
  }
}

// TCP 探活：复用 index.js 的 checkTcpPort
async function probeTcp(port, checkTcpPort) {
  const start = Date.now();
  const up = await checkTcpPort(port);
  const latencyMs = Date.now() - start;
  return {
    status: up ? 'up' : 'down',
    latencyMs,
    detail: `TCP ${port} ${latencyMs}ms`,
    error: up ? null : '连接被拒绝'
  };
}

async function probeApp(app, checkTcpPort) {
  const probe = normalizeProbe(app);
  if (!probe) {
    return {
      status: 'unknown',
      probeType: null,
      latencyMs: null,
      detail: '无可用探活方式',
      error: null
    };
  }
  let r;
  if (probe.type === 'http') r = await probeHttp(probe.target, probe.expect);
  else if (probe.type === 'systemd') r = await probeSystemd(probe.unit);
  else if (probe.type === 'docker') r = await probeDocker(probe.container);
  else r = await probeTcp(probe.port, checkTcpPort);
  return { ...r, probeType: probe.type };
}

// 未登记发现：ss -ltnp 只取 127.0.0.1 监听行，排除 ignorePorts / ignoreProcesses /
// 已登记端口 / docker-proxy（Docker 端口转发，信息与容器条目重复）。
// ignoreProcesses 是一组对进程名生效的正则（登记表里的可选字段）：用于滤掉常驻工具链
// 的临时监听（chrome / agent-browser 的调试端口等），它们的端口号每次都变，没法用端口清单排除。
async function collectDiscovered(ignorePorts, ignoreProcesses, occupiedPorts) {
  try {
    const { stdout } = await execFileAsync('ss', ['-ltnp'], {
      timeout: 3000,
      maxBuffer: 1024 * 1024
    });
    const ignore = new Set(ignorePorts.map(Number));
    const occupied = new Set(occupiedPorts.map(Number));
    const procSkip = [];
    for (const pattern of ignoreProcesses) {
      try {
        procSkip.push(new RegExp(pattern));
      } catch (e) {
        // 单个正则写错不影响其它规则
      }
    }
    const found = new Map();
    for (const line of String(stdout).split('\n')) {
      if (!line.includes('127.0.0.1:')) continue;
      const pm = line.match(/127\.0\.0\.1:(\d+)/);
      if (!pm) continue;
      const port = Number(pm[1]);
      if (!Number.isFinite(port)) continue;
      if (ignore.has(port) || occupied.has(port)) continue;
      const um = line.match(/users:\(\("([^"]+)",pid=\d+/);
      const process = um ? um[1] : null;
      if (process === 'docker-proxy') continue;
      if (process && procSkip.some((re) => re.test(process))) continue;
      if (!found.has(port)) found.set(port, { port, process, url: null });
    }
    return Array.from(found.values())
      .sort((a, b) => a.port - b.port)
      .slice(0, MAX_DISCOVERED);
  } catch (e) {
    // 解析失败绝不影响 apps
    return [];
  }
}

// 单次完整采集（不含 cached 字段；cached 由调用方按命中情况补）
async function collectOnce(checkTcpPort) {
  const p = registryPath();
  const reg = readRegistry(); // 解析失败会 throw，由路由转 500
  const generatedAt = new Date().toISOString();

  if (!reg.exists) {
    return {
      generatedAt,
      ttlSeconds: TTL_SECONDS,
      registryPath: p,
      registryMtime: null,
      notice: '未找到应用登记表',
      warning: null,
      categories: [],
      apps: [],
      discovered: []
    };
  }

  const data = reg.data && typeof reg.data === 'object' ? reg.data : {};
  const declaredCategories = Array.isArray(data.categories) ? data.categories : [];
  const rawApps = Array.isArray(data.apps) ? data.apps : [];
  const ignorePorts = Array.isArray(data.ignorePorts) ? data.ignorePorts : [];
  const ignoreProcesses = Array.isArray(data.ignoreProcesses) ? data.ignoreProcesses : [];

  // 校验 + 去重（重复 id 保留第一条并记 warning）
  const seen = new Set();
  const warnings = [];
  const valid = [];
  for (const a of rawApps) {
    if (!a || typeof a !== 'object') continue;
    if (a.hidden === true) continue;
    const id = String(a.id || '');
    if (!ID_RE.test(id)) {
      warnings.push(`非法 id: ${id || '(空)'}`);
      continue;
    }
    if (seen.has(id)) {
      warnings.push(`重复 id: ${id}`);
      continue;
    }
    seen.add(id);
    valid.push(a);
  }

  // 并行探活（allSettled；单条异常不影响其它）
  const settled = await Promise.allSettled(valid.map((a) => probeApp(a, checkTcpPort)));

  const apps = [];
  for (let i = 0; i < valid.length; i++) {
    const a = valid[i];
    const r = settled[i];
    let pr;
    if (r.status === 'fulfilled') {
      pr = r.value;
    } else {
      pr = {
        status: 'down',
        probeType: null,
        latencyMs: null,
        detail: null,
        error: String((r.reason && r.reason.message) || r.reason)
      };
    }
    const port = Number(a.port);
    apps.push({
      id: a.id,
      name: truncate(a.name || a.id, 16),
      category: a.category != null ? String(a.category) : '',
      desc: a.desc != null ? truncate(a.desc, 24) : null,
      url: typeof a.url === 'string' && a.url ? a.url : null,
      icon: a.icon ? truncate(a.icon, 1) : truncate(a.name || a.id, 1),
      port: Number.isFinite(port) && port > 0 ? port : null,
      tags: Array.isArray(a.tags) ? a.tags.map(String) : [],
      status: pr.status,
      probeType: pr.probeType,
      latencyMs: pr.latencyMs,
      detail: pr.detail,
      error: pr.error || null
    });
  }

  // 分类聚合：未知分类归入「其他」（动态补一个 other）
  const catMap = new Map();
  for (const c of declaredCategories) {
    if (c && c.id) catMap.set(String(c.id), { id: String(c.id), name: String(c.name || c.id), total: 0, up: 0, down: 0 });
  }
  for (const app of apps) {
    let c = catMap.get(app.category);
    if (!c) {
      if (!catMap.has(OTHER_CATEGORY.id)) {
        catMap.set(OTHER_CATEGORY.id, { id: OTHER_CATEGORY.id, name: OTHER_CATEGORY.name, total: 0, up: 0, down: 0 });
      }
      app.category = OTHER_CATEGORY.id;
      c = catMap.get(OTHER_CATEGORY.id);
    }
    c.total++;
    if (app.status === 'up') c.up++;
    else if (app.status === 'down') c.down++;
  }

  const occupiedPorts = rawApps
    .map((a) => Number(a && a.port))
    .filter((n) => Number.isFinite(n) && n > 0);
  const discovered = await collectDiscovered(ignorePorts, ignoreProcesses, occupiedPorts);

  return {
    generatedAt,
    ttlSeconds: TTL_SECONDS,
    registryPath: p,
    registryMtime: reg.mtimeMs,
    notice: null,
    warning: warnings.length ? warnings.join('；') : null,
    categories: Array.from(catMap.values()),
    apps,
    discovered
  };
}

/**
 * 创建采集器实例（模块级缓存 + 单飞）。
 * @param {{ checkTcpPort: (port:number, host?:string, timeout?:number)=>Promise<boolean> }} deps
 */
function createCollector(deps) {
  const checkTcpPort = deps.checkTcpPort;
  let cache = { at: 0, payload: null };
  let inflight = null;

  async function collect() {
    const payload = await collectOnce(checkTcpPort);
    cache = { at: Date.now(), payload };
    return payload;
  }

  function getPayload(refresh) {
    const fresh = cache.payload && Date.now() - cache.at < TTL_MS;
    if (!refresh && fresh) {
      return Promise.resolve({ ...cache.payload, cached: true });
    }
    if (!inflight) {
      const p = collect();
      inflight = p;
      const clear = () => {
        if (inflight === p) inflight = null;
      };
      p.then(clear, clear);
    }
    // 并发请求（含 refresh=1）复用同一次采集
    return inflight.then((payload) => ({ ...payload, cached: false }));
  }

  return { getPayload };
}

module.exports = { createCollector, readRegistry, registryPath, normalizeProbe };
