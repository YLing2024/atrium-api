'use strict';

import type { Stats } from 'fs';

/**
 * 应用面板（Apps Panel）后端 —— 应用登记表读取 + 探活采集
 *
 * 数据源：应用登记表 `data/apps.json`（覆盖：环境变量 ADMIN_APPS_FILE）。
 * 只读消费：文件不存在不自动生成；mtime 变化即重读（改登记表无需重启服务）。
 * 本模块为 CommonJS，由 src/index.ts require；不新增任何依赖。
 *
 * 探活优先级：probe > container > unit > port(tcp) > 无（status = unknown）。
 * 状态语义：
 *   up       http 2xx/3xx 或 expect 命中 / systemd active / docker running / tcp 通
 *   auth     http 401 / 403
 *   degraded http 5xx 或超时 / systemd activating|reloading / docker restarting|paused
 *   down     连接被拒 / 解析失败 / systemd 非 active / docker exited|dead
 *   idle     按需唤醒应用（onDemand:true）当前探活失败 —— 属正常休眠，非故障（不计入宕机）
 *   unknown  没有可用的探活方式
 */

const fs = require('fs') as typeof import('fs');
const path = require('path') as typeof import('path');
const { execFile } = require('child_process') as typeof import('child_process');
const { promisify } = require('util') as typeof import('util');

const execFileAsync = promisify(execFile);

const TTL_SECONDS = 10;
const TTL_MS = TTL_SECONDS * 1000;
const PROBE_TIMEOUT_MS = 1500; // 单条探活超时
const MAX_DISCOVERED = 30; // 未登记发现上限
const ID_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const OTHER_CATEGORY = { id: 'other', name: '其他' };

// 探活 TCP 连接函数（由 index.js 注入，复用其 checkTcpPort）
type CheckTcpPort = (port: number, host?: string, timeout?: number) => Promise<boolean>;

// 探活状态（语义见文件头注释）
type ProbeStatus = 'up' | 'auth' | 'degraded' | 'down' | 'idle' | 'unknown';

// 规范化后的探活方式；null 表示无可用探活
type Probe =
  | { type: 'http'; target: string; expect: number[] | null }
  | { type: 'systemd'; unit: string }
  | { type: 'docker'; container: string }
  | { type: 'tcp'; port: number };

// 单条探活原始结果
type ProbeResult = {
  status: ProbeStatus;
  latencyMs: number | null;
  detail: string | null;
  error: string | null;
};

// 探活结果 + 命中的探活方式
type AppProbeResult = ProbeResult & { probeType: string | null };

// 登记表里的应用条目（字段类型宽松：登记表是外部输入，逐字段规范化）
type AppEntry = {
  id?: unknown;
  name?: unknown;
  category?: unknown;
  desc?: unknown;
  url?: unknown;
  icon?: unknown;
  onDemand?: unknown;
  port?: unknown;
  unit?: unknown;
  container?: unknown;
  probe?: unknown;
  tags?: unknown;
  hidden?: unknown;
  [key: string]: unknown;
};

// 登记表原始数据（结构见 apps.example.json）
type RegistryData = {
  categories?: unknown;
  apps?: unknown;
  ignorePorts?: unknown;
  ignoreProcesses?: unknown;
  [key: string]: unknown;
};

// 分类聚合项
type CategoryAgg = { id: string; name: string; total: number; up: number; down: number };

// 接口返回的应用条目（字段名严格固定，见接口契约）
type AppView = {
  id: unknown;
  name: string;
  category: string;
  desc: string | null;
  url: string | null;
  icon: string | null;
  onDemand: boolean;
  port: number | null;
  tags: string[];
  status: ProbeStatus;
  probeType: string | null;
  latencyMs: number | null;
  detail: string | null;
  error: string | null;
};

// 未登记发现条目
type DiscoveredEntry = { port: number; process: string | null; url: null };

// 登记表路径：每次调用读取 env（测试实例可用 ADMIN_APPS_FILE 隔离）
function registryPath(): string {
  return process.env.ADMIN_APPS_FILE || path.join(__dirname, '..', 'data', 'apps.json');
}

// 登记表 mtime 缓存：命中同 mtime 直接复用解析结果
const registryCache: { path: string | null; mtimeMs: number; data: RegistryData | null } = {
  path: null,
  mtimeMs: -1,
  data: null
};

/**
 * 读取登记表。
 * @returns {{ exists:boolean, data:object|null, mtimeMs:number|null }}
 * @throws 解析失败时抛错（message 以「应用登记表解析失败: 」开头）
 */
function readRegistry(): { exists: boolean; data: RegistryData | null; mtimeMs: number | null } {
  const p = registryPath();
  let st: Stats;
  try {
    st = fs.statSync(p);
  } catch (e: any) {
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
  } catch (e: any) {
    throw new Error('应用登记表解析失败: ' + e.message);
  }
  registryCache.path = p;
  registryCache.mtimeMs = st.mtimeMs;
  registryCache.data = data;
  return { exists: true, data, mtimeMs: st.mtimeMs };
}

function truncate(s: unknown, n: number): string {
  const str = String(s == null ? '' : s);
  return str.length > n ? str.slice(0, n) : str;
}

// 推导/规范化探活方式；返回 null 表示无可用探活（status = unknown）
function normalizeProbe(app: AppEntry): Probe | null {
  const p = (app && app.probe) as {
    type?: unknown; target?: unknown; expect?: unknown;
    unit?: unknown; container?: unknown; port?: unknown;
  } | null;
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

// HTTP 状态码 → 探活状态（纯函数：先看 expect 白名单，再按区间归类）
function httpStatusFromCode(code: number, expect: number[] | null): ProbeStatus {
  if (Array.isArray(expect) && expect.includes(code)) return 'up';
  if (code >= 200 && code < 400) return 'up';
  if (code === 401 || code === 403) return 'auth';
  if (code >= 500) return 'degraded';
  return 'down';
}

// systemd is-active 输出 → 探活状态（纯函数）
function systemdStatusFromOutput(out: string): ProbeStatus {
  if (out === 'active') return 'up';
  if (out === 'activating' || out === 'reloading') return 'degraded';
  return 'down';
}

// docker inspect .State.Status 输出 → 探活状态（纯函数）
function dockerStatusFromOutput(out: string): ProbeStatus {
  if (out === 'running') return 'up';
  if (out === 'restarting' || out === 'paused') return 'degraded';
  return 'down';
}

// HTTP 探活：fetch + AbortController(1500ms)，redirect: 'manual'
async function probeHttp(target: string, expect: number[] | null): Promise<ProbeResult> {
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
    const status = httpStatusFromCode(code, expect);
    return { status, latencyMs, detail: `HTTP ${code}`, error: null };
  } catch (e: any) {
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
async function probeSystemd(unit: string): Promise<ProbeResult> {
  const start = Date.now();
  try {
    const { stdout } = await execFileAsync('systemctl', ['is-active', unit], {
      timeout: PROBE_TIMEOUT_MS
    });
    const out = String(stdout).trim();
    const status = systemdStatusFromOutput(out);
    return { status, latencyMs: Date.now() - start, detail: `systemd ${out}`, error: null };
  } catch (e: any) {
    // is-active 对非 active 单元退出码非 0，stdout 仍可能是 inactive/failed
    const out = String((e && e.stdout) || '').trim();
    let status: ProbeStatus;
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
async function probeDocker(container: string): Promise<ProbeResult> {
  const start = Date.now();
  try {
    const { stdout } = await execFileAsync(
      'docker',
      ['inspect', '-f', '{{.State.Status}}', container],
      { timeout: PROBE_TIMEOUT_MS }
    );
    const out = String(stdout).trim();
    const status = dockerStatusFromOutput(out);
    return { status, latencyMs: Date.now() - start, detail: `docker ${out}`, error: null };
  } catch (e: any) {
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
async function probeTcp(port: number, checkTcpPort: CheckTcpPort): Promise<ProbeResult> {
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

// 登记表条目 + 探活结果 → 接口返回条目（纯函数：字段类型归一化，缺省/异常输入一律兜底）
function toAppView(a: AppEntry, pr: AppProbeResult): AppView {
  const port = Number(a.port);
  return {
    id: a.id,
    name: truncate(a.name || a.id, 16),
    category: a.category != null ? String(a.category) : '',
    desc: a.desc != null ? truncate(a.desc, 24) : null,
    url: typeof a.url === 'string' && a.url ? a.url : null,
    // icon：图标名（字符串），前端按图标表匹配；缺失/非法 → null（前端回退首字）。原样透传，不截断
    icon: typeof a.icon === 'string' && a.icon ? a.icon : null,
    // onDemand：按需唤醒（布尔，缺省 false）。非法类型按 false 处理，不触发 warning
    onDemand: a.onDemand === true,
    port: Number.isFinite(port) && port > 0 ? port : null,
    tags: Array.isArray(a.tags) ? a.tags.map(String) : [],
    status: pr.status,
    probeType: pr.probeType,
    latencyMs: pr.latencyMs,
    detail: pr.detail,
    error: pr.error || null
  };
}

async function probeApp(app: AppEntry, checkTcpPort: CheckTcpPort): Promise<AppProbeResult> {
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
  // 按需唤醒：平时停着、访问时才起，探活不通属正常 → 归为休眠（不影响其它状态判定）
  if (app && app.onDemand === true && r.status === 'down') {
    return {
      status: 'idle',
      probeType: probe.type,
      latencyMs: null,
      detail: '按需唤醒，当前休眠',
      error: null
    };
  }
  return { ...r, probeType: probe.type };
}

// 未登记发现：ss -ltnp 只取 127.0.0.1 监听行，排除 ignorePorts / ignoreProcesses /
// 已登记端口 / docker-proxy（Docker 端口转发，信息与容器条目重复）。
// ignoreProcesses 是一组对进程名生效的正则（登记表里的可选字段）：用于滤掉常驻工具链
// 的临时监听（chrome / agent-browser 的调试端口等），它们的端口号每次都变，没法用端口清单排除。
// ss -ltnp 输出 → 未登记发现（纯函数：解析 + 排除 + 去重 + 排序 + 截断）
function scanDiscovered(
  stdout: unknown,
  ignorePorts: unknown[],
  ignoreProcesses: unknown[],
  occupiedPorts: unknown[]
): DiscoveredEntry[] {
  const ignore = new Set(ignorePorts.map(Number));
  const occupied = new Set(occupiedPorts.map(Number));
  const procSkip: RegExp[] = [];
  for (const pattern of ignoreProcesses) {
    try {
      procSkip.push(new RegExp(pattern as string));
    } catch (e: any) {
      // 单个正则写错不影响其它规则
    }
  }
  const found = new Map<number, DiscoveredEntry>();
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
}

async function collectDiscovered(ignorePorts: unknown[], ignoreProcesses: unknown[], occupiedPorts: unknown[]): Promise<DiscoveredEntry[]> {
  try {
    const { stdout } = await execFileAsync('ss', ['-ltnp'], {
      timeout: 3000,
      maxBuffer: 1024 * 1024
    });
    return scanDiscovered(stdout, ignorePorts, ignoreProcesses, occupiedPorts);
  } catch (e: any) {
    // 解析失败绝不影响 apps
    return [];
  }
}

// 单次完整采集（不含 cached 字段；cached 由调用方按命中情况补）
async function collectOnce(checkTcpPort: CheckTcpPort) {
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

  const data: RegistryData = reg.data && typeof reg.data === 'object' ? reg.data : {};
  const declaredCategories = Array.isArray(data.categories) ? data.categories : [];
  const rawApps = Array.isArray(data.apps) ? data.apps : [];
  const ignorePorts = Array.isArray(data.ignorePorts) ? data.ignorePorts : [];
  const ignoreProcesses = Array.isArray(data.ignoreProcesses) ? data.ignoreProcesses : [];

  // 校验 + 去重（重复 id 保留第一条并记 warning）
  const seen = new Set();
  const warnings: string[] = [];
  const valid: AppEntry[] = [];
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

  const apps: AppView[] = [];
  for (let i = 0; i < valid.length; i++) {
    const a = valid[i];
    const r = settled[i];
    let pr: AppProbeResult;
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
    apps.push(toAppView(a, pr));
  }

  // 分类聚合：未知分类归入「其他」（动态补一个 other）
  const catMap = new Map<string, CategoryAgg>();
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
    c!.total++;
    if (app.status === 'up') c!.up++;
    else if (app.status === 'down') c!.down++;
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

// 一次完整采集的返回载荷（collectOnce 的解析结果）
type CollectPayload = Awaited<ReturnType<typeof collectOnce>>;

/**
 * 创建采集器实例（模块级缓存 + 单飞）。
 * @param {{ checkTcpPort: (port:number, host?:string, timeout?:number)=>Promise<boolean> }} deps
 */
function createCollector(deps: { checkTcpPort: CheckTcpPort }) {
  const checkTcpPort = deps.checkTcpPort;
  let cache: { at: number; payload: CollectPayload | null } = { at: 0, payload: null };
  let inflight: Promise<CollectPayload> | null = null;

  async function collect() {
    const payload = await collectOnce(checkTcpPort);
    cache = { at: Date.now(), payload };
    return payload;
  }

  function getPayload(refresh: boolean) {
    const fresh = cache.payload && Date.now() - cache.at < TTL_MS;
    if (!refresh && fresh) {
      return Promise.resolve({ ...(cache.payload as CollectPayload), cached: true });
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

module.exports = {
  createCollector,
  readRegistry,
  registryPath,
  normalizeProbe,
  // 以下为纯函数，导出供单元测试（行为未变）
  scanDiscovered,
  httpStatusFromCode,
  systemdStatusFromOutput,
  dockerStatusFromOutput,
  toAppView
};
