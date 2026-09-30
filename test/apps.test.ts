'use strict';

// 模块边界标记：让本文件成为 TS 模块（类型导入会被原样剥离，运行时仍是 CommonJS）
import type {} from 'node:test';

// apps.ts 纯函数单元测试（node:test，零依赖）
// 不触碰真实 data/apps.json；仅用内存构造的输入与临时文件。

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  normalizeProbe,
  registryPath,
  readRegistry,
  scanDiscovered,
  httpStatusFromCode,
  systemdStatusFromOutput,
  dockerStatusFromOutput,
  toAppView
} = require('../src/apps.ts');

// ---------- httpStatusFromCode：状态判定与映射 ----------

test('httpStatusFromCode：2xx/3xx 为 up', () => {
  assert.equal(httpStatusFromCode(200, null), 'up');
  assert.equal(httpStatusFromCode(301, null), 'up');
  assert.equal(httpStatusFromCode(399, null), 'up');
});

test('httpStatusFromCode：expect 白名单命中优先于按区间归类', () => {
  assert.equal(httpStatusFromCode(404, [200, 404]), 'up');
  assert.equal(httpStatusFromCode(500, [500]), 'up'); // 白名单命中即 up，即使 5xx
  assert.equal(httpStatusFromCode(404, [200]), 'down'); // 不在白名单仍是 down
});

test('httpStatusFromCode：401/403 为 auth，5xx 为 degraded，其余为 down', () => {
  assert.equal(httpStatusFromCode(401, null), 'auth');
  assert.equal(httpStatusFromCode(403, null), 'auth');
  assert.equal(httpStatusFromCode(500, null), 'degraded');
  assert.equal(httpStatusFromCode(503, null), 'degraded');
  assert.equal(httpStatusFromCode(400, null), 'down');
  assert.equal(httpStatusFromCode(404, null), 'down');
  assert.equal(httpStatusFromCode(0, null), 'down');
});

// ---------- systemd / docker 输出映射 ----------

test('systemdStatusFromOutput：active→up，过渡态→degraded，其余→down', () => {
  assert.equal(systemdStatusFromOutput('active'), 'up');
  assert.equal(systemdStatusFromOutput('activating'), 'degraded');
  assert.equal(systemdStatusFromOutput('reloading'), 'degraded');
  assert.equal(systemdStatusFromOutput('inactive'), 'down');
  assert.equal(systemdStatusFromOutput('failed'), 'down');
  assert.equal(systemdStatusFromOutput(''), 'down');
});

test('dockerStatusFromOutput：running→up，过渡态→degraded，其余→down', () => {
  assert.equal(dockerStatusFromOutput('running'), 'up');
  assert.equal(dockerStatusFromOutput('restarting'), 'degraded');
  assert.equal(dockerStatusFromOutput('paused'), 'degraded');
  assert.equal(dockerStatusFromOutput('exited'), 'down');
  assert.equal(dockerStatusFromOutput('dead'), 'down');
  assert.equal(dockerStatusFromOutput(''), 'down');
});

// ---------- normalizeProbe：探活方式推导与归一化 ----------

test('normalizeProbe：显式 http probe（含 expect 数字归一化）', () => {
  assert.deepEqual(
    normalizeProbe({ probe: { type: 'http', target: 'http://127.0.0.1:1/x' } }),
    { type: 'http', target: 'http://127.0.0.1:1/x', expect: null }
  );
  assert.deepEqual(
    normalizeProbe({ probe: { type: 'HTTP', target: 't', expect: [200, '404'] } }),
    { type: 'http', target: 't', expect: [200, 404] }
  );
});

test('normalizeProbe：http 缺 target 时回退到自动推导', () => {
  // probe.type=http 但无 target，视为无效 → 落到 app.port 的 tcp
  assert.deepEqual(
    normalizeProbe({ probe: { type: 'http' }, port: 8080 }),
    { type: 'tcp', port: 8080 }
  );
});

test('normalizeProbe：systemd / docker 可用 probe 字段或 app 顶层字段', () => {
  assert.deepEqual(
    normalizeProbe({ probe: { type: 'systemd' }, unit: 'nginx' }),
    { type: 'systemd', unit: 'nginx' }
  );
  assert.deepEqual(
    normalizeProbe({ probe: { type: 'systemd', unit: 'sshd' } }),
    { type: 'systemd', unit: 'sshd' }
  );
  assert.deepEqual(
    normalizeProbe({ probe: { type: 'docker', container: 'memos' } }),
    { type: 'docker', container: 'memos' }
  );
});

test('normalizeProbe：tcp 端口非法视为无效', () => {
  assert.deepEqual(normalizeProbe({ probe: { type: 'tcp', port: 6379 } }), { type: 'tcp', port: 6379 });
  assert.equal(normalizeProbe({ probe: { type: 'tcp', port: 0 } }), null);
  assert.equal(normalizeProbe({ probe: { type: 'tcp', port: -1 } }), null);
  assert.equal(normalizeProbe({ probe: { type: 'tcp', port: 'abc' } }), null);
});

test('normalizeProbe：无 probe 时按 container > unit > port 自动推导', () => {
  assert.deepEqual(
    normalizeProbe({ container: 'c', unit: 'u', port: 1 }),
    { type: 'docker', container: 'c' }
  );
  assert.deepEqual(normalizeProbe({ unit: 'u', port: 1 }), { type: 'systemd', unit: 'u' });
  assert.deepEqual(normalizeProbe({ port: 3000 }), { type: 'tcp', port: 3000 });
});

test('normalizeProbe：无任何可用探活方式时为 null', () => {
  assert.equal(normalizeProbe({}), null);
  assert.equal(normalizeProbe({ port: 0 }), null);
  assert.equal(normalizeProbe({ port: 'x' }), null);
  assert.equal(normalizeProbe({ probe: null }), null);
  assert.equal(normalizeProbe({ probe: { type: 'unknown' } }), null);
});

// ---------- scanDiscovered：ss -ltnp 进程/端口行解析 ----------

const SS_SAMPLE = [
  'State Recv-Q Send-Q Local Address:Port Peer Address:Port Process',
  'LISTEN 0      4096       127.0.0.1:3100       0.0.0.0:*    users:(("node",pid=1234,fd=20))',
  'LISTEN 0      128        127.0.0.1:6379       0.0.0.0:*    users:(("redis-server",pid=999,fd=6))',
  'LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=1,fd=3))',
  'LISTEN 0      128            [::1]:8080         [::]:*    users:(("foo",pid=2,fd=4))'
].join('\n');

test('scanDiscovered：只保留 127.0.0.1 监听行，忽略 0.0.0.0 / ::1', () => {
  const out = scanDiscovered(SS_SAMPLE, [], [], []);
  assert.deepEqual(out, [
    { port: 3100, process: 'node', url: null },
    { port: 6379, process: 'redis-server', url: null }
  ]);
});

test('scanDiscovered：排除 ignorePorts 与 occupiedPorts', () => {
  assert.deepEqual(scanDiscovered(SS_SAMPLE, [3100], [], []), [{ port: 6379, process: 'redis-server', url: null }]);
  assert.deepEqual(scanDiscovered(SS_SAMPLE, [], [], [6379]), [{ port: 3100, process: 'node', url: null }]);
});

test('scanDiscovered：排除 docker-proxy 与 ignoreProcesses 命中的进程', () => {
  const lines = [
    'LISTEN 0 128 127.0.0.1:5000 0.0.0.0:* users:(("docker-proxy",pid=7,fd=1))',
    'LISTEN 0 128 127.0.0.1:6000 0.0.0.0:* users:(("chrome",pid=8,fd=1))',
    'LISTEN 0 128 127.0.0.1:7000 0.0.0.0:* users:(("nginx",pid=9,fd=1))'
  ].join('\n');
  assert.deepEqual(scanDiscovered(lines, [], ['^chrome'], []), [{ port: 7000, process: 'nginx', url: null }]);
});

test('scanDiscovered：非法 ignoreProcesses 正则被忽略且不抛错', () => {
  const lines = 'LISTEN 0 128 127.0.0.1:7000 0.0.0.0:* users:(("nginx",pid=9,fd=1))';
  assert.deepEqual(scanDiscovered(lines, [], ['('], []), [{ port: 7000, process: 'nginx', url: null }]);
});

test('scanDiscovered：无 users 字段时 process 为 null，仍计入', () => {
  const lines = 'LISTEN 0 128 127.0.0.1:9000 0.0.0.0:*';
  assert.deepEqual(scanDiscovered(lines, [], [], []), [{ port: 9000, process: null, url: null }]);
});

test('scanDiscovered：同端口去重、按端口升序、最多 30 条', () => {
  const dup = [
    'LISTEN 0 128 127.0.0.1:2222 0.0.0.0:* users:(("a",pid=1,fd=1))',
    'LISTEN 0 128 127.0.0.1:2222 0.0.0.0:* users:(("b",pid=2,fd=2))'
  ].join('\n');
  assert.deepEqual(scanDiscovered(dup, [], [], []), [{ port: 2222, process: 'a', url: null }]);

  const many = [];
  for (let i = 0; i < 40; i++) {
    many.push(`LISTEN 0 128 127.0.0.1:${1000 + i} 0.0.0.0:* users:(("p${i}",pid=${i},fd=1))`);
  }
  const out = scanDiscovered(many.join('\n'), [], [], []);
  assert.equal(out.length, 30);
  assert.equal(out[0].port, 1000);
  assert.equal(out[29].port, 1029);
});

// ---------- toAppView：登记表字段归一化（缺省 / 异常输入） ----------

const OK_PROBE = { status: 'up', probeType: 'tcp', latencyMs: 3, detail: 'TCP 3100 3ms', error: null };

test('toAppView：name 缺省回退 id，超长截断到 16', () => {
  assert.equal(toAppView({ id: 'abcd' }, OK_PROBE).name, 'abcd');
  assert.equal(toAppView({ id: 'abcd', name: 'x'.repeat(20) }, OK_PROBE).name, 'x'.repeat(16));
  assert.equal(toAppView({ id: undefined, name: undefined }, OK_PROBE).name, '');
});

test('toAppView：desc 缺省为 null，超长截断到 24', () => {
  assert.equal(toAppView({ id: 'a' }, OK_PROBE).desc, null);
  assert.equal(toAppView({ id: 'a', desc: 'y'.repeat(30) }, OK_PROBE).desc, 'y'.repeat(24));
});

test('toAppView：url / icon 非字符串或空串一律 null', () => {
  assert.equal(toAppView({ id: 'a' }, OK_PROBE).url, null);
  assert.equal(toAppView({ id: 'a', url: '' }, OK_PROBE).url, null);
  assert.equal(toAppView({ id: 'a', url: 123 }, OK_PROBE).url, null);
  assert.equal(toAppView({ id: 'a', url: 'https://x' }, OK_PROBE).url, 'https://x');
  assert.equal(toAppView({ id: 'a', icon: '' }, OK_PROBE).icon, null);
  assert.equal(toAppView({ id: 'a', icon: 5 }, OK_PROBE).icon, null);
  assert.equal(toAppView({ id: 'a', icon: '管' }, OK_PROBE).icon, '管');
});

test('toAppView：onDemand 仅严格 true 生效，非法类型按 false', () => {
  assert.equal(toAppView({ id: 'a', onDemand: true }, OK_PROBE).onDemand, true);
  assert.equal(toAppView({ id: 'a', onDemand: 'true' }, OK_PROBE).onDemand, false);
  assert.equal(toAppView({ id: 'a', onDemand: 1 }, OK_PROBE).onDemand, false);
  assert.equal(toAppView({ id: 'a' }, OK_PROBE).onDemand, false);
});

test('toAppView：port 规范化（数字串保号，非法/非正为 null）', () => {
  assert.equal(toAppView({ id: 'a', port: 3100 }, OK_PROBE).port, 3100);
  assert.equal(toAppView({ id: 'a', port: '3100' }, OK_PROBE).port, 3100);
  assert.equal(toAppView({ id: 'a', port: 0 }, OK_PROBE).port, null);
  assert.equal(toAppView({ id: 'a', port: -1 }, OK_PROBE).port, null);
  assert.equal(toAppView({ id: 'a', port: 'x' }, OK_PROBE).port, null);
  assert.equal(toAppView({ id: 'a' }, OK_PROBE).port, null);
});

test('toAppView：tags 数组映射为字符串，非数组为 []', () => {
  assert.deepEqual(toAppView({ id: 'a', tags: ['x', 1, null] }, OK_PROBE).tags, ['x', '1', 'null']);
  assert.deepEqual(toAppView({ id: 'a', tags: 'nope' }, OK_PROBE).tags, []);
  assert.deepEqual(toAppView({ id: 'a' }, OK_PROBE).tags, []);
});

test('toAppView：category 缺省为空串，探活字段透传，空 error 归一为 null', () => {
  const v = toAppView({ id: 'a' }, { status: 'down', probeType: null, latencyMs: null, detail: 'd', error: '' });
  assert.equal(v.category, '');
  assert.equal(v.status, 'down');
  assert.equal(v.probeType, null);
  assert.equal(v.latencyMs, null);
  assert.equal(v.detail, 'd');
  assert.equal(v.error, null);
});

// ---------- registryPath / readRegistry：路径与环境变量解析 ----------

test('registryPath：ADMIN_APPS_FILE 覆盖优先，否则默认 repo/data/apps.json', () => {
  const prev = process.env.ADMIN_APPS_FILE;
  try {
    process.env.ADMIN_APPS_FILE = '/tmp/custom-apps.json';
    assert.equal(registryPath(), '/tmp/custom-apps.json');
    delete process.env.ADMIN_APPS_FILE;
    assert.equal(registryPath(), path.join(__dirname, '..', 'data', 'apps.json'));
  } finally {
    if (prev === undefined) delete process.env.ADMIN_APPS_FILE;
    else process.env.ADMIN_APPS_FILE = prev;
  }
});

test('readRegistry：文件不存在 → exists=false', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'admin-apps-'));
  const prev = process.env.ADMIN_APPS_FILE;
  try {
    process.env.ADMIN_APPS_FILE = path.join(dir, 'missing.json');
    assert.deepEqual(readRegistry(), { exists: false, data: null, mtimeMs: null });
  } finally {
    if (prev === undefined) delete process.env.ADMIN_APPS_FILE;
    else process.env.ADMIN_APPS_FILE = prev;
  }
});

test('readRegistry：合法 JSON 解析出对象与 mtime', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'admin-apps-'));
  const p = path.join(dir, 'apps.json');
  fs.writeFileSync(p, JSON.stringify({ version: 1, apps: [{ id: 'a' }] }));
  const prev = process.env.ADMIN_APPS_FILE;
  try {
    process.env.ADMIN_APPS_FILE = p;
    const r = readRegistry();
    assert.equal(r.exists, true);
    assert.deepEqual(r.data, { version: 1, apps: [{ id: 'a' }] });
    assert.equal(typeof r.mtimeMs, 'number');
  } finally {
    if (prev === undefined) delete process.env.ADMIN_APPS_FILE;
    else process.env.ADMIN_APPS_FILE = prev;
  }
});

test('readRegistry：非法 JSON 抛错且 message 带固定前缀', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'admin-apps-'));
  const p = path.join(dir, 'broken.json');
  fs.writeFileSync(p, '{ not json');
  const prev = process.env.ADMIN_APPS_FILE;
  try {
    process.env.ADMIN_APPS_FILE = p;
    assert.throws(
      () => readRegistry(),
      (e: unknown) => e instanceof Error && /^应用登记表解析失败: /.test(e.message)
    );
  } finally {
    if (prev === undefined) delete process.env.ADMIN_APPS_FILE;
    else process.env.ADMIN_APPS_FILE = prev;
  }
});
