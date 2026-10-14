'use strict';

// 模块边界标记：让本文件成为 TS 模块（类型导入会被原样剥离，运行时仍是 CommonJS）
import type {} from 'node:test';

// proctop.ts 纯函数单元测试（node:test，零依赖）
// 只调用导出的纯函数；不真调 ps / docker，不触碰 Redis —— proctop.ts 已把重依赖延迟到
// collectProcesses 内部，import 本模块无副作用。

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  parsePsOutput,
  parsePsOutputWithStats,
  resolveProcessName,
  extractShimContainerId,
  parseDockerPs,
  matchContainerName,
  summarizeProcesses,
  buildProcessTree,
  parseCgroupBytesToMb,
  serviceUnitName,
  cgroupMemoryPath,
  resolveMaxProcessRows,
  parseThreadCount,
  sumThreads,
  DEFAULT_MAX_PROCESS_ROWS,
  MAX_PROCESS_ROWS
} = require('../src/metrics/proctop.ts');

// ---------- parsePsOutput：ps 文本 → 行数组 ----------

// 构造一行固定列宽的 ps 输出（与 collectProcesses 的 ps 参数一致：comm 定宽 16 列）
const psLine = (
  pid: number,
  ppid: number,
  comm: string,
  rssKb: number,
  pcpu: number,
  args = ''
) =>
  `${String(pid).padStart(6)} ${String(ppid).padStart(6)} ${comm.padEnd(16)} ${String(rssKb).padStart(8)} ${String(pcpu).padStart(5)} ${args}`.trimEnd();

test('parsePsOutput：跳过表头，pid/ppid/rss→mem_mb/cpu 兜底解析正确', () => {
  const sample = [
    '  PID   PPID COMMAND             RSS  %CPU COMMAND', // 表头不匹配 → 丢弃
    psLine(1, 0, 'systemd', 1024, 0.1, '/sbin/init splash'),
    psLine(123, 1, 'node', 51200, 3.5, 'node /app/index.js --port 3000'),
    psLine(456, 123, 'kworker/0:0', 0, 0.0)
  ].join('\n');
  const rows = parsePsOutput(sample);
  assert.equal(rows.length, 3);
  assert.deepEqual(rows[0], {
    pid: 1,
    ppid: 0,
    comm: 'systemd',
    rss_kb: 1024,
    mem_mb: 1,
    args: '/sbin/init splash',
    cpu: 0.1
  });
  assert.equal(rows[1].mem_mb, 50); // 51200 kB / 1024
  assert.equal(rows[1].cpu, 3.5);
  assert.equal(rows[1].args, 'node /app/index.js --port 3000');
  assert.equal(rows[2].ppid, 123);
  assert.equal(rows[2].mem_mb, 0);
  assert.equal(rows[2].args, ''); // 无 args 列时为空串
});

test('parsePsOutput：comm 含空格时按定宽列对齐，RSS 不被读成 0', () => {
  // 实测存在把 comm 改成含空格名字的进程（next-server (v1 / node /home/jopl）
  const rows = parsePsOutput(
    psLine(789, 1, 'next-server (v1', 87048, 0.0, 'next-server (v16.2.3)')
  );
  assert.equal(rows.length, 1);
  assert.equal(rows[0].comm, 'next-server (v1');
  assert.equal(rows[0].rss_kb, 87048);
  assert.equal(rows[0].mem_mb, 85);
  assert.equal(rows[0].args, 'next-server (v16.2.3)');
});

test('parsePsOutput：非法/空行与不符合列宽格式的行被忽略', () => {
  assert.deepEqual(parsePsOutput(''), []);
  assert.deepEqual(parsePsOutput('\n\n'), []);
  assert.deepEqual(parsePsOutput('garbage line'), []);
  assert.deepEqual(parsePsOutput('notapid 1 comm 0 0'), []);
});

// ---------- summarizeProcesses：截断与合计（截断前口径） ----------

const mkRow = (pid: number, rssKb: number) => ({
  pid,
  ppid: 0,
  comm: 'x',
  args: '',
  rss_kb: rssKb,
  mem_mb: Math.round(rssKb / 1024),
  cpu: 0
});

test('summarizeProcesses：未超上限时不截断，total_mem_mb 为全部 RSS 之和', () => {
  const r = summarizeProcesses([mkRow(1, 1024), mkRow(2, 2048)], MAX_PROCESS_ROWS);
  assert.equal(r.count, 2);
  assert.equal(r.truncated, false);
  assert.equal(r.processes.length, 2);
  assert.equal(r.total_mem_mb, 3); // (1024+2048)/1024
});

test('summarizeProcesses：超上限按内存降序截断、truncated=true、count 与合计仍为截断前全量', () => {
  const rows = [];
  for (let i = 0; i < 520; i++) rows.push(mkRow(i + 1, (520 - i) * 1024)); // rss 降序
  const r = summarizeProcesses(rows, 500);
  assert.equal(r.count, 520);
  assert.equal(r.truncated, true);
  assert.equal(r.processes.length, 500);
  assert.equal(r.processes[0].pid, 1); // 内存最大者保留
  assert.equal(r.processes[499].pid, 500);
  assert.equal(r.total_mem_mb, Math.round(rows.reduce((s, x) => s + x.rss_kb, 0) / 1024));
});

test('summarizeProcesses：未排序输入也会按内存降序返回', () => {
  const r = summarizeProcesses([mkRow(1, 1024), mkRow(2, 4096), mkRow(3, 2048)]);
  assert.deepEqual(r.processes.map((x: any) => x.pid), [2, 3, 1]);
});

// ---------- buildProcessTree：父子关系 + 子树合计 ----------

test('buildProcessTree：根 = 全部之和，叶子 = 自身，subtree_cpu 同理', () => {
  const tree = buildProcessTree([
    { pid: 1, ppid: 0, mem_mb: 100, cpu: 1 },
    { pid: 2, ppid: 1, mem_mb: 20, cpu: 0.5 },
    { pid: 3, ppid: 1, mem_mb: 30, cpu: 2 },
    { pid: 4, ppid: 2, mem_mb: 5, cpu: 0.1 },
    { pid: 5, ppid: 999, mem_mb: 10, cpu: 0.3 } // 父不在集合内 → 独立根
  ]);
  const by = new Map<number, any>();
  for (const n of tree) by.set(n.pid, n);
  assert.equal(by.get(1).subtree_mem_mb, 155); // 100 + 20 + 5 + 30
  assert.equal(by.get(1).subtree_cpu, 3.6);
  assert.equal(by.get(2).subtree_mem_mb, 25); // 20 + 5
  assert.equal(by.get(2).subtree_cpu, 0.6);
  assert.equal(by.get(3).subtree_mem_mb, 30); // 叶子 = 自身
  assert.equal(by.get(3).subtree_cpu, 2);
  assert.equal(by.get(4).subtree_mem_mb, 5);
  assert.equal(by.get(4).subtree_cpu, 0.1);
  assert.equal(by.get(5).subtree_mem_mb, 10);
  assert.equal(by.get(5).subtree_cpu, 0.3);
});

test('buildProcessTree：环路与自环不无限递归，结果有限', () => {
  const tree = buildProcessTree([
    { pid: 7, ppid: 8, mem_mb: 7, cpu: 0.7 },
    { pid: 8, ppid: 7, mem_mb: 8, cpu: 0.8 },
    { pid: 9, ppid: 9, mem_mb: 9, cpu: 0.9 } // 自环 → 根
  ]);
  const by = new Map<number, any>();
  for (const n of tree) by.set(n.pid, n);
  for (const n of tree) {
    assert.equal(Number.isFinite((n as any).subtree_mem_mb), true);
    assert.equal(Number.isFinite((n as any).subtree_cpu), true);
  }
  assert.equal(by.get(9).subtree_mem_mb, 9); // 自环根 = 自身
});

// ---------- containerd shim：容器 ID 提取 + 短 ID 前缀匹配 ----------

test('extractShimContainerId：支持 -id / --id，非法输入返回 null', () => {
  const id = 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890';
  assert.equal(extractShimContainerId(`-namespace moby -address /run/x -id ${id}`), id);
  assert.equal(extractShimContainerId(`-namespace moby --id ${id}`), id);
  assert.equal(extractShimContainerId('-namespace moby -workdir /x'), null);
  assert.equal(extractShimContainerId(''), null);
});

test('parseDockerPs：解析 12 位短 ID → 容器名映射', () => {
  const map = parseDockerPs(
    ['abcdef123456 vaultwarden', '001122334455 memos', '', 'broken'].join('\n')
  );
  assert.equal(map.size, 2);
  assert.equal(map.get('abcdef123456'), 'vaultwarden');
  assert.equal(map.get('001122334455'), 'memos');
});

test('matchContainerName：按前缀匹配全长 ID，未命中等价于回退', () => {
  const map = parseDockerPs(['abcdef123456 vaultwarden', '001122334455 memos'].join('\n'));
  const full = 'abcdef123456' + '0'.repeat(52);
  assert.equal(matchContainerName(full, map), 'vaultwarden');
  assert.equal(matchContainerName('001122334455' + 'f'.repeat(52), map), 'memos');
  assert.equal(matchContainerName('deadbeef00000000', map), null);
  assert.equal(matchContainerName(null, map), null);
  assert.equal(matchContainerName('abcdef123456', null), null);
});

test('resolveProcessName：shim 命中容器名，查不到/无映射回退 comm', () => {
  const full = 'abcdef123456' + '0'.repeat(52);
  const row = {
    pid: 42,
    ppid: 1,
    comm: 'containerd-shim-runc-v2',
    args: `-namespace moby -id ${full}`,
    rss_kb: 0,
    mem_mb: 0,
    cpu: 0
  };
  const map = parseDockerPs('abcdef123456 vaultwarden');
  assert.equal(resolveProcessName(row, new Map(), map), 'vaultwarden');
  assert.equal(resolveProcessName(row, new Map(), new Map()), 'containerd-shim-runc-v2');
  // systemd MainPID 命中优先于 shim
  assert.equal(resolveProcessName(row, new Map([[42, 'nginx']]), map), 'nginx');
});

test('resolveProcessName：既有命名规则保持不变', () => {
  const mk = (comm: string, args = '') => ({
    pid: 1,
    ppid: 0,
    comm,
    args,
    rss_kb: 0,
    mem_mb: 0,
    cpu: 0
  });
  assert.equal(resolveProcessName(mk('node', 'node x'), new Map(), new Map()), 'node');
  assert.equal(resolveProcessName(mk('python3'), new Map(), new Map()), 'python');
  assert.equal(resolveProcessName(mk('opencode'), new Map(), new Map()), 'opencode');
  assert.equal(resolveProcessName(mk('bash'), new Map(), new Map()), 'bash');
});

// ---------- resolveMaxProcessRows：环境变量覆盖（非法回退默认） ----------

test('resolveMaxProcessRows：合法纯正整数采用，非法/空/超界回退默认', () => {
  assert.equal(DEFAULT_MAX_PROCESS_ROWS, 2000);
  assert.equal(resolveMaxProcessRows('3000'), 3000);
  assert.equal(resolveMaxProcessRows(3000), 3000);
  assert.equal(resolveMaxProcessRows(' 42 '), 42); // 首尾空白容忍
  // 非法一律回退默认（默认由实现给出，此处只断言等于 DEFAULT_MAX_PROCESS_ROWS）
  for (const bad of [undefined, null, '', '  ', 'abc', '0', '-5', '12abc', '3e3', '1.9']) {
    assert.equal(resolveMaxProcessRows(bad), DEFAULT_MAX_PROCESS_ROWS, `bad=${String(bad)}`);
  }
  // 超出安全整数范围的字符串回退默认
  assert.equal(resolveMaxProcessRows('99999999999999999999'), DEFAULT_MAX_PROCESS_ROWS);
  // 自定义 fallback 生效
  assert.equal(resolveMaxProcessRows('abc', 777), 777);
});

// ---------- parsePsOutputWithStats：解析计数（失败不再静默丢弃） ----------

test('parsePsOutputWithStats：空行不计，非空不合格式计入 skipped_count', () => {
  const sample = [
    psLine(1, 0, 'systemd', 1024, 0.1, '/sbin/init'),
    'garbage line',
    '',
    '   ',
    psLine(2, 1, 'node', 2048, 0.2, 'node x')
  ].join('\n');
  const r = parsePsOutputWithStats(sample);
  assert.equal(r.rows.length, 2);
  assert.equal(r.parsed_count, 2);
  assert.equal(r.skipped_count, 1); // 只有 'garbage line' 计失败；空行/纯空白不计
});

test('parsePsOutputWithStats：全空输出计数为 0', () => {
  const r = parsePsOutputWithStats('\n\n');
  assert.deepEqual(r, { rows: [], parsed_count: 0, skipped_count: 0 });
});

// ---------- cgroup 纯函数：数值解析 / 单元名 / 文件路径 ----------

test('parseCgroupBytesToMb：字节→MB 取整，非法/哨兵/负数一律 null', () => {
  assert.equal(parseCgroupBytesToMb('1048576'), 1); // 1 MiB
  assert.equal(parseCgroupBytesToMb('2621440'), 3); // 2.5 MiB → 四舍五入 3
  assert.equal(parseCgroupBytesToMb('0'), 0);
  assert.equal(parseCgroupBytesToMb(''), null);
  assert.equal(parseCgroupBytesToMb('   '), null);
  assert.equal(parseCgroupBytesToMb('[not set]'), null);
  assert.equal(parseCgroupBytesToMb('infinity'), null);
  assert.equal(parseCgroupBytesToMb('-1'), null);
  assert.equal(parseCgroupBytesToMb('18446744073709551615'), null); // UINT64_MAX 哨兵
  assert.equal(parseCgroupBytesToMb(null), null);
});

test('serviceUnitName：裸名补 .service，已带已知后缀的保持', () => {
  assert.equal(serviceUnitName('admin-server'), 'admin-server.service');
  assert.equal(serviceUnitName('redis-server'), 'redis-server.service');
  assert.equal(serviceUnitName('nginx.service'), 'nginx.service');
  assert.equal(serviceUnitName('system.slice'), 'system.slice');
  assert.equal(serviceUnitName(''), '');
});

test('cgroupMemoryPath：服务单元在 system.slice 下，slice 自身直连', () => {
  assert.equal(
    cgroupMemoryPath('admin-server'),
    '/sys/fs/cgroup/system.slice/admin-server.service/memory.current'
  );
  assert.equal(
    cgroupMemoryPath('nginx.service'),
    '/sys/fs/cgroup/system.slice/nginx.service/memory.current'
  );
  assert.equal(
    cgroupMemoryPath('system.slice'),
    '/sys/fs/cgroup/system.slice/memory.current'
  );
});

// ---------- 线程数：/proc/<pid>/task 条目解析 + 顶层求和 ----------

test('parseThreadCount：数组条目按数字 tid 计数，非数组（读不到）一律 null', () => {
  assert.equal(parseThreadCount(['1']), 1);
  assert.equal(parseThreadCount(['1', '2', '3', '4']), 4);
  // 异常/竞态残留项（非数字）不计入
  assert.equal(parseThreadCount(['1', '2', 'not-a-tid', '', '.', '..']), 2);
  // 读到目录但为空：如实为 0（不是读不到）
  assert.equal(parseThreadCount([]), 0);
  // 目录不存在 / 权限不足 / 进程已退出：调用方传 null → null，绝不猜 0
  assert.equal(parseThreadCount(null), null);
  assert.equal(parseThreadCount(undefined), null);
  assert.equal(parseThreadCount('/proc/1/task'), null); // 非数组
});

test('parseThreadCount：数字字符串也接受（readdirSync 返回 string[]，防御非字符串混入）', () => {
  assert.equal(parseThreadCount([12, 34]), 2);
  assert.equal(parseThreadCount(['42']), 1);
});

test('sumThreads：只累加数字 thread_count，null/缺省的行跳过（不按 0 计）', () => {
  assert.equal(sumThreads([{ thread_count: 1 }, { thread_count: 3 }, { thread_count: 10 }]), 14);
  assert.equal(sumThreads([{ thread_count: 5 }, { thread_count: null }, {}]), 5);
  assert.equal(sumThreads([]), 0);
  assert.equal(sumThreads([{ thread_count: null }]), 0);
});

// ---------- buildProcessTree：subtree_count（含自身） ----------

test('buildProcessTree：subtree_count 为含自身的后代数，叶子为 1', () => {
  const tree = buildProcessTree([
    { pid: 1, ppid: 0, mem_mb: 1, cpu: 0 },
    { pid: 2, ppid: 1, mem_mb: 1, cpu: 0 },
    { pid: 3, ppid: 1, mem_mb: 1, cpu: 0 },
    { pid: 4, ppid: 2, mem_mb: 1, cpu: 0 }
  ]);
  const by = new Map<number, any>();
  for (const n of tree) by.set(n.pid, n);
  assert.equal(by.get(1).subtree_count, 4); // 自身 + 2 + 3 + 4
  assert.equal(by.get(2).subtree_count, 2); // 自身 + 4
  assert.equal(by.get(3).subtree_count, 1);
  assert.equal(by.get(4).subtree_count, 1);
});
