'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type {} from 'node:child_process';

/**
 * 进程排行：TOP 内存进程 + 瞬时 CPU（与系统卡片同一套 /proc 差分与 EMA 平滑）。
 */

const { exec, execSync } = require('child_process') as typeof import('child_process');
const { promisify } = require('util') as typeof import('util');

const execAsync = promisify(exec);

const { collectAllProcCpu } = require('../probe/system.ts') as {
  collectAllProcCpu: () => { perPid: Map<number, number>; totalPct: number };
};
const { SYSTEMD_SERVICES } = require('../probe/services.ts') as {
  SYSTEMD_SERVICES: string[];
};

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
      } catch (e: any) {
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

module.exports = { collectProcesses };
