'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type {} from 'node:net';

/**
 * 服务探活：TCP 端口连通性与进程 pid 检测。
 * SERVICE_CHECKS 为服务状态卡片的受检清单；SYSTEMD_SERVICES 为进程排行的 systemd 正规化清单。
 */

const net = require('net') as typeof import('net');
const { execSync } = require('child_process') as typeof import('child_process');

const { PORT } = require('../config.ts') as { PORT: number };

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
function checkTcpPort(port: number, host = '127.0.0.1', timeout = 1500): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (ok: boolean) => {
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
function pidByPort(port: number): number | null {
  try {
    const out = execSync(
      `ss -ltnp 2>/dev/null | awk '$4 ~ /:${port}$/ {print $6}' | head -1`,
      { encoding: 'utf-8' }
    );
    const m = out.match(/pid=(\d+)/);
    return m ? Number(m[1]) : null;
  } catch (e: any) {
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
          const out = execSync(`systemctl is-active ${svc.name}.service`, { timeout: 3000 })
            .toString()
            .trim();
          const up = out === 'active';
          return { name: svc.name, status: up ? 'up' : 'down', pid: up ? pidByProcessName(svc.name) : null };
        } catch {
          return { name: svc.name, status: 'down', pid: null };
        }
      }
      const up = await checkTcpPort(svc.port as number);
      return {
        name: svc.name,
        status: up ? 'up' : 'down',
        pid: up ? pidByPort(svc.port as number) : null
      };
    })
  );
  return results;
}

// 按进程名反查 pid（systemd 服务用）
function pidByProcessName(name: string): number | null {
  try {
    const out = execSync(`pgrep -f "${name}" | head -1`, { timeout: 3000 })
      .toString()
      .trim();
    return out ? parseInt(out, 10) : null;
  } catch {
    return null;
  }
}

/* ============ 进程排行用到的 systemd 服务清单 ============ */

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

module.exports = { SERVICE_CHECKS, checkTcpPort, pidByPort, collectServices, pidByProcessName, SYSTEMD_SERVICES };
