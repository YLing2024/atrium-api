'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type {} from 'node:child_process';

/**
 * 软件版本监控路由：只采集本地当前版本（不查外部 latest），带 60 秒结果缓存。
 */

const express = require('express') as typeof import('express');
const { exec } = require('child_process') as typeof import('child_process');
const { promisify } = require('util') as typeof import('util');

const execAsync = promisify(exec);

const { authRequired } = require('../middleware/auth.ts') as {
  authRequired: import('express').RequestHandler;
};

const router = express.Router();

// 软件版本监控（需鉴权）：只采集本地当前版本，不查外部 latest 接口
const NODE_BIN = '/root/.nvm/versions/node/v24.19.0/bin';

// 版本清洗：去 v/V 前缀、去开头的 epoch（形如 '5:8.0.2-3+deb13u2'，仅当最前为数字+冒号）、
// 取第一个 '-' 前的主版本段。例：'5:8.0.2-3+deb13u2' → '8.0.2'；'v24.19.0' → '24.19.0'
function stripVersion(v: unknown): string {
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
type VersionItem = { name: string; category: string; version: string; ok: boolean };
const VERSION_CACHE_TTL_MS = 60000;
const versionCache: { ts: number; list: VersionItem[] | null } = { ts: 0, list: null };

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
router.get('/api/admin/versions', authRequired, async (req, res) => {
  try {
    const now = Date.now();
    if (!versionCache.list || now - versionCache.ts > VERSION_CACHE_TTL_MS) {
      versionCache.list = await getVersions();
      versionCache.ts = now;
    }
    res.json({ list: versionCache.list });
  } catch (e: any) {
    res.status(500).json({ error: '获取软件版本失败: ' + e.message });
  }
});

module.exports = router;
