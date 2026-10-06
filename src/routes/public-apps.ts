'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type {} from 'express';

/**
 * 公开只读应用中心路由：GET /api/public/apps（免鉴权）。
 *
 * 复用 src/apps.ts 的 createCollector + probe/services.ts 的 checkTcpPort：
 * 沿用模块级 10s 缓存 + 单飞（并发复用同一 Promise）。
 * 与 /api/admin/apps 的差异：
 *   - 不加 authRequired；
 *   - ?refresh=1 需限流：同一来源 IP 10s 内只真正刷新一次，超出按缓存读；
 *   - 只输出公开安全字段（见 apps.ts 的 toPublicPayload），剔除 port / unit / container /
 *     probe / registryPath / registryMtime / notice / warning 与未登记发现 discovered[]；
 *   - 响应头 Cache-Control: no-store；
 *   - 失败一律 503 通用文案，不回栈信息。
 */

const express = require('express') as typeof import('express');

const appsService = require('../apps.ts') as {
  createCollector(deps: {
    checkTcpPort: (port: number, host?: string, timeout?: number) => Promise<boolean>;
  }): {
    getPayload(refresh: boolean): Promise<{ apps: Array<{ status: string }>; [key: string]: unknown }>;
  };
  toPublicPayload(payload: { categories?: unknown; apps?: unknown }): unknown;
  createRefreshLimiter(windowMs: number): (key: string, now?: number) => boolean;
};
const { checkTcpPort } = require('../probe/services.ts') as {
  checkTcpPort: (port: number, host?: string, timeout?: number) => Promise<boolean>;
};
const { auditLog, clientIp } = require('../util.ts') as {
  auditLog: (action: string, ip: string, ok: unknown, detail?: string) => void;
  clientIp: (req: import('express').Request) => string;
};

const router = express.Router();

// 公开面板独立采集器：与 admin 面板各自持有缓存，互不影响（admin 行为保持不变）
const appsCollector = appsService.createCollector({ checkTcpPort });

// 刷新限流窗口与缓存 TTL 一致（10s）：同一 IP 一个窗口内至多一次真正刷新
const REFRESH_WINDOW_MS = 10000;
const allowRefresh = appsService.createRefreshLimiter(REFRESH_WINDOW_MS);

// 公开应用中心（免鉴权，只读）
router.get('/api/public/apps', async (req, res) => {
  const ip = clientIp(req);
  const t0 = Date.now();
  const wantsRefresh = req.query.refresh === '1' || req.query.refresh === 'true';
  // 公开接口不能变成打本机的放大器：窗口内重复 refresh 一律按缓存读
  const refresh = wantsRefresh && allowRefresh(ip);
  try {
    const payload = await appsCollector.getPayload(refresh);
    const failed = payload.apps.filter((a) => a.status === 'down').length;
    // 审计只记条数 / 耗时 / 失败条数，绝不记录登记表里的 url
    auditLog(
      'public_apps_list',
      ip,
      true,
      `apps=${payload.apps.length} failed=${failed} ms=${Date.now() - t0}`
    );
    res.set('Cache-Control', 'no-store');
    res.json(appsService.toPublicPayload(payload));
  } catch {
    auditLog('public_apps_list', ip, false, `ms=${Date.now() - t0}`);
    // 后端不可用：统一 503 通用文案，绝不回 500 栈信息
    res.status(503).json({ error: '应用数据暂不可用' });
  }
});

module.exports = router;
