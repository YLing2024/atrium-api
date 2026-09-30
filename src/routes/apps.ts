'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type {} from 'express';

/**
 * 应用面板路由：只读消费应用登记表 + 实时探活（逻辑在 src/apps.ts）。
 * 模块级缓存 TTL 10s + 单飞（并发复用同一 Promise），refresh=1 绕过缓存。
 */

const express = require('express') as typeof import('express');

const appsService = require('../apps.ts') as {
  createCollector(deps: {
    checkTcpPort: (port: number, host?: string, timeout?: number) => Promise<boolean>;
  }): {
    getPayload(refresh: boolean): Promise<{ apps: Array<{ status: string }>; [key: string]: unknown }>;
  };
};
const { checkTcpPort } = require('../probe/services.ts') as {
  checkTcpPort: (port: number, host?: string, timeout?: number) => Promise<boolean>;
};
const { authRequired } = require('../middleware/auth.ts') as {
  authRequired: import('express').RequestHandler;
};
const { auditLog, clientIp } = require('../util.ts') as {
  auditLog: (action: string, ip: string, ok: unknown, detail?: string) => void;
  clientIp: (req: import('express').Request) => string;
};

const router = express.Router();

// 应用登记表 + 探活：只读消费，逻辑见 src/apps.ts。
const appsCollector = appsService.createCollector({ checkTcpPort });

router.get('/api/admin/apps', authRequired, async (req, res) => {
  const ip = clientIp(req);
  const t0 = Date.now();
  const refresh = req.query.refresh === '1' || req.query.refresh === 'true';
  try {
    const payload = await appsCollector.getPayload(refresh);
    const failed = payload.apps.filter((a) => a.status === 'down').length;
    // 审计只记条数 / 耗时 / 失败条数，绝不记录登记表里的 url
    auditLog('apps_list', ip, true, `apps=${payload.apps.length} failed=${failed} ms=${Date.now() - t0}`);
    res.json(payload);
  } catch (e: any) {
    auditLog('apps_list', ip, false, `ms=${Date.now() - t0}`);
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
