'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type { Request } from 'express';

/**
 * 通用工具：审计日志、客户端 IP、哈希比对与 EMA 平滑。
 * 本模块为最底层（不依赖项目内其它模块），供各服务与路由复用。
 */

const fs = require('fs') as typeof import('fs');
const path = require('path') as typeof import('path');
const crypto = require('crypto') as typeof import('crypto');

// 审计日志：JSON 行追加写，写入失败不影响业务
const AUDIT_LOG_FILE =
  process.env.ADMIN_AUDIT_LOG || path.join(__dirname, '..', 'audit.log');

function auditLog(action: string, ip: string, ok: unknown, detail?: string): void {
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
  } catch (e: any) {
    // 审计日志写入失败仅告警，不阻断业务
    console.error('[admin-server] 审计日志写入失败:', e.message);
  }
}

// 取客户端 IP：nginx 统一注入 X-Real-IP（req.ip 恒为回环），再退化到 X-Forwarded-For / socket
function clientIp(req: Request): string {
  const xr = req.headers['x-real-ip'];
  if (xr && String(xr).trim()) return String(xr).trim();
  const xf = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  if (xf) return xf;
  return req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
}

// SHA-256 后定时安全比较，避免时序攻击
function sha256(str: unknown): Buffer {
  return crypto.createHash('sha256').update(String(str)).digest();
}

function verifyPassword(input: unknown, stored: unknown): boolean {
  const a = sha256(input);
  const b = sha256(stored);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// 十六进制 sha256（接口令牌 key 用：api:token:<sha256(token)>，只存哈希不存明文）
function sha256hex(str: unknown): string {
  return crypto.createHash('sha256').update(String(str)).digest('hex');
}

// 通用 EMA（指数移动平均）平滑：所有 CPU 值统一走此函数，同参数结果一致。
// prev 为 null/undefined（首次）时直接取 current，避免冷启动跳变
function ema(prev: number | null | undefined, current: number, alpha: number): number {
  return prev == null ? current : prev * (1 - alpha) + current * alpha;
}

module.exports = { auditLog, clientIp, sha256, verifyPassword, sha256hex, ema };
