'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type { Request, Response, NextFunction } from 'express';

/**
 * 鉴权中间件：本地会话（builtin）/ SSO 头（X-Auth-User）/ API Token，含 401 语义。
 */

const fs = require('fs') as typeof import('fs');
const path = require('path') as typeof import('path');
const crypto = require('crypto') as typeof import('crypto');
const { createTotpAuth } = require('totp-auth') as typeof import('totp-auth');

const config = require('../config.ts') as import('../config.ts').AdminConfigModule;
const { AUTH_MODE } = config;
const state = require('../state.ts') as {
  redis: import('ioredis').Redis;
};
const { redis } = state;
const { sha256hex } = require('../util.ts') as {
  sha256hex: (str: unknown) => string;
};

// 本服务注入的登录身份（express Request 扩展，供 authRequired 之后的处理器读取）
declare global {
  // 既有的 express 类型扩展写法：为此命名空间声明式地补充 Request 字段
  // （ESLint 报告 namespace 写法，但改成模块语法会改变类型扩展语义，故保留）
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: { role: string; name: string; via: string };
    }
  }
}

// 多会话：Redis key 带 token 后缀（admin:session:<token>），每个会话独立，多端可同时登录
const SESSION_KEY_PREFIX = process.env.ADMIN_REDIS_PREFIX || 'admin:session:';
const SESSION_TTL = 43200; // 12 小时，每次请求校验通过后滑动续期

// 接口令牌：Redis key 前缀 api:token:<sha256(token)>，只存哈希不存明文。
// 固定过期不滑动、绝不进 SESSION_INDEX_SET、不写设备元数据 → 与登录设备管理完全隔离
const API_TOKEN_PREFIX = 'api:token:';
const API_TOKEN_MAX_DAYS = 365;

function sessionKey(token: string): string {
  return SESSION_KEY_PREFIX + token;
}

function apiTokenKey(id: string): string {
  return API_TOKEN_PREFIX + id;
}

// 接口令牌元数据（Redis 里的 JSON）
export type ApiTokenMeta = {
  id: string;
  name: string;
  note?: string;
  createdAt?: number | string;
  expiresAt?: number | string;
  lastUsedAt?: number | string;
  canWrite?: boolean;
};

// TOTP secret 持久化文件（可被 ADMIN_TOTP_SECRET_FILE 覆盖，测试实例独立隔离）
const TOTP_SECRET_FILE =
  process.env.ADMIN_TOTP_SECRET_FILE || path.join(__dirname, '..', '..', 'totp-secret.json');

// 复用独立模块：TOTP 动态码验证 + JWT + 按 IP 阶梯限速 + secret 文件持久化
const totpAuth = createTotpAuth({
  secretFile: TOTP_SECRET_FILE,
  issuer: 'HomeAdmin',
  jwtSecret: config.getOrCreateJwtSecret(),
  jwtExpiresIn: '12h',
  rateLimit: { maxFailures: 5, lockout: [60, 300, 900] }
});

// 手工解析 Cookie 头取指定字段（无 cookie-parser 依赖）
function readCookie(req: Request, name: string): string {
  const raw = req.headers.cookie || '';
  for (const part of String(raw).split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return '';
}

// 自带账号会话 token：Authorization: Bearer 优先，其次 HttpOnly cookie admin_session
function builtinSessionToken(req: Request): string {
  const header = req.headers.authorization || '';
  if (header.startsWith('Bearer ')) {
    const t = header.slice(7).trim();
    if (t) return t;
  }
  return readCookie(req, 'admin_session');
}

// 下发自带账号会话 cookie：Path=/; HttpOnly; SameSite=Lax；HTTPS（X-Forwarded-Proto / req.secure）下加 Secure
function setSessionCookie(req: Request, res: Response, token: string): void {
  const proto = String(req.get('x-forwarded-proto') || '').split(',')[0].trim();
  const secure = proto === 'https' || req.secure;
  const parts = [
    `admin_session=${token}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${SESSION_TTL}`
  ];
  if (secure) parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}

// 清除会话 cookie（登出）
function clearSessionCookie(res: Response): void {
  res.append('Set-Cookie', 'admin_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0');
}

// 鉴权中间件：按 AUTH_MODE 分支
//   builtin —— 自带账号会话：`Authorization: Bearer <token>` 或 cookie `admin_session`，
//             在 Redis 校验 `admin:session:<token>`，命中即通过并滑动续期；**忽略外部 X-Auth-User**（防提权）。
//   sso     —— 只认前置认证层注入的 `X-Auth-User`（网关会先剥掉客户端伪造的同名头）。
// 两种情况失败都返回 401 JSON（不 302、不 500）。
async function authRequired(req: Request, res: Response, next: NextFunction) {
  if (AUTH_MODE === 'builtin') {
    const token = builtinSessionToken(req);
    if (token) {
      try {
        if (await redis.get(sessionKey(token))) {
          await redis.expire(sessionKey(token), SESSION_TTL); // 滑动续期，沿用现有 TTL
          req.user = { role: 'admin', name: 'admin', via: 'builtin' };
          return next();
        }
      } catch (e: any) {
        return res.status(500).json({ error: '会话服务异常' });
      }
    }
    return res.status(401).json({ error: '未登录' });
  }
  const xAuthUser = req.get('x-auth-user');
  if (xAuthUser && String(xAuthUser).trim()) {
    req.user = { role: 'admin', name: String(xAuthUser).trim(), via: 'gateway' };
    return next();
  }
  return res.status(401).json({ error: '未登录' });
}

// 解析 api:token: 值的 JSON；返回 null 表示数据异常
function parseApiTokenMeta(raw: string | null): ApiTokenMeta | null {
  if (!raw) return null;
  try {
    const meta = JSON.parse(raw);
    if (!meta || typeof meta.id !== 'string' || typeof meta.name !== 'string') return null;
    return meta;
  } catch (e: any) {
    return null;
  }
}

// 按明文 token 查 API 令牌表：命中返回 meta，未命中/数据异常返回 null。
// authRequired 的降级分支与 notificationsWriteAuth 的 canWrite 闸门共用此函数（唯一比对入口）。
// 注意：不在此吞掉 Redis 异常，交由各自调用方 try/catch 决定 500 还是 401。
async function lookupApiTokenMeta(token: string | null): Promise<ApiTokenMeta | null> {
  if (!token) return null;
  const raw = await redis.get(API_TOKEN_PREFIX + sha256hex(token));
  const meta = parseApiTokenMeta(raw);
  if (!meta || typeof meta.name !== 'string' || !meta.name) return null;
  return meta;
}

// 写入接口鉴权：仅「直连回环地址」的本机脚本免 SSO。
// 注意 admin-server 只监听 127.0.0.1，经 nginx 反代的请求 socket 也是回环，
// 但 nginx 必然注入 X-Real-IP / X-Forwarded-For；据此把它们继续交给 authRequired，
// 避免把写入接口做成事实上的完全公开。
function isDirectLoopback(req: Request): boolean {
  const addr = ((req.socket && req.socket.remoteAddress) || '').replace(/^::ffff:/, '');
  if (addr !== '127.0.0.1' && addr !== '::1') return false;
  if (req.headers['x-real-ip'] || req.headers['x-forwarded-for']) return false;
  return true;
}

// 从请求中提取 API 令牌明文：Authorization: Bearer 优先，兼容 X-Quotahub-Token 与 ?token=
// （仅用于通知写入等独立令牌通道；/api/admin/* 主鉴权只认网关注入的 X-Auth-User）
function requestApiToken(req: Request): string | null {
  const header = req.headers.authorization || '';
  if (header.startsWith('Bearer ')) {
    const t = header.slice(7).trim();
    if (t) return t;
  }
  const alias = req.get('x-quotahub-token');
  if (alias && String(alias).trim()) return String(alias).trim();
  const queryToken = req.query && req.query.token ? String(req.query.token) : null;
  return queryToken && queryToken.trim() ? queryToken.trim() : null;
}

async function notificationsWriteAuth(req: Request, res: Response, next: NextFunction) {
  if (isDirectLoopback(req)) return next();
  // 显式识别「本次请求是否用 API Token」：经网关的请求带 X-Auth-User，authRequired 会走
  // 「信任头部」路径、req.user 无 via/canWrite，只读令牌会绕过闸门，故这里独立查令牌表。
  const token = requestApiToken(req);
  if (token) {
    let meta;
    try {
      meta = await lookupApiTokenMeta(token);
    } catch (e: any) {
      return res.status(500).json({ error: '会话服务异常' });
    }
    if (meta) {
      // 命中 API 令牌表：只有 canWrite=true 才放行，否则 403（沿用原中文文案）
      if (meta.canWrite === true) return next();
      return res.status(403).json({ error: '该接口令牌为只读，无权写入通知' });
    }
  }
  // 不是 API 令牌（SSO 会话 / 其它）→ 走原有鉴权逻辑，不受影响
  return authRequired(req, res, next);
}

module.exports = {
  authRequired,
  notificationsWriteAuth,
  sessionKey,
  SESSION_KEY_PREFIX,
  SESSION_TTL,
  apiTokenKey,
  API_TOKEN_PREFIX,
  API_TOKEN_MAX_DAYS,
  parseApiTokenMeta,
  lookupApiTokenMeta,
  builtinSessionToken,
  setSessionCookie,
  clearSessionCookie,
  totpAuth
};
