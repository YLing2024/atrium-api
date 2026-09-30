'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type { Request, Response, NextFunction } from 'express';

/**
 * 统一错误处理：multer 体积超限等，保持既有状态码与中文 JSON 文案。
 * 说明：仓库现状没有 JSON 解析错误中间件、没有静态托管、没有自定义 404 兜底
 * （未知路径/坏 JSON 均由 express 默认行为处理）；此处不新增，以免改变既有行为。
 */

const multer = require('multer') as typeof import('multer');

// 全局错误处理（multer 体积超限等）
function errorHandler(err: unknown, req: Request, res: Response, next: NextFunction) {
  if (err instanceof multer.MulterError) {
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    return res.status(status).json({ error: '文件过大（上限 100MB）' });
  }
  console.error('[admin-server] 未捕获错误:', err);
  res.status(500).json({ error: '服务器内部错误' });
}

module.exports = { errorHandler };
