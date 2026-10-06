'use strict';

/**
 * admin-server 入口
 *  - 装配中间件链、挂载各业务 router、启动采样/通知维护、app.listen
 *  - 业务逻辑分层在 probe / metrics / notifications / middleware / routes 下
 */

import type {} from 'express';

const express = require('express') as typeof import('express');

const config = require('./config.ts') as import('./config.ts').AdminConfigModule;
const { errorHandler } = require('./middleware/errors.ts') as {
  errorHandler: (
    err: unknown,
    req: import('express').Request,
    res: import('express').Response,
    next: import('express').NextFunction
  ) => void;
};
const { startSampler } = require('./metrics/store.ts') as { startSampler: () => void };
const { startNotificationMaintenance } = require('./notifications/store.ts') as {
  startNotificationMaintenance: () => void;
};
const { UPLOAD_DIR } = require('./routes/files.ts') as { UPLOAD_DIR: string };

const systemRouter = require('./routes/system.ts');
const authRouter = require('./routes/auth.ts');
const apiTokensRouter = require('./routes/api-tokens.ts');
const notificationsRouter = require('./routes/notifications.ts');
const versionsRouter = require('./routes/versions.ts');
const termRouter = require('./routes/term.ts');
const appsRouter = require('./routes/apps.ts');
const publicAppsRouter = require('./routes/public-apps.ts');
const filesRouter = require('./routes/files.ts');
const sharesRouter = require('./routes/shares.ts');
const historyRouter = require('./routes/history.ts');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 挂载顺序与原单文件路由注册顺序保持一致（同名路径不存在跨模块重叠）
app.use(systemRouter); // '/' + 系统信息 / 服务状态 / 历史与聚合 / SSE
app.use(authRouter); // 认证 / 设备会话 / TOTP / 修改密码
app.use(apiTokensRouter); // 接口令牌
app.use(notificationsRouter); // 通知中心
app.use(versionsRouter); // 软件版本
app.use(termRouter); // Web 终端
app.use(appsRouter); // 应用面板
app.use(publicAppsRouter); // 公开只读应用中心（/api/public/apps，免鉴权）
app.use(filesRouter); // 通用上传下载 + 文件区
app.use(sharesRouter); // 文件区临时链接
app.use(errorHandler); // 统一错误处理（与原位置一致：files/shares 之后、history 之前）
app.use(historyRouter); // Hermes 历史只读浏览

// 启动采样器与通知维护（与原模块加载期自启动的副作用等价）
startSampler();
startNotificationMaintenance();

app.listen(config.PORT, config.HOST, () => {
  console.log(`[admin-server] 已启动，监听地址: ${config.HOST}:${config.PORT}`);
  console.log(
    `[admin-server] 管理端认证模式: ${config.AUTH_MODE === 'sso' ? 'SSO（信任 X-Auth-User）' : '自带账号（builtin）'}`
  );
  console.log(`[admin-server] 上传目录: ${UPLOAD_DIR}`);
  console.log(`[admin-server] 配置文件: ${config.CONFIG_PATH}`);
  console.log(`[admin-server] 提示: 登录使用 TOTP 动态验证码，secret 见 config.json 的 totp_secret 字段`);
});
