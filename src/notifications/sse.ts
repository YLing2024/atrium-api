'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type { Response } from 'express';
import type { NotificationItem } from './store.ts';

/**
 * 通知 SSE 广播：订阅者集合 + 新通知入帧推送（连接断开必须移除，不泄漏监听器）。
 */

// SSE 订阅者集合：新通知入库后立即广播
const notificationClients = new Set<Response>();

function broadcastNotification(item: NotificationItem): void {
  const frame = 'event: notification\ndata: ' + JSON.stringify(item) + '\n\n';
  for (const res of notificationClients) {
    try {
      res.write(frame);
    } catch (e: any) {
      notificationClients.delete(res);
    }
  }
}

module.exports = { notificationClients, broadcastNotification };
