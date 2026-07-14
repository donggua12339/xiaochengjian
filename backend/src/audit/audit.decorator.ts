import { SetMetadata } from '@nestjs/common';
import type { AuditAction } from '@prisma/client';

/**
 * 审计日志装饰器
 * 标记接口需要记录审计日志
 *
 * 用法:
 *   @Audit('CREATE_APP')
 *   @Post()
 *   async createApp(...) { ... }
 *
 * 拦截器会自动记录:developerId(从 JWT) + action + target(从返回值的 id) + ip + userAgent
 */
export const AUDIT_KEY = 'auditAction';
export const Audit = (action: AuditAction) => SetMetadata(AUDIT_KEY, action);
