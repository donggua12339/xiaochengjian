import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';

/**
 * 统一异常响应
 * - 不向客户端暴露内部错误细节(防信息泄露)
 * - 记录完整错误到日志(含 requestId)
 * - 客户端可通过 requestId 联系运维查日志
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();
    const requestId = (request.headers['x-request-id'] as string) ?? uuidv4();

    let status: number;
    let message: string;
    let code: string | undefined;

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const resp = exception.getResponse();
      if (typeof resp === 'string') {
        message = resp;
        code = this.statusToCode(status);
      } else if (typeof resp === 'object' && resp !== null) {
        const r = resp as Record<string, unknown>;
        const rawMessage = r.message;
        if (Array.isArray(rawMessage)) {
          message = rawMessage[0] ?? exception.message;
        } else if (typeof rawMessage === 'string') {
          message = rawMessage;
        } else {
          message = exception.message;
        }
        code = (r.code as string) ?? this.statusToCode(status);
      } else {
        message = exception.message;
        code = this.statusToCode(status);
      }
    } else if (exception instanceof Error) {
      status = HttpStatus.INTERNAL_SERVER_ERROR;
      message = '服务器内部错误';
      code = 'INTERNAL_ERROR';
      this.logger.error(
        `requestId=${requestId} path=${request.method} ${request.url} error=${exception.message}`,
        exception.stack,
      );
    } else {
      status = HttpStatus.INTERNAL_SERVER_ERROR;
      message = '服务器内部错误';
      code = 'INTERNAL_ERROR';
    }

    // 业务异常(HttpException 非 5xx)记 warn,5xx 记 error
    if (status >= 500) {
      this.logger.error(
        `requestId=${requestId} ${status} ${code} ${request.method} ${request.url}`,
      );
    } else if (status >= 400) {
      this.logger.warn(`requestId=${requestId} ${status} ${code} ${request.method} ${request.url}`);
    }

    response.status(status).json({
      code,
      message,
      requestId,
      timestamp: new Date().toISOString(),
    });
  }

  private statusToCode(status: number): string {
    switch (status) {
      case HttpStatus.BAD_REQUEST:
        return 'BAD_REQUEST';
      case HttpStatus.UNAUTHORIZED:
        return 'UNAUTHORIZED';
      case HttpStatus.FORBIDDEN:
        return 'FORBIDDEN';
      case HttpStatus.NOT_FOUND:
        return 'NOT_FOUND';
      case HttpStatus.CONFLICT:
        return 'CONFLICT';
      case HttpStatus.TOO_MANY_REQUESTS:
        return 'TOO_MANY_REQUESTS';
      case HttpStatus.INTERNAL_SERVER_ERROR:
        return 'INTERNAL_ERROR';
      default:
        return 'ERROR';
    }
  }
}
