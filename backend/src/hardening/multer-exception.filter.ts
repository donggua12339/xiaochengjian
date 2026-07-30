import {
  Catch,
  ExceptionFilter,
  ArgumentsHost,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { MulterError } from 'multer';
import type { Response } from 'express';

/**
 * Multer 异常过滤器
 *
 * 将 multer 内部错误码映射为语义化 HTTP 响应,
 * 避免用户看到裸 500 或 "LIMIT_FILE_SIZE" 等技术字符串。
 */
@Catch(MulterError)
export class MulterExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(MulterExceptionFilter.name);

  catch(exception: MulterError, host: ArgumentsHost): void {
    const response = host.switchToHttp().getResponse<Response>();

    const errorMap: Record<string, { status: number; message: string }> = {
      LIMIT_FILE_SIZE: {
        status: HttpStatus.PAYLOAD_TOO_LARGE,
        message: '文件大小超过限制(最大 200MB)',
      },
      LIMIT_FILE_COUNT: {
        status: HttpStatus.BAD_REQUEST,
        message: '文件数量超过限制',
      },
      LIMIT_UNEXPECTED_FILE: {
        status: HttpStatus.BAD_REQUEST,
        message: '上传字段名不正确(期望 apk 或 keystore)',
      },
      LIMIT_FIELD_KEY: {
        status: HttpStatus.BAD_REQUEST,
        message: '字段名过长',
      },
      LIMIT_FIELD_COUNT: {
        status: HttpStatus.BAD_REQUEST,
        message: '字段数量超过限制',
      },
      LIMIT_FIELD_SIZE: {
        status: HttpStatus.BAD_REQUEST,
        message: '字段值超过大小限制',
      },
    };

    const mapped = errorMap[exception.code] ?? {
      status: HttpStatus.INTERNAL_SERVER_ERROR,
      message: '文件上传失败',
    };

    this.logger.warn(
      `MulterError: code=${exception.code} field=${exception.field} message=${exception.message}`,
    );

    response.status(mapped.status).json({
      code: 'UPLOAD_ERROR',
      message: mapped.message,
      detail: exception.code,
    });
  }
}
