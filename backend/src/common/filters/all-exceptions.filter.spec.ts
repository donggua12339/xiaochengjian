import { Test } from '@nestjs/testing';
import {
  HttpException,
  HttpStatus,
  BadRequestException,
  NotFoundException,
  UnauthorizedException,
  ConflictException,
  ForbiddenException,
} from '@nestjs/common';
import { AllExceptionsFilter } from './all-exceptions.filter';

/**
 * AllExceptionsFilter 单元测试
 *
 * 覆盖:
 *  - HttpException + string response
 *  - HttpException + object response(message string / array / missing)
 *  - HttpException + object response with custom code
 *  - 普通 Error(500)
 *  - 非 Error 对象(500)
 *  - x-request-id 从 header 读取
 *  - 无 x-request-id 生成 uuid
 *  - statusToCode 全分支
 *  - response.json 格式
 */
describe('AllExceptionsFilter', () => {
  let filter: AllExceptionsFilter;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      providers: [AllExceptionsFilter],
    }).compile();
    filter = moduleRef.get(AllExceptionsFilter);
  });

  function buildHost(opts: {
    requestId?: string;
    method?: string;
    url?: string;
  } = {}): any {
    const headers: Record<string, string> = {};
    if (opts.requestId) headers['x-request-id'] = opts.requestId;
    const response = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
    };
    return {
      switchToHttp: () => ({
        getResponse: () => response,
        getRequest: () => ({
          headers,
          method: opts.method ?? 'POST',
          url: opts.url ?? '/v1/test',
        }),
      }),
    };
  }

  function getResponse(host: any) {
    return host.switchToHttp().getResponse();
  }

  describe('HttpException 处理', () => {
    it('string response 应直接作为 message', () => {
      const host = buildHost();
      const ex = new HttpException('custom error', HttpStatus.BAD_REQUEST);
      filter.catch(ex, host);
      const res = getResponse(host);
      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'BAD_REQUEST',
          message: 'custom error',
        }),
      );
    });

    it('object response + message string', () => {
      const host = buildHost();
      const ex = new NotFoundException({
        message: 'CARD_NOT_FOUND',
        code: 'CARD_NOT_FOUND',
      });
      filter.catch(ex, host);
      const res = getResponse(host);
      expect(res.status).toHaveBeenCalledWith(404);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'CARD_NOT_FOUND',
          message: 'CARD_NOT_FOUND',
        }),
      );
    });

    it('object response + message array 应取第一个', () => {
      const host = buildHost();
      const ex = new BadRequestException({
        message: ['field1 is required', 'field2 is invalid'],
      });
      filter.catch(ex, host);
      const res = getResponse(host);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'field1 is required',
          code: 'BAD_REQUEST',
        }),
      );
    });

    it('object response 无 message 字段应用 exception.message', () => {
      const host = buildHost();
      const ex = new HttpException({ code: 'CUSTOM' }, HttpStatus.CONFLICT);
      filter.catch(ex, host);
      const res = getResponse(host);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'CUSTOM',
          message: expect.any(String),
        }),
      );
    });

    it('object response 无 code 字段应用 statusToCode', () => {
      const host = buildHost();
      const ex = new UnauthorizedException({ message: 'INVALID_CREDENTIALS' });
      filter.catch(ex, host);
      const res = getResponse(host);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'UNAUTHORIZED',
          message: 'INVALID_CREDENTIALS',
        }),
      );
    });

    it('ForbiddenException 403', () => {
      const host = buildHost();
      filter.catch(new ForbiddenException('APP_LIMIT_REACHED'), host);
      expect(getResponse(host).status).toHaveBeenCalledWith(403);
    });

    it('ConflictException 409', () => {
      const host = buildHost();
      filter.catch(new ConflictException('EMAIL_ALREADY_REGISTERED'), host);
      expect(getResponse(host).status).toHaveBeenCalledWith(409);
    });
  });

  describe('非 HttpException', () => {
    it('普通 Error 应 500 + INTERNAL_ERROR + 服务器内部错误', () => {
      const host = buildHost();
      const ex = new Error('database connection failed');
      filter.catch(ex, host);
      const res = getResponse(host);
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'INTERNAL_ERROR',
          message: '服务器内部错误',
        }),
      );
    });

    it('非 Error 对象(string)应 500', () => {
      const host = buildHost();
      filter.catch('string error', host);
      const res = getResponse(host);
      expect(res.status).toHaveBeenCalledWith(500);
      expect(res.json).toHaveBeenCalledWith(
        expect.objectContaining({
          code: 'INTERNAL_ERROR',
          message: '服务器内部错误',
        }),
      );
    });

    it('null 应 500', () => {
      const host = buildHost();
      filter.catch(null, host);
      expect(getResponse(host).status).toHaveBeenCalledWith(500);
    });

    it('undefined 应 500', () => {
      const host = buildHost();
      filter.catch(undefined, host);
      expect(getResponse(host).status).toHaveBeenCalledWith(500);
    });
  });

  describe('requestId 处理', () => {
    it('应从 x-request-id header 读取', () => {
      const host = buildHost({ requestId: 'my-request-id' });
      filter.catch(new Error('x'), host);
      expect(getResponse(host).json).toHaveBeenCalledWith(
        expect.objectContaining({
          requestId: 'my-request-id',
        }),
      );
    });

    it('无 x-request-id 应生成 uuid', () => {
      const host = buildHost();
      filter.catch(new Error('x'), host);
      const call = getResponse(host).json.mock.calls[0][0];
      expect(call.requestId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );
    });
  });

  describe('response.json 格式', () => {
    it('应含 code/message/requestId/timestamp', () => {
      const host = buildHost({ requestId: 'r-1' });
      filter.catch(new BadRequestException('bad'), host);
      const body = getResponse(host).json.mock.calls[0][0];
      expect(body).toHaveProperty('code');
      expect(body).toHaveProperty('message');
      expect(body).toHaveProperty('requestId', 'r-1');
      expect(body).toHaveProperty('timestamp');
      expect(body.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    });
  });

  describe('statusToCode 全分支', () => {
    function testStatus(status: HttpStatus, expectedCode: string) {
      const host = buildHost();
      filter.catch(new HttpException('x', status), host);
      expect(getResponse(host).json.mock.calls[0][0].code).toBe(expectedCode);
    }

    it('400 -> BAD_REQUEST', () => testStatus(HttpStatus.BAD_REQUEST, 'BAD_REQUEST'));
    it('401 -> UNAUTHORIZED', () => testStatus(HttpStatus.UNAUTHORIZED, 'UNAUTHORIZED'));
    it('403 -> FORBIDDEN', () => testStatus(HttpStatus.FORBIDDEN, 'FORBIDDEN'));
    it('404 -> NOT_FOUND', () => testStatus(HttpStatus.NOT_FOUND, 'NOT_FOUND'));
    it('409 -> CONFLICT', () => testStatus(HttpStatus.CONFLICT, 'CONFLICT'));
    it('429 -> TOO_MANY_REQUESTS', () => testStatus(HttpStatus.TOO_MANY_REQUESTS, 'TOO_MANY_REQUESTS'));
    it('500 -> INTERNAL_ERROR', () => testStatus(HttpStatus.INTERNAL_SERVER_ERROR, 'INTERNAL_ERROR'));
    it('418 -> ERROR(默认)', () => testStatus(418, 'ERROR'));
    it('302 -> ERROR(非错误状态码默认)', () => testStatus(302, 'ERROR'));
  });
});
