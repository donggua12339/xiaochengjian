/**
 * API client 纯函数单元测试
 *
 * 覆盖:
 *  - token 存取(getAccessToken / getRefreshToken / setTokens / clearTokens)
 *  - extractApiError(axios 错误 -> ApiError)
 */

describe('api/client', () => {
  beforeEach(() => {
    localStorage.clear();
  });

  describe('token 存取', () => {
    let client: typeof import('./client');

    beforeEach(async () => {
      jest.resetModules();
      client = await import('./client');
    });

    it('getAccessToken 初始返回 null', () => {
      expect(client.getAccessToken()).toBeNull();
    });

    it('getRefreshToken 初始返回 null', () => {
      expect(client.getRefreshToken()).toBeNull();
    });

    it('setTokens 写入后 getAccessToken / getRefreshToken 可读', () => {
      client.setTokens('access-123', 'refresh-456');
      expect(client.getAccessToken()).toBe('access-123');
      expect(client.getRefreshToken()).toBe('refresh-456');
    });

    it('clearTokens 清除后返回 null', () => {
      client.setTokens('access', 'refresh');
      client.clearTokens();
      expect(client.getAccessToken()).toBeNull();
      expect(client.getRefreshToken()).toBeNull();
    });

    it('setTokens 覆盖旧 token', () => {
      client.setTokens('old-access', 'old-refresh');
      client.setTokens('new-access', 'new-refresh');
      expect(client.getAccessToken()).toBe('new-access');
      expect(client.getRefreshToken()).toBe('new-refresh');
    });
  });

  describe('extractApiError', () => {
    let client: typeof import('./client');
    let axios: typeof import('axios').default;

    beforeEach(async () => {
      jest.resetModules();
      client = await import('./client');
      axios = (await import('axios')).default;
    });

    it('axios 错误 + 有 response.data 时提取 code/message', () => {
      const error = {
        isAxiosError: true,
        response: {
          data: {
            code: 'CARD_INVALID',
            message: '卡密无效',
            requestId: 'req-1',
            timestamp: '2026-07-19T00:00:00Z',
          },
        },
        message: 'Request failed',
      };
      const result = client.extractApiError(error);
      expect(result.code).toBe('CARD_INVALID');
      expect(result.message).toBe('卡密无效');
      expect(result.requestId).toBe('req-1');
      expect(result.timestamp).toBe('2026-07-19T00:00:00Z');
    });

    it('axios 错误 + 无 response.data 时 fallback 到 error.message', () => {
      const error = {
        isAxiosError: true,
        response: undefined,
        message: 'Network Error',
      };
      const result = client.extractApiError(error);
      expect(result.code).toBe('UNKNOWN');
      expect(result.message).toBe('Network Error');
    });

    it('axios 错误 + response.data 无 code/message 时用默认值', () => {
      const error = {
        isAxiosError: true,
        response: { data: {} },
        message: 'some error',
      };
      const result = client.extractApiError(error);
      expect(result.code).toBe('UNKNOWN');
      expect(result.message).toBe('some error');
    });

    it('非 axios 错误(Error 实例)时提取 message', () => {
      const error = new Error('something wrong');
      const result = client.extractApiError(error);
      expect(result.code).toBe('UNKNOWN');
      expect(result.message).toBe('something wrong');
    });

    it('非 Error 非 axios 错误时返回默认 message', () => {
      const result = client.extractApiError(null);
      expect(result.code).toBe('UNKNOWN');
      expect(result.message).toBe('未知错误');
    });

    it('真实 axios 错误可通过 isAxiosError 判断', () => {
      // 构造一个真实 axios 错误(不发请求,用静态方法)
      const fakeError = new axios.AxiosError(
        'timeout of 15000ms exceeded',
        'ECONNABORTED',
        undefined,
        undefined,
        {
          status: 408,
          data: { code: 'TIMEOUT', message: '请求超时' },
        } as any,
      );
      const result = client.extractApiError(fakeError);
      expect(result.code).toBe('TIMEOUT');
      expect(result.message).toBe('请求超时');
    });
  });
});
