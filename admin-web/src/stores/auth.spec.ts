/**
 * auth store 单元测试
 *
 * 覆盖:
 *  - isLoggedIn / needs2FA getters
 *  - login(成功 + requiresTotp 分支)
 *  - logout(清 token + 清 developer)
 *  - handleError(转调 extractApiError)
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { setActivePinia, createPinia } from 'pinia';

// mock api/client 的 request + token 操作
vi.mock('@/api/client', () => ({
  request: vi.fn(),
  setTokens: vi.fn(),
  clearTokens: vi.fn(),
  getAccessToken: vi.fn(() => null),
  extractApiError: vi.fn((err: unknown) => ({
    code: 'TEST_CODE',
    message: (err as Error)?.message ?? '测试错误',
  })),
}));

import { useAuthStore } from './auth';
import { request, clearTokens, setTokens, getAccessToken } from '@/api/client';

describe('auth store', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    vi.clearAllMocks();
  });

  describe('getters', () => {
    it('初始状态 isLoggedIn=false', () => {
      const store = useAuthStore();
      expect(store.isLoggedIn).toBe(false);
    });

    it('accessToken 存在时 isLoggedIn=true', () => {
      vi.mocked(getAccessToken).mockReturnValue('token-123');
      const store = useAuthStore();
      expect(store.isLoggedIn).toBe(true);
    });

    it('developer 为 null 时 needs2FA=false', () => {
      const store = useAuthStore();
      expect(store.needs2FA).toBe(false);
    });

    it('developer.totpEnabled=true 时 needs2FA=true', () => {
      const store = useAuthStore();
      store.developer = {
        id: 'd1',
        email: 'a@b.c',
        role: 'USER',
        vipLevel: 'free',
        totpEnabled: true,
        maxApps: 5,
        createdAt: '2026-01-01',
      };
      expect(store.needs2FA).toBe(true);
    });
  });

  describe('login', () => {
    it('requiresTotp=false 时存 token', async () => {
      vi.mocked(request).mockResolvedValueOnce({
        requiresTotp: false,
        accessToken: 'access-1',
        refreshToken: 'refresh-1',
      });

      const store = useAuthStore();
      const result = await store.login('a@b.c', 'pass');

      expect(result.requiresTotp).toBe(false);
      expect(setTokens).toHaveBeenCalledWith('access-1', 'refresh-1');
      expect(store.accessToken).toBe('access-1');
    });

    it('requiresTotp=true 时不存 token,返回 pendingTotpToken', async () => {
      vi.mocked(request).mockResolvedValueOnce({
        requiresTotp: true,
        pendingTotpToken: 'pending-1',
      });

      const store = useAuthStore();
      const result = await store.login('a@b.c', 'pass');

      expect(result.requiresTotp).toBe(true);
      expect(result.pendingTotpToken).toBe('pending-1');
      expect(setTokens).not.toHaveBeenCalled();
    });
  });

  describe('logout', () => {
    it('清 token + 清 developer', async () => {
      vi.mocked(request).mockResolvedValueOnce({});
      localStorage.setItem('xcj_refresh_token', 'refresh-1');

      const store = useAuthStore();
      store.accessToken = 'access-1';
      store.developer = {
        id: 'd1',
        email: 'a@b.c',
        role: 'USER',
        vipLevel: 'free',
        totpEnabled: false,
        maxApps: 5,
        createdAt: '2026-01-01',
      };

      await store.logout();

      expect(clearTokens).toHaveBeenCalled();
      expect(store.accessToken).toBeNull();
      expect(store.developer).toBeNull();
    });

    it('登出请求失败时不阻塞 clearTokens', async () => {
      vi.mocked(request).mockRejectedValueOnce(new Error('network error'));
      localStorage.setItem('xcj_refresh_token', 'refresh-1');

      const store = useAuthStore();
      store.accessToken = 'access-1';

      await store.logout();

      expect(clearTokens).toHaveBeenCalled();
      expect(store.accessToken).toBeNull();
    });
  });

  describe('handleError', () => {
    it('转调 extractApiError 返回 message', () => {
      const store = useAuthStore();
      const msg = store.handleError(new Error('测试错误'));
      expect(msg).toBe('测试错误');
    });
  });

  describe('loadProfile', () => {
    it('加载 profile 并填充 developer', async () => {
      vi.mocked(request).mockResolvedValueOnce({
        id: 'd1',
        email: 'a@b.c',
        role: 'USER',
        createdAt: '2026-01-01',
        maxApps: 5,
        totpEnabled: false,
      });

      const store = useAuthStore();
      await store.loadProfile();

      expect(store.developer).not.toBeNull();
      expect(store.developer?.id).toBe('d1');
      expect(store.developer?.email).toBe('a@b.c');
      expect(store.developer?.vipLevel).toBe('free'); // 占位
    });
  });
});
