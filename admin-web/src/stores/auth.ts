import { defineStore } from 'pinia';
import { request, setTokens, clearTokens, getAccessToken, extractApiError } from '@/api/client';

interface Developer {
  id: string;
  email: string;
  role: string;
  vipLevel: string;
  totpEnabled: boolean;
  maxApps: number;
  createdAt: string;
}

interface LoginResult {
  requiresTotp: boolean;
  pendingTotpToken?: string;
  developerId?: string;
  accessToken?: string;
  refreshToken?: string;
}

export const useAuthStore = defineStore('auth', {
  state: () => ({
    developer: null as Developer | null,
    accessToken: getAccessToken(),
  }),

  getters: {
    isLoggedIn: (state) => !!state.accessToken,
    needs2FA: (state) => state.developer?.totpEnabled ?? false,
  },

  actions: {
    async register(email: string, password: string) {
      return request<{ developerId: string; email: string }>({
        method: 'POST',
        url: '/auth/register',
        data: { email, password },
      });
    },

    async login(email: string, password: string): Promise<LoginResult> {
      const result = await request<LoginResult>({
        method: 'POST',
        url: '/auth/login',
        data: { email, password },
      });
      if (!result.requiresTotp && result.accessToken && result.refreshToken) {
        setTokens(result.accessToken, result.refreshToken);
        this.accessToken = result.accessToken;
      }
      return result;
    },

    async verifyTotpLogin(pendingTotpToken: string, code: string) {
      const result = await request<{ accessToken: string; refreshToken: string }>({
        method: 'POST',
        url: '/auth/2fa/login',
        data: { pendingTotpToken, code },
      });
      setTokens(result.accessToken, result.refreshToken);
      this.accessToken = result.accessToken;
    },

    async verifyBackupLogin(pendingTotpToken: string, backupCode: string) {
      const result = await request<{ accessToken: string; refreshToken: string }>({
        method: 'POST',
        url: '/auth/2fa/backup',
        data: { pendingTotpToken, backupCode },
      });
      setTokens(result.accessToken, result.refreshToken);
      this.accessToken = result.accessToken;
    },

    async logout() {
      const refreshToken = localStorage.getItem('xcj_refresh_token');
      if (refreshToken) {
        try {
          await request({ method: 'POST', url: '/auth/logout', data: { refreshToken } });
        } catch {
          // 忽略登出失败
        }
      }
      clearTokens();
      this.accessToken = null;
      this.developer = null;
    },

    async setupTotp() {
      return request<{ secret: string; otpauthUrl: string }>({
        method: 'POST',
        url: '/auth/2fa/setup',
      });
    },

    async verifyTotpSetup(code: string) {
      return request<{ backupCodes: string[] }>({
        method: 'POST',
        url: '/auth/2fa/verify',
        data: { code },
      });
    },

    async changePassword(currentPassword: string, newPassword: string) {
      return request<{ success: true }>({
        method: 'POST',
        url: '/auth/change-password',
        data: { currentPassword, newPassword },
      });
    },

    async loadProfile() {
      const profile = await request<{
        id: string;
        email: string;
        role: string;
        createdAt: string;
        maxApps: number;
        totpEnabled: boolean;
      }>({
        method: 'GET',
        url: '/auth/profile',
      });
      // 补齐 store 中 Developer 接口未覆盖的字段(会员层未实现,占位)
      this.developer = {
        id: profile.id,
        email: profile.email,
        role: profile.role,
        vipLevel: 'free',
        totpEnabled: profile.totpEnabled,
        maxApps: profile.maxApps,
        createdAt: profile.createdAt,
      };
      return profile;
    },

    handleError(error: unknown): string {
      const apiError = extractApiError(error);
      return apiError.message;
    },
  },
});
