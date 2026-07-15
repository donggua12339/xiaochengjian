import axios, { type AxiosInstance, type AxiosRequestConfig } from 'axios';

/**
 * API 客户端
 * 统一处理:
 *  - baseURL(/v1 前缀)
  *  - JWT 自动注入 Authorization header
 *  - 401 自动跳登录 + 清 token
 *  - 错误响应统一解包(code/message/requestId/timestamp)
 */

export interface ApiError {
  code: string;
  message: string;
  requestId?: string;
  timestamp?: string;
}

export interface ApiResult<T = unknown> {
  data: T;
}

const ACCESS_TOKEN_KEY = 'xcj_access_token';
const REFRESH_TOKEN_KEY = 'xcj_refresh_token';

export function getAccessToken(): string | null {
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getRefreshToken(): string | null {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setTokens(accessToken: string, refreshToken: string): void {
  localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
  localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
}

export function clearTokens(): void {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
}

const client: AxiosInstance = axios.create({
  baseURL: '/v1',
  timeout: 15000,
  headers: { 'Content-Type': 'application/json' },
});

/**
 * 长超时客户端(注入等耗时操作,3 分钟)
 */
export const longTimeoutClient: AxiosInstance = axios.create({
  baseURL: '/v1',
  timeout: 180000,
  headers: { 'Content-Type': 'application/json' },
});

longTimeoutClient.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// 请求拦截:注入 JWT
client.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// 响应拦截:解包 + 401 处理
client.interceptors.response.use(
  (response) => response.data,
  async (error) => {
    if (error.response?.status === 401) {
      // 尝试 refresh
      const refreshToken = getRefreshToken();
      if (refreshToken && !error.config._retried) {
        error.config._retried = true;
        try {
          const res = await axios.post('/v1/auth/refresh', { refreshToken });
          const { accessToken, refreshToken: newRefresh } = res.data;
          setTokens(accessToken, newRefresh);
          error.config.headers.Authorization = `Bearer ${accessToken}`;
          return client(error.config);
        } catch {
          clearTokens();
          window.location.href = '/login';
          return Promise.reject(error);
        }
      } else {
        clearTokens();
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  },
);

export default client;

/**
 * 通用请求函数(带类型)
 */
export async function request<T = unknown>(config: AxiosRequestConfig): Promise<T> {
  return client(config) as unknown as Promise<T>;
}

/**
 * 从 axios 错误提取 ApiError
 */
export function extractApiError(error: unknown): ApiError {
  if (axios.isAxiosError(error)) {
    const data = error.response?.data as ApiError | undefined;
    return {
      code: data?.code ?? 'UNKNOWN',
      message: data?.message ?? error.message ?? '网络错误',
      requestId: data?.requestId,
      timestamp: data?.timestamp,
    };
  }
  return { code: 'UNKNOWN', message: (error as Error)?.message ?? '未知错误' };
}
