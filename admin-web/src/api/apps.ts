import { request } from './client';

export interface AppItem {
  id: string;
  name: string;
  packageName: string;
  appSecretPrefix: string;
  rateLimitIpPerMinute: number | null;
  rateLimitDevicePerMinute: number | null;
  offlineCacheDays: number;
  createdAt: string;
  updatedAt: string;
}

export interface AppDetail extends AppItem {
  signHashAllowList: string[];
  rateLimitFailLockThreshold: number | null;
  rateLimitFailLockTtl: number | null;
  sdkRsaPublicKeyHash: string | null;
}

export interface CreateAppDto {
  name: string;
  packageName: string;
}

export interface UpdateAppDto {
  name?: string;
  rateLimitIpPerMinute?: number | null;
  rateLimitDevicePerMinute?: number | null;
  rateLimitFailLockThreshold?: number | null;
  rateLimitFailLockTtl?: number | null;
  offlineCacheDays?: number;
  signHashAllowList?: string[];
}

export interface CreateAppResult extends AppDetail {
  appSecret: string;
}

export const appsApi = {
  list: () => request<AppItem[]>({ method: 'GET', url: '/apps' }),

  getById: (id: string) => request<AppDetail>({ method: 'GET', url: `/apps/${id}` }),

  create: (dto: CreateAppDto) =>
    request<CreateAppResult>({ method: 'POST', url: '/apps', data: dto }),

  update: (id: string, dto: UpdateAppDto) =>
    request<AppDetail>({ method: 'PATCH', url: `/apps/${id}`, data: dto }),

  delete: (id: string) =>
    request<{ success: boolean }>({ method: 'DELETE', url: `/apps/${id}` }),

  rotateSecret: (id: string) =>
    request<{ appSecret: string; appSecretPrefix: string }>({
      method: 'POST',
      url: `/apps/${id}/rotate-secret`,
    }),
};
