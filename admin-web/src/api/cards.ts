import { request } from './client';
import type { CardKeyType, BindingStrategy } from './types';

export interface CardKeyItem {
  id: string;
  type: CardKeyType;
  bindingStrategy: BindingStrategy;
  maxDevices: number;
  status: string;
  cardKeyPrefix: string;
  remark: string | null;
  batchId: string;
  activatedAt: string | null;
  expiresAt: string | null;
  boundDevicesCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface CardKeyListResult {
  items: CardKeyItem[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

export interface GenerateCardsDto {
  type: CardKeyType;
  bindingStrategy: BindingStrategy;
  maxDevices?: number;
  count: number;
  remark?: string;
}

export interface GenerateCardsResult {
  batchId: string;
  cardKeys: string[];
  count: number;
}

export const cardsApi = {
  list: (appId: string, params: {
    page?: number;
    pageSize?: number;
    type?: CardKeyType;
    status?: string;
    batchId?: string;
  }) =>
    request<CardKeyListResult>({
      method: 'GET',
      url: `/apps/${appId}/cards`,
      params,
    }),

  getById: (appId: string, cardId: string) =>
    request<CardKeyItem & { boundDevices: { id: string; machineId: string; boundAt: string }[] }>({
      method: 'GET',
      url: `/apps/${appId}/cards/${cardId}`,
    }),

  generate: (appId: string, dto: GenerateCardsDto) =>
    request<GenerateCardsResult>({
      method: 'POST',
      url: `/apps/${appId}/cards/generate`,
      data: dto,
    }),

  disable: (appId: string, cardId: string) =>
    request<CardKeyItem>({ method: 'POST', url: `/apps/${appId}/cards/${cardId}/disable` }),

  enable: (appId: string, cardId: string) =>
    request<CardKeyItem>({ method: 'POST', url: `/apps/${appId}/cards/${cardId}/enable` }),

  unbind: (appId: string, cardId: string, deviceId: string) =>
    request<{ success: boolean }>({
      method: 'POST',
      url: `/apps/${appId}/cards/${cardId}/unbind`,
      data: { deviceId },
    }),
};
