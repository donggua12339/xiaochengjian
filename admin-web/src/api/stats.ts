import { request } from './client';

/**
 * 应用概览统计
 * 对应后端 GET /apps/:appId/stats/overview
 */
export interface AppOverviewStats {
  cards: {
    total: number;
    byStatus: Record<string, number>;
    byType: Record<string, number>;
    activated: number;
  };
  devices: {
    total: number;
    active30d: number;
  };
  validations: {
    today: number;
    todaySuccess: number;
    todayFailRate: number;
  };
}

export function getAppOverviewStats(appId: string) {
  return request<AppOverviewStats>({
    method: 'GET',
    url: `/apps/${appId}/stats/overview`,
  });
}
