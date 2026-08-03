import { request } from './client';

export interface HardenConfig {
  appId: string;
  encryptStrings: boolean;
  vmpProtect: boolean;
  segmentStrings: boolean;
  soEncrypt: boolean;
  detectionModules: Record<string, boolean>;
  killAction: string;
  weakThreshold: number;
  delayMinMs: number;
  delayMaxMs: number;
  strength: string;
}

export interface QualityReportItem {
  id: string;
  appId: string;
  overallScore: number;
  grade: string;
  dimensions: Record<string, { score: number; maxScore: number; details?: string[] }>;
  createdAt: string;
}

export function getHardenConfig(appId: string) {
  return request<HardenConfig>({ method: 'GET', url: `/apps/${appId}/harden/config` });
}

export function saveHardenConfig(appId: string, config: Partial<HardenConfig>) {
  return request<HardenConfig>({
    method: 'PUT',
    url: `/apps/${appId}/harden/config`,
    data: config,
  });
}

export function submitQualityReport(
  appId: string,
  report: {
    overallScore: number;
    grade: string;
    dimensions: unknown;
    raw: unknown;
  },
) {
  return request<QualityReportItem>({
    method: 'POST',
    url: `/apps/${appId}/harden/report`,
    data: report,
  });
}

export function getQualityReports(appId: string, limit = 10) {
  return request<QualityReportItem[]>({
    method: 'GET',
    url: `/apps/${appId}/harden/reports`,
    params: { limit },
  });
}
