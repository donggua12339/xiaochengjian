import { request, longTimeoutClient } from './client';

/** APK 分析结果 */
export interface ApkAnalysis {
  packageName: string;
  originalApplicationName: string | null;
  dexFiles: string[];
  isMultidex: boolean;
  nativeAbis: string[];
  alreadyHardened: boolean;
  detectedHardener: string | null;
  minSdkVersion: number;
  targetSdkVersion: number;
  apkSize: number;
  recommendedConfig: HardeningRequestConfig;
  unavailableFeatures: Array<{ feature: string; reason: string }>;
}

/** 加固请求配置 */
export interface HardeningRequestConfig {
  productLine: 'xuanjia' | 'tianyan';
  preset?: 'basic' | 'standard' | 'aggressive' | 'paranoid';
  xuanjia?: Record<string, boolean>;
  tianyan?: Record<string, boolean>;
  killPolicy?: {
    strongEvidence: 'kill' | 'warn' | 'none';
    weakScoreThreshold: number;
    delayMinMs: number;
    delayMaxMs: number;
  };
}

/** 加固任务状态 */
export interface HardeningTaskStatus {
  id: string;
  status: 'analyzing' | 'hardening' | 'signing' | 'completed' | 'failed';
  progress: number;
  message: string;
}

/** 上传 APK 分析(长超时 + 自动 Content-Type) */
export async function analyzeApk(apkFile: File) {
  const formData = new FormData();
  formData.append('apk', apkFile);
  const res = await longTimeoutClient.post('/hardening/analyze', formData, {
    headers: { 'Content-Type': undefined as any },  // 让 axios 自动生成 boundary
  });
  return res.data as { taskId: string; analysis: ApkAnalysis; _tmpApkPath: string };
}

/** 执行加固 */
export function hardenApk(params: {
  apkFile: File;
  keystoreFile?: File;
  keystorePassword: string;
  keyAlias: string;
  keyPassword: string;
  config: HardeningRequestConfig;
  analysis: ApkAnalysis;
  ownershipConfirmed: boolean; // ADR 0097
}) {
  const formData = new FormData();
  formData.append('apk', params.apkFile);
  if (params.keystoreFile) {
    formData.append('keystore', params.keystoreFile);
  }
  formData.append('keystorePassword', params.keystorePassword);
  formData.append('keyAlias', params.keyAlias);
  formData.append('keyPassword', params.keyPassword);
  formData.append('config', JSON.stringify(params.config));
  formData.append('analysisJson', JSON.stringify(params.analysis));
  formData.append('ownershipConfirmed', params.ownershipConfirmed ? 'true' : 'false');

  const res = await longTimeoutClient.post('/hardening/harden', formData, {
    headers: { 'Content-Type': undefined as any },
  });
  return res.data as { taskId: string; status: string; message: string };
}

/** 查询加固状态 */
export function getHardeningStatus(taskId: string) {
  return request<HardeningTaskStatus>({
    method: 'GET',
    url: `/hardening/status/${taskId}`,
  });
}

/** 下载加固后的 APK(返回 blob URL) */
export function downloadHardenedApk(taskId: string): string {
  const baseURL = (import.meta.env.VITE_API_BASE_URL as string) || '/api/v1';
  const token = localStorage.getItem('access_token') || '';
  return `${baseURL}/hardening/download/${taskId}?token=${encodeURIComponent(token)}`;
}
