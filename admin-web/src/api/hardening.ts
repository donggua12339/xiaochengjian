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

/** 任务状态(后端返回) */
export interface HardeningTaskStatus {
  id: string;
  status: 'queued' | 'analyzing' | 'hardening' | 'signing' | 'completed' | 'failed';
  progress: number;
  message: string;
  step: string;
  detail: string;
  analysis?: ApkAnalysis | null;
  error?: string;
  createdAt: string;
  updatedAt: string;
}

/** 任务列表项(精简) */
export interface HardeningTaskSummary {
  id: string;
  status: string;
  progress: number;
  message: string;
  step: string;
  detail: string;
  apkFileName?: string;
  analysis?: { packageName: string; nativeAbis: string[]; dexFiles: string[] } | null;
  createdAt: string;
  updatedAt: string;
}

/** 上传 APK 开始异步分析(立即返回 taskId) */
export async function analyzeApk(apkFile: File) {
  const formData = new FormData();
  formData.append('apk', apkFile);
  const res = await longTimeoutClient.post('/hardening/analyze', formData);
  return res.data as { taskId: string };
}

/** 轮询任务状态 */
export async function getHardeningStatus(taskId: string) {
  const res = await request<HardeningTaskStatus>({
    method: 'GET',
    url: `/hardening/status/${taskId}`,
  });
  return res;
}

/** 获取当前用户的所有加固任务 */
export async function getHardeningTasks() {
  const res = await request<{ tasks: HardeningTaskSummary[] }>({
    method: 'GET',
    url: '/hardening/tasks',
  });
  return res;
}

/** 执行加固(异步,返回 taskId) */
export async function hardenApk(params: {
  apkFile: File;
  keystoreFile?: File;
  keystorePassword: string;
  keyAlias: string;
  keyPassword: string;
  config: HardeningRequestConfig;
  analysis: ApkAnalysis;
  ownershipConfirmed: boolean;
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

  const res = await longTimeoutClient.post('/hardening/harden', formData);
  return res.data as { taskId: string; status: string; message: string };
}

/** 下载加固后的 APK */
export function downloadHardenedApk(taskId: string): string {
  const baseURL = (import.meta.env.VITE_API_BASE_URL as string) || '/api/v1';
  const token = localStorage.getItem('xcj_access_token') || '';
  return `${baseURL}/hardening/download/${taskId}?token=${encodeURIComponent(token)}`;
}
