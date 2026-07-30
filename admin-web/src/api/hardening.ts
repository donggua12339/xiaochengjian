import { request, longTimeoutClient } from './client';
import type { AxiosProgressEvent } from 'axios';

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

/** 上传结果 */
export interface UploadResult {
  fileId: string;
  fileName: string;
  fileSize: number;
}

/**
 * Step 0: 上传 APK 文件(带上传进度回调)
 * 文件只上传一次,返回 fileId 供后续 analyze/harden 引用。
 */
export async function uploadApk(
  apkFile: File,
  onProgress?: (percent: number) => void,
): Promise<UploadResult> {
  const formData = new FormData();
  formData.append('apk', apkFile);

  const res = await longTimeoutClient.post('/hardening/upload', formData, {
    onUploadProgress: (event: AxiosProgressEvent) => {
      if (onProgress && event.total) {
        onProgress(Math.round((event.loaded / event.total) * 100));
      }
    },
  });
  return res as unknown as UploadResult;
}

/**
 * Step 1: 传 fileId 启动异步分析
 */
export async function analyzeApk(fileId: string): Promise<{ taskId: string }> {
  const res = await longTimeoutClient.post('/hardening/analyze', { fileId });
  return res as unknown as { taskId: string };
}

/** 轮询任务状态 */
export async function getHardeningStatus(taskId: string): Promise<HardeningTaskStatus> {
  const res = await request<HardeningTaskStatus>({
    method: 'GET',
    url: `/hardening/status/${taskId}`,
  });
  return res;
}

/** 获取当前用户的所有加固任务 */
export async function getHardeningTasks(): Promise<{ tasks: HardeningTaskSummary[] }> {
  const res = await request<{ tasks: HardeningTaskSummary[] }>({
    method: 'GET',
    url: '/hardening/tasks',
  });
  return res;
}

/**
 * Step 3: 传 fileId + keystore 执行加固
 * APK 不再重新上传,通过 fileId 引用。
 * Keystore 通过 multipart 内存传输(不落盘)。
 */
export async function hardenApk(params: {
  fileId: string;
  keystoreFile: File;
  keystorePassword: string;
  keyAlias: string;
  keyPassword: string;
  config: HardeningRequestConfig;
  analysis: ApkAnalysis;
  ownershipConfirmed: boolean;
}): Promise<{ taskId: string; status: string; message: string }> {
  const formData = new FormData();
  formData.append('fileId', params.fileId);
  formData.append('keystore', params.keystoreFile);
  formData.append('keystorePassword', params.keystorePassword);
  formData.append('keyAlias', params.keyAlias);
  formData.append('keyPassword', params.keyPassword);
  formData.append('config', JSON.stringify(params.config));
  formData.append('analysisJson', JSON.stringify(params.analysis));
  formData.append('ownershipConfirmed', params.ownershipConfirmed ? 'true' : 'false');

  const res = await longTimeoutClient.post('/hardening/harden', formData);
  return res as unknown as { taskId: string; status: string; message: string };
}

/** 下载加固后的 APK(axios blob 下载,带 JWT) */
export async function downloadHardenedApk(taskId: string): Promise<void> {
  const res = await longTimeoutClient.get(`/hardening/download/${taskId}`, {
    responseType: 'blob',
  });
  const blob = res instanceof Blob ? res : new Blob([res as unknown as BlobPart]);
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `hardened_${taskId.slice(0, 8)}.apk`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
