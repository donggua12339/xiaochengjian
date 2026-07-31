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
  status: 'queued' | 'analyzing' | 'hardening' | 'signing' | 'completed' | 'failed' | 'cancelled';
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

/** 取消任务(Bug E) */
export async function cancelHardeningTask(taskId: string): Promise<{ cancelled: boolean }> {
  const res = await request<{ cancelled: boolean }>({
    method: 'DELETE',
    url: `/hardening/tasks/${taskId}`,
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

// ========== 分片上传 ==========

export const CHUNK_SIZE = 5 * 1024 * 1024; // 5MB
export const MAX_FILE_SIZE = 1024 * 1024 * 1024; // 1GB
const MAX_CONCURRENT = 3;
const MAX_RETRIES = 3;

/** 分片上传 init */
export async function uploadInit(
  fileName: string,
  fileSize: number,
  totalChunks: number,
): Promise<{ uploadId: string; chunkSize: number }> {
  const res = await longTimeoutClient.post('/hardening/upload/init', {
    fileName,
    fileSize,
    totalChunks,
  });
  return res as unknown as { uploadId: string; chunkSize: number };
}

/** 上传单个分片 */
async function uploadSingleChunk(
  uploadId: string,
  chunkIndex: number,
  chunk: Blob,
  onChunkProgress?: (chunkIndex: number, percent: number) => void,
): Promise<void> {
  const formData = new FormData();
  formData.append('uploadId', uploadId);
  formData.append('chunkIndex', String(chunkIndex));
  formData.append('chunk', chunk, `chunk_${chunkIndex}`);

  await longTimeoutClient.post('/hardening/upload/chunk', formData, {
    onUploadProgress: (event: AxiosProgressEvent) => {
      if (onChunkProgress && event.total) {
        onChunkProgress(chunkIndex, Math.round((event.loaded / event.total) * 100));
      }
    },
  });
}

/** 完成分片上传 → 拼接 → 返回 fileId 或 missing 列表 */
export async function uploadComplete(
  uploadId: string,
): Promise<UploadResult | { missing: number[] }> {
  const res = await longTimeoutClient.post('/hardening/upload/complete', { uploadId });
  return res as unknown as UploadResult | { missing: number[] };
}

/**
 * 分片上传编排器
 *
 * 滑动窗口 3 并发 + 自动重试 3 次 + 进度回调
 */
export async function chunkedUpload(
  file: File,
  onProgress: (percent: number) => void,
  signal?: AbortSignal,
): Promise<UploadResult> {
  const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

  // Step 1: init
  const { uploadId } = await uploadInit(file.name, file.size, totalChunks);

  // 断点续传: 从 sessionStorage 恢复
  const ssKey = `xcj_upload_${uploadId}`;
  let completedSet = new Set<number>();
  try {
    const saved = sessionStorage.getItem(ssKey);
    if (saved) completedSet = new Set(JSON.parse(saved) as number[]);
  } catch { /* ignore */ }

  // 每片当前进度(用于精确总进度计算)
  const chunkProgress = new Map<number, number>();
  let completedCount = completedSet.size;

  function computeTotalProgress(): number {
    let loaded = completedCount * CHUNK_SIZE;
    for (const [, pct] of chunkProgress) {
      loaded += (pct / 100) * CHUNK_SIZE;
    }
    return Math.min(100, Math.round((loaded / file.size) * 100));
  }

  // 上传单片(带重试)——提取到外层,Step 2 和 Step 3 补传共用
  async function uploadWithRetry(idx: number, attempt: number): Promise<void> {
    if (signal?.aborted) throw new Error('上传已取消');
    const start = idx * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, file.size);
    const chunk = file.slice(start, end);
    try {
      await uploadSingleChunk(uploadId, idx, chunk, (ci, pct) => {
        chunkProgress.set(ci, pct);
        onProgress(computeTotalProgress());
      });
    } catch (err) {
      if (attempt < MAX_RETRIES - 1) {
        await new Promise((r) => setTimeout(r, 1000 * Math.pow(2, attempt)));
        return uploadWithRetry(idx, attempt + 1);
      }
      throw err;
    }
  }

  // Step 2: 滑动窗口上传
  const queue: number[] = [];
  for (let i = 0; i < totalChunks; i++) {
    if (!completedSet.has(i)) queue.push(i);
  }

  let inFlight = 0;
  let queueIdx = 0;

  await new Promise<void>((resolve, reject) => {
    if (signal?.aborted) { reject(new Error('上传已取消')); return; }

    function tryNext() {
      if (signal?.aborted) { reject(new Error('上传已取消')); return; }

      while (inFlight < MAX_CONCURRENT && queueIdx < queue.length) {
        const chunkIdx = queue[queueIdx++];
        inFlight++;

        uploadWithRetry(chunkIdx, 0)
          .then(() => {
            completedSet.add(chunkIdx);
            completedCount++;
            chunkProgress.delete(chunkIdx);
            onProgress(computeTotalProgress());
            try { sessionStorage.setItem(ssKey, JSON.stringify([...completedSet])); } catch { /* ignore */ }
            inFlight--;
            if (completedCount === totalChunks) { resolve(); return; }
            tryNext();
          })
          .catch((err) => {
            inFlight--;
            reject(err);
          });
      }
    }

    if (queue.length === 0) { resolve(); return; }
    tryNext();
  });

  // 清理 sessionStorage
  try { sessionStorage.removeItem(ssKey); } catch { /* ignore */ }

  // Step 3: complete(含缺片补传重试)
  onProgress(99);
  const MAX_COMPLETE_RETRIES = 3;
  for (let attempt = 0; attempt < MAX_COMPLETE_RETRIES; attempt++) {
    const result = await uploadComplete(uploadId);

    if ('fileId' in result) {
      onProgress(100);
      return result as UploadResult;
    }

    // 后端返回缺片列表 → 补传后重试 complete
    const missing = (result as { missing: number[] }).missing;
    if (missing && missing.length > 0) {
      for (const chunkIdx of missing) {
        await uploadWithRetry(chunkIdx, 0);
      }
      continue; // 补传完,重试 complete
    }

    throw new Error('uploadComplete 返回格式异常');
  }

  throw new Error(`分片拼接失败: 重试 ${MAX_COMPLETE_RETRIES} 次仍有缺片`);
}
