import { request } from './client';

/**
 * 自有 APK 诊断 API(ADR 0077)
 *
 * 端点:
 *  - POST /v1/audit/analyze  上传 APK + 诊断(只读)
 *  - POST /v1/audit/resign   签名回填(例外 A)
 *  - GET  /v1/audit/logs     诊断历史
 */

export interface AuditLogOwnItem {
  id: string;
  developerId: string;
  appId: string;
  apkHash: string;
  apkSize: number;
  packageName: string;
  signatureHash: string;
  check1Passed: boolean;
  check2Passed: boolean;
  check3Passed: boolean;
  status: 'SUCCESS' | 'REJECTED' | 'FAILED' | 'RESIGN';
  rejectReason: string | null;
  reportPath: string | null;
  operation: 'ANALYZE' | 'RESIGN';
  resignFromHash: string | null;
  resignToHash: string | null;
  keystoreFingerprint: string | null;
  ip: string;
  userAgent: string | null;
  createdAt: string;
}

export interface AnalyzeReport {
  taskId: string;
  timestamp: string;
  apkInfo: {
    packageName: string;
    apkHash: string;
    apkSize: number;
    signatureHash: string;
  };
  manifest: {
    permissions: string[];
  };
  securityFindings: {
    cleartextTraffic: boolean | null;
    debuggable: boolean | null;
    backupEnabled: boolean | null;
  };
  note?: string;
}

export interface AnalyzeResponse {
  taskId: string;
  report: AnalyzeReport;
}

export interface ResignResponse {
  taskId: string;
  oldHash: string;
  newHash: string;
  resignedApkBase64: string;
  resignedApkSize: number;
}

export interface WatermarkTraceResponse {
  found: boolean;
  watermark?: {
    version: string;
    watermarkId: string;
    timestamp: number;
    nonce: string;
  };
  extractedAt: string;
}

export const auditApi = {
  /**
   * 上传 APK 做只读诊断
   * @param apkFile APK 文件
   */
  analyze: (apkFile: File) => {
    const formData = new FormData();
    formData.append('apk', apkFile);
    formData.append('originalName', apkFile.name);
    return request<AnalyzeResponse>({
      method: 'POST',
      url: '/audit/analyze',
      data: formData,
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 600000, // 10 分钟(诊断可能慢)
    });
  },

  /**
   * 签名回填(例外 A)
   * @param apkFile APK 文件
   * @param keystoreFile keystore 文件(.jks/.keystore)
   * @param credentials keystore 密码 + key alias + key 密码
   */
  resign: (
    apkFile: File,
    keystoreFile: File,
    credentials: {
      keystorePassword: string;
      keyAlias: string;
      keyPassword: string;
    },
  ) => {
    const formData = new FormData();
    formData.append('apk', apkFile);
    formData.append('keystore', keystoreFile);
    formData.append('keystorePassword', credentials.keystorePassword);
    formData.append('keyAlias', credentials.keyAlias);
    formData.append('keyPassword', credentials.keyPassword);
    formData.append('originalName', apkFile.name);
    return request<ResignResponse>({
      method: 'POST',
      url: '/audit/resign',
      data: formData,
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 300000, // 5 分钟
    });
  },

  /**
   * 查询诊断历史
   */
  listLogs: (params: { limit?: number; offset?: number } = {}) => {
    const hasParams = Object.keys(params).length > 0;
    return request<AuditLogOwnItem[]>({
      method: 'GET',
      url: '/audit/logs',
      params: hasParams ? params : undefined,
    });
  },

  /**
   * 导出诊断历史为 CSV(合规审计用)
   * @returns { csv, filename }
   */
  exportLogsCsv: (limit?: number) => {
    return request<{ csv: string; filename: string }>({
      method: 'GET',
      url: '/audit/logs/export',
      params: limit ? { limit } : undefined,
    });
  },

  /**
   * 水印追溯(ADMIN only,ADR 0030 §c 追溯闭环)
   * @param apkFile 含 META-INF/xcj-watermark.enc.txt 的 APK
   */
  traceWatermark: (apkFile: File) => {
    const formData = new FormData();
    formData.append('apk', apkFile);
    return request<WatermarkTraceResponse>({
      method: 'POST',
      url: '/watermark/trace',
      data: formData,
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 60000,
    });
  },
};
