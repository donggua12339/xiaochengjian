import { request } from './client';

/**
 * Packer API(ADR 0081)
 *
 * 端点:
 *  - POST /v1/packer/pack   自有 APK SDK 封装(七锁校验)
 *  - GET  /v1/packer/logs   封装历史
 */

export interface PackerLogItem {
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
  check4Passed: boolean;
  check5Passed: boolean;
  check6Passed: boolean;
  check7Passed: boolean;
  status: 'SUCCESS' | 'REJECTED' | 'FAILED';
  rejectReason: string | null;
  dexInjected: boolean;
  multidexHandled: boolean;
  injectedDexHash: string | null;
  resignedApkHash: string | null;
  keystoreFingerprint: string | null;
  ip: string;
  userAgent: string | null;
  createdAt: string;
}

export interface PackResponse {
  taskId: string;
  packedApkHash: string;
  injectedDexHash: string;
  injectedDefenderDexHash: string | null;
  injectedSoHash: string | null;
  defenderSoName: string | null;
  keystoreFingerprint: string;
  packedApkBase64: string;
  packedApkSize: number;
}

/**
 * defender 模块配置(单个模块)
 *
 * 与 backend DefenderModuleConfigInput 对齐
 */
export interface DefenderModuleConfig {
  enabled: boolean;
  onViolation: 'kill' | 'warn' | 'none';
}

/**
 * defender 完整配置(ADR 0088)
 *
 * 与 backend DefenderConfigInput 对齐,缺失字段用 SDK 默认值
 */
export interface DefenderConfig {
  appId: string;
  serverUrl: string;
  signatureVerify?: DefenderModuleConfig;
  antiDebug?: DefenderModuleConfig;
  antiFrida?: DefenderModuleConfig;
  antiDump?: DefenderModuleConfig;
  rootDetect?: DefenderModuleConfig;
  xposedDetect?: DefenderModuleConfig & { killThreshold?: number };
  emulatorDetect?: DefenderModuleConfig;
  integrityCheck?: DefenderModuleConfig;
  secureScreen?: { enabled: boolean; excludeActivities?: string[] };
  onViolationKill?: {
    delayMinMs?: number;
    delayMaxMs?: number;
    method?: 'sigabrt' | 'exit';
    showToast?: boolean;
    toastMessage?: string;
  };
  report?: { enabled?: boolean; throttleMs?: number };
}

export const packerApi = {
  /**
   * 执行封装(七锁校验)
   * @param apkFile 自有 APK
   * @param keystoreFile 自备 Keystore
   * @param xcjAuthSdkDexFile classes-xcj.dex(xcj-auth-sdk 编译产物)
   * @param credentials Keystore 凭证
   * @param sdkConfig SDK 配置(appId/serverUrl 等)
   * @param defenderEnabled 是否启用 defender-sdk 注入(ADR 0088)
   * @param defenderConfig defender 模块配置(defenderEnabled=true 时必填)
   */
  pack: (
    apkFile: File,
    keystoreFile: File,
    xcjAuthSdkDexFile: File,
    credentials: {
      keystorePassword: string;
      keyAlias: string;
      keyPassword: string;
    },
    sdkConfig: Record<string, unknown>,
    defenderEnabled: boolean,
    defenderConfig: DefenderConfig,
  ) => {
    const formData = new FormData();
    formData.append('apk', apkFile);
    formData.append('keystore', keystoreFile);
    formData.append('xcjAuthSdkDex', xcjAuthSdkDexFile);
    formData.append('keystorePassword', credentials.keystorePassword);
    formData.append('keyAlias', credentials.keyAlias);
    formData.append('keyPassword', credentials.keyPassword);
    formData.append('sdkConfig', JSON.stringify(sdkConfig));
    formData.append('originalName', apkFile.name);
    formData.append('defenderEnabled', defenderEnabled ? 'true' : 'false');
    if (defenderEnabled) {
      formData.append('defenderConfig', JSON.stringify(defenderConfig));
    }
    return request<PackResponse>({
      method: 'POST',
      url: '/packer/pack',
      data: formData,
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 300000,
    });
  },

  /**
   * 查询封装历史
   */
  listLogs: (params: { limit?: number; offset?: number } = {}) => {
    return request<PackerLogItem[]>({
      method: 'GET',
      url: '/packer/logs',
      params,
    });
  },
};
