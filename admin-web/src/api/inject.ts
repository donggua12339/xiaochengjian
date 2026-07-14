import { request } from './client';

export interface InjectResult {
  downloadToken: string;
  originalSize: number;
  injectedSize: number;
  watermarkId: string;
}

export const injectApi = {
  /**
   * 上传 APK + keystore 执行注入
   */
  inject: (files: { apk: File; keystore: File }, params: {
    ksPass: string;
    ksKeyAlias: string;
    keyPass: string;
    watermarkId: string;
  }) => {
    const formData = new FormData();
    formData.append('apk', files.apk);
    formData.append('keystore', files.keystore);
    formData.append('ksPass', params.ksPass);
    formData.append('ksKeyAlias', params.ksKeyAlias);
    formData.append('keyPass', params.keyPass);
    formData.append('watermarkId', params.watermarkId);

    return request<InjectResult>({
      method: 'POST',
      url: '/admin/inject',
      data: formData,
      headers: { 'Content-Type': 'multipart/form-data' },
    });
  },

  /**
   * 下载注入后的 APK(返回 URL,浏览器直接打开)
   */
  getDownloadUrl: (token: string) => {
    const accessToken = localStorage.getItem('xcj_access_token') ?? '';
    return `${import.meta.env.VITE_API_BASE ?? '/v1'}/admin/inject/download?token=${token}&_auth=${encodeURIComponent(accessToken)}`;
  },
};
