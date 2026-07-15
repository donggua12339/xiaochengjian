import { longTimeoutClient } from './client';

export interface InjectResult {
  downloadToken: string;
  originalSize: number;
  injectedSize: number;
  watermarkId: string;
}

export const injectApi = {
  /**
   * 上传 APK + keystore 执行注入
   * keystore 可选(不传则用系统默认 keystore)
   */
  inject: (files: { apk: File; keystore: File | null }, params: {
    ksPass?: string;
    ksKeyAlias?: string;
    keyPass?: string;
    watermarkId: string;
  }) => {
    const formData = new FormData();
    formData.append('apk', files.apk);
    if (files.keystore) {
      formData.append('keystore', files.keystore);
      formData.append('ksPass', params.ksPass ?? '');
      formData.append('ksKeyAlias', params.ksKeyAlias ?? '');
      formData.append('keyPass', params.keyPass ?? '');
    }
    formData.append('watermarkId', params.watermarkId);

    return longTimeoutClient.post<InjectResult>('/admin/inject', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    }).then((res) => res.data);
  },

  /**
   * 下载注入后的 APK(返回 URL,浏览器直接打开)
   */
  getDownloadUrl: (token: string) => {
    const accessToken = localStorage.getItem('xcj_access_token') ?? '';
    return `${import.meta.env.VITE_API_BASE ?? '/v1'}/admin/inject/download?token=${token}&_auth=${encodeURIComponent(accessToken)}`;
  },
};
