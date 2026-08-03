/**
 * audit API 单元测试
 *
 * 覆盖:
 *  - analyze: 构造 FormData + multipart header
 *  - resign: 构造 FormData(apk + keystore + 凭证)
 *  - listLogs: GET + params
 *  - exportLogsCsv: GET + 可选 limit
 *  - traceWatermark: 构造 FormData
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// mock client 的 request + getAccessToken(resign M16 用 getAccessToken)
const requestMock = vi.fn();
const getAccessTokenMock = vi.fn().mockReturnValue('test-token');
vi.mock('@/api/client', () => ({
  request: (...args: unknown[]) => requestMock(...args),
  getAccessToken: () => getAccessTokenMock(),
}));

// resign(M16)直接用 axios streaming,不走 request
const axiosPostMock = vi.fn();
vi.mock('axios', () => ({
  default: { post: (...args: unknown[]) => axiosPostMock(...args) },
}));

import { auditApi } from './audit';

describe('audit API', () => {
  beforeEach(() => {
    requestMock.mockReset();
    axiosPostMock.mockReset();
    getAccessTokenMock.mockReturnValue('test-token');
  });

  it('analyze 应构造 multipart 请求', async () => {
    requestMock.mockResolvedValue({ taskId: 't-1', report: {} });
    const file = new File(['apk'], 'test.apk', { type: 'application/vnd.android.package-archive' });
    await auditApi.analyze(file);
    expect(requestMock).toHaveBeenCalled();
    const call = requestMock.mock.calls[0][0];
    expect(call.method).toBe('POST');
    expect(call.url).toBe('/audit/analyze');
    expect(call.headers['Content-Type']).toContain('multipart/form-data');
    expect(call.data).toBeInstanceOf(FormData);
  });

  it('resign 应构造含 keystore + 凭证的 multipart(axios streaming,M16)', async () => {
    axiosPostMock.mockResolvedValue({
      data: new Blob(['signed-apk']),
      headers: {
        'x-task-id': 't-2',
        'x-old-hash': 'old-h',
        'x-new-hash': 'new-h',
        'x-apk-size': '123',
      },
    });
    const apk = new File(['apk'], 'a.apk');
    const ks = new File(['ks'], 'k.jks');
    const result = await auditApi.resign(apk, ks, {
      keystorePassword: 'pass',
      keyAlias: 'key0',
      keyPassword: 'pass',
    });

    expect(axiosPostMock).toHaveBeenCalled();
    const [url, formData, config] = axiosPostMock.mock.calls[0] as [
      string,
      FormData,
      { responseType: string; headers: Record<string, string> },
    ];
    expect(url).toBe('/v1/audit/resign');
    expect(config.responseType).toBe('blob');
    expect(config.headers.Authorization).toBe('Bearer test-token');
    expect(formData.get('keystorePassword')).toBe('pass');
    expect(formData.get('keyAlias')).toBe('key0');
    expect(formData.get('keyPassword')).toBe('pass');
    expect(formData.get('apk')).toBeInstanceOf(File);
    expect(formData.get('keystore')).toBeInstanceOf(File);
    // 响应从 blob + header 组装
    expect(result.taskId).toBe('t-2');
    expect(result.oldHash).toBe('old-h');
    expect(result.newHash).toBe('new-h');
    expect(result.resignedApkSize).toBe(123);
    expect(result.blob).toBeInstanceOf(Blob);
  });

  it('listLogs 默认无参应 GET /audit/logs', async () => {
    requestMock.mockResolvedValue([]);
    await auditApi.listLogs();
    const call = requestMock.mock.calls[0][0];
    expect(call.method).toBe('GET');
    expect(call.url).toBe('/audit/logs');
    expect(call.params).toBeUndefined();
  });

  it('listLogs 应支持 limit + offset', async () => {
    requestMock.mockResolvedValue([]);
    await auditApi.listLogs({ limit: 10, offset: 20 });
    expect(requestMock.mock.calls[0][0].params).toEqual({ limit: 10, offset: 20 });
  });

  it('exportLogsCsv 应 GET /audit/logs/export', async () => {
    requestMock.mockResolvedValue({ csv: 'csv-data', filename: 'test.csv' });
    await auditApi.exportLogsCsv(5000);
    const call = requestMock.mock.calls[0][0];
    expect(call.method).toBe('GET');
    expect(call.url).toBe('/audit/logs/export');
    expect(call.params).toEqual({ limit: 5000 });
  });

  it('exportLogsCsv 无参应不传 params', async () => {
    requestMock.mockResolvedValue({ csv: '', filename: '' });
    await auditApi.exportLogsCsv();
    expect(requestMock.mock.calls[0][0].params).toBeUndefined();
  });

  it('traceWatermark 应构造 multipart', async () => {
    requestMock.mockResolvedValue({ found: false });
    const apk = new File(['apk'], 'a.apk');
    await auditApi.traceWatermark(apk);
    const call = requestMock.mock.calls[0][0];
    expect(call.url).toBe('/watermark/trace');
    expect(call.headers['Content-Type']).toContain('multipart/form-data');
  });
});
