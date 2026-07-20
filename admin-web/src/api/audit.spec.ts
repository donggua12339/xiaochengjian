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

// mock client 的 request
const requestMock = vi.fn();
vi.mock('@/api/client', () => ({
  request: (...args: unknown[]) => requestMock(...args),
}));

import { auditApi } from './audit';

describe('audit API', () => {
  beforeEach(() => {
    requestMock.mockReset();
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

  it('resign 应构造含 keystore + 凭证的 multipart', async () => {
    requestMock.mockResolvedValue({ taskId: 't-2' });
    const apk = new File(['apk'], 'a.apk');
    const ks = new File(['ks'], 'k.jks');
    await auditApi.resign(apk, ks, {
      keystorePassword: 'pass',
      keyAlias: 'key0',
      keyPassword: 'pass',
    });
    const call = requestMock.mock.calls[0][0];
    expect(call.url).toBe('/audit/resign');
    const formData = call.data as FormData;
    expect(formData.get('keystorePassword')).toBe('pass');
    expect(formData.get('keyAlias')).toBe('key0');
    expect(formData.get('keyPassword')).toBe('pass');
    expect(formData.get('apk')).toBeInstanceOf(File);
    expect(formData.get('keystore')).toBeInstanceOf(File);
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
