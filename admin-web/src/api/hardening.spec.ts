/**
 * api/hardening 单元测试
 *
 * 覆盖:
 *  - downloadHardenedApk:触发下载 + 延迟释放 blob URL(Bug: 提前 revoke 导致静默失败)
 *  - getDefaultSignStatus:GET /hardening/default-sign-status
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const getMock = vi.fn();
const requestMock = vi.fn();
vi.mock('@/api/client', () => ({
  longTimeoutClient: { get: (...a: unknown[]) => getMock(...a), post: vi.fn() },
  request: (...a: unknown[]) => requestMock(...a),
}));

import { downloadHardenedApk, getDefaultSignStatus } from './hardening';

describe('api/hardening', () => {
  let createObjectURL: ReturnType<typeof vi.fn>;
  let revokeObjectURL: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers();
    getMock.mockReset();
    requestMock.mockReset();
    // jsdom 未实现 URL.createObjectURL,直接赋值 mock
    createObjectURL = vi.fn().mockReturnValue('blob:fake');
    revokeObjectURL = vi.fn();
    URL.createObjectURL = createObjectURL;
    URL.revokeObjectURL = revokeObjectURL;
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  describe('downloadHardenedApk', () => {
    it('应触发下载且 10s 后才释放 blob URL(防静默失败)', async () => {
      getMock.mockResolvedValue(new Blob(['apk-bytes']));

      const click = vi.fn();
      const anchor = { href: '', download: '', click } as unknown as HTMLAnchorElement;
      vi.spyOn(document, 'createElement').mockReturnValue(anchor);
      vi.spyOn(document.body, 'appendChild').mockImplementation((n) => n);
      vi.spyOn(document.body, 'removeChild').mockImplementation((n) => n);

      await downloadHardenedApk('task-12345678-extra');

      // 用 blob URL 触发下载,文件名取 taskId 前 8 位
      expect(createObjectURL).toHaveBeenCalled();
      expect(anchor.href).toBe('blob:fake');
      expect(anchor.download).toBe('hardened_task-123.apk');
      expect(click).toHaveBeenCalled();

      // 关键:下载刚触发时不能立刻 revoke(否则静默失败)
      expect(revokeObjectURL).not.toHaveBeenCalled();

      // 10s 后才释放
      vi.advanceTimersByTime(10_000);
      expect(revokeObjectURL).toHaveBeenCalledWith('blob:fake');
    });

    it('响应非 Blob 时应包装成 Blob', async () => {
      getMock.mockResolvedValue('raw-string');
      const anchor = { href: '', download: '', click: vi.fn() } as unknown as HTMLAnchorElement;
      vi.spyOn(document, 'createElement').mockReturnValue(anchor);
      vi.spyOn(document.body, 'appendChild').mockImplementation((n) => n);
      vi.spyOn(document.body, 'removeChild').mockImplementation((n) => n);

      await expect(downloadHardenedApk('abcdefgh')).resolves.toBeUndefined();
      expect(anchor.click).toHaveBeenCalled();
    });
  });

  describe('getDefaultSignStatus', () => {
    it('应 GET default-sign-status 并返回结果', async () => {
      requestMock.mockResolvedValue({ enabled: true, alias: 'donggua16600' });
      const r = await getDefaultSignStatus();
      expect(requestMock).toHaveBeenCalledWith(
        expect.objectContaining({ method: 'GET', url: '/hardening/default-sign-status' }),
      );
      expect(r).toEqual({ enabled: true, alias: 'donggua16600' });
    });

    it('未启用时返回 enabled=false', async () => {
      requestMock.mockResolvedValue({ enabled: false });
      const r = await getDefaultSignStatus();
      expect(r.enabled).toBe(false);
    });
  });
});
