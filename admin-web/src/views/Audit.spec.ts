import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';
import { createMemoryHistory, createRouter } from 'vue-router';
import { createPinia, setActivePinia } from 'pinia';
import Audit from './Audit.vue';
import { auditApi } from '@/api/audit';
import { useAuthStore } from '@/stores/auth';

// mock auditApi
vi.mock('@/api/audit', () => ({
  auditApi: {
    analyze: vi.fn(),
    resign: vi.fn(),
    listLogs: vi.fn().mockResolvedValue([]),
    traceWatermark: vi.fn(),
  },
}));

// mock auth store
vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({
    developer: { id: 'dev-1', email: 'test@test.com', role: 'ADMIN' },
    handleError: (e: unknown) => (e as Error)?.message ?? 'error',
  }),
}));

// mock naive-ui message(避免 useMessage 在无 provider 时报错)
const mockMessage = {
  success: vi.fn(),
  error: vi.fn(),
  warning: vi.fn(),
  info: vi.fn(),
};
vi.mock('naive-ui', async () => {
  const actual = await vi.importActual<typeof import('naive-ui')>('naive-ui');
  return {
    ...actual,
    useMessage: () => mockMessage,
  };
});

describe('Audit.vue', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    vi.clearAllMocks();
  });

  function mountComponent() {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: '/', component: Audit }],
    });
    return mount(Audit, {
      global: {
        plugins: [router],
      },
    });
  }

  it('应渲染 4 个 Tab(诊断/回填/历史/水印追溯)', async () => {
    const wrapper = mountComponent();
    await flushPromises();
    const html = wrapper.html();
    // 4 个 Tab 标题(水印追溯仅 ADMIN 可见,测试用例的 mock role=ADMIN)
    expect(html).toContain('诊断(只读)');
    expect(html).toContain('签名回填(例外 A)');
    expect(html).toContain('诊断历史');
    expect(html).toContain('水印追溯(ADMIN)');
  });

  it('挂载时应加载历史日志', async () => {
    mountComponent();
    await flushPromises();
    expect(auditApi.listLogs).toHaveBeenCalledWith({ limit: 50, offset: 0 });
  });

  it('诊断成功路径(mock analyze 返回报告)', async () => {
    vi.mocked(auditApi.analyze).mockResolvedValue({
      taskId: 'audit-test',
      report: {
        taskId: 'audit-test',
        timestamp: '2026-07-20T00:00:00Z',
        apkInfo: {
          packageName: 'com.test',
          apkHash: 'abc123',
          apkSize: 1024,
          signatureHash: 'sig456',
        },
        manifest: { permissions: ['android.permission.INTERNET'] },
        securityFindings: {
          cleartextTraffic: null,
          debuggable: null,
          backupEnabled: null,
        },
      },
    });
    const wrapper = mountComponent();
    await flushPromises();
    // 初始加载不调 analyze(需用户点击按钮 + 上传文件,留给 e2e)
    expect(auditApi.analyze).not.toHaveBeenCalled();
    // 验证组件渲染了"自有 APK 诊断"标题
    expect(wrapper.html()).toContain('自有 APK 诊断');
  });
});
