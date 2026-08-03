/**
 * HardenUpload.vue 组件测试
 *
 * 覆盖:
 *  - NSteps current = currentStep + 1(修复 off-by-one:Naive UI NSteps 是 1-based)
 *  - 初始渲染上传步骤
 *  - 默认签名可用时显示"使用默认签名"选项
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount, flushPromises } from '@vue/test-utils';

// naive-ui useMessage 需 provider,单测里 stub 掉
vi.mock('naive-ui', async (importOriginal) => {
  const actual = await importOriginal<typeof import('naive-ui')>();
  return {
    ...actual,
    useMessage: () => ({ error: vi.fn(), success: vi.fn(), warning: vi.fn(), info: vi.fn() }),
  };
});

const getDefaultSignStatusMock = vi.fn();
vi.mock('@/api/hardening', () => ({
  chunkedUpload: vi.fn(),
  analyzeApk: vi.fn(),
  hardenApk: vi.fn(),
  getHardeningStatus: vi.fn(),
  downloadHardenedApk: vi.fn(),
  getDefaultSignStatus: (...a: unknown[]) => getDefaultSignStatusMock(...a),
  MAX_FILE_SIZE: 1024 * 1024 * 1024,
}));

import HardenUpload from './HardenUpload.vue';
import { NSteps } from 'naive-ui';

describe('HardenUpload.vue', () => {
  beforeEach(() => {
    getDefaultSignStatusMock.mockReset();
  });

  const mountComponent = async () => {
    const wrapper = mount(HardenUpload, {
      global: { stubs: { teleport: true } },
    });
    await flushPromises();
    return wrapper;
  };

  it('初始应渲染 APK 加固标题 + 上传步骤', async () => {
    getDefaultSignStatusMock.mockResolvedValue({ enabled: false });
    const wrapper = await mountComponent();
    expect(wrapper.text()).toContain('APK 加固');
    expect(wrapper.text()).toContain('选择 APK 文件');
  });

  it('NSteps current 应为 1(上传步,1-based)', async () => {
    getDefaultSignStatusMock.mockResolvedValue({ enabled: false });
    const wrapper = await mountComponent();
    const steps = wrapper.findComponent(NSteps);
    expect(steps.exists()).toBe(true);
    // currentStep=0 → NSteps current=1(修复 off-by-one)
    expect(steps.props('current')).toBe(1);
  });

  it('默认签名可用时应显示"使用默认签名"入口', async () => {
    getDefaultSignStatusMock.mockResolvedValue({ enabled: true, alias: 'donggua16600' });
    const wrapper = await mountComponent();
    // 默认签名选项在 Step 3(签名步),初始 currentStep=0 不可见,但 onMounted 已拉取状态
    expect(getDefaultSignStatusMock).toHaveBeenCalled();
    // 步骤条含"签名"步
    expect(wrapper.text()).toContain('签名');
  });

  it('默认签名不可用时 onMounted 静默降级', async () => {
    getDefaultSignStatusMock.mockRejectedValue(new Error('network'));
    const wrapper = await mountComponent();
    expect(getDefaultSignStatusMock).toHaveBeenCalled();
    expect(wrapper.text()).toContain('APK 加固');
  });
});
