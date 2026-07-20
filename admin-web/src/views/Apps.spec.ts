import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import Apps from './Apps.vue';

vi.mock('@/api/apps', () => ({
  appsApi: {
    list: vi.fn().mockResolvedValue([]),
    create: vi.fn().mockResolvedValue({ appSecret: 'test-secret' }),
    delete: vi.fn().mockResolvedValue(undefined),
  },
}));

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({ handleError: (e: unknown) => (e as Error)?.message ?? 'error' }),
}));

vi.mock('naive-ui', async () => {
  const actual = await vi.importActual('naive-ui');
  return {
    ...actual,
    useMessage: () => ({
      error: vi.fn(),
      success: vi.fn(),
      warning: vi.fn(),
    }),
  };
});

describe('Apps.vue', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
  });

  it('应渲染应用管理标题', () => {
    const wrapper = mount(Apps, { global: { plugins: [createPinia()] } });
    expect(wrapper.text()).toContain('应用管理');
  });

  it('应渲染创建应用按钮', () => {
    const wrapper = mount(Apps, { global: { plugins: [createPinia()] } });
    expect(wrapper.text()).toContain('创建应用');
  });
});
