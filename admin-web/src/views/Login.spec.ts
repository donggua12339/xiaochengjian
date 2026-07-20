import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import Login from './Login.vue';

vi.mock('@/api/client', () => ({
  request: vi.fn().mockResolvedValue({ accessToken: 'test-token', refreshToken: 'test-refresh' }),
  setTokens: vi.fn(),
}));

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
  useRoute: () => ({ query: {} }),
}));

vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({
    login: vi.fn().mockResolvedValue({ requiresTotp: false }),
    handleError: (e: unknown) => (e as Error)?.message ?? 'error',
  }),
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

describe('Login.vue', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
  });

  it('应渲染登录标题', () => {
    const wrapper = mount(Login, { global: { plugins: [createPinia()] } });
    expect(wrapper.text()).toContain('登录');
  });

  it('应渲染邮箱和密码输入框', () => {
    const wrapper = mount(Login, { global: { plugins: [createPinia()] } });
    expect(wrapper.find('input[type="text"]').exists()).toBe(true);
    expect(wrapper.find('input[type="password"]').exists()).toBe(true);
  });
});
