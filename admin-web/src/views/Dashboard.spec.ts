import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mount } from '@vue/test-utils';
import { createPinia, setActivePinia } from 'pinia';
import Dashboard from './Dashboard.vue';

vi.mock('@/api/apps', () => ({
  appsApi: {
    list: vi.fn().mockResolvedValue([]),
  },
}));

vi.mock('vue-router', () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

describe('Dashboard.vue', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
  });

  it('应渲染概览标题', () => {
    const wrapper = mount(Dashboard, { global: { plugins: [createPinia()] } });
    expect(wrapper.text()).toContain('概览');
  });

  it('应渲染我的应用标题', () => {
    const wrapper = mount(Dashboard, { global: { plugins: [createPinia()] } });
    expect(wrapper.text()).toContain('我的应用');
  });
});
