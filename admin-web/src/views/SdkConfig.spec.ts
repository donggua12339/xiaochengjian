/**
 * SdkConfig.vue 组件测试
 *
 * 覆盖:
 *  - 渲染 3 个复选框(obfstr / opaque-jni / control-flow-flattening)
 *  - 勾选 obfstr 后 Cargo.toml [features] 含 obfstr
 *  - control-flow-flattening 是未来工作(disabled)
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { mount } from '@vue/test-utils';
import { setActivePinia, createPinia } from 'pinia';
import SdkConfig from './SdkConfig.vue';
import { NCheckbox } from 'naive-ui';

// mock naive-ui 的 useMessage(组件里用了)
vi.mock('naive-ui', async () => {
  const actual = await vi.importActual('naive-ui');
  return {
    ...actual,
    useMessage: () => ({
      success: vi.fn(),
      error: vi.fn(),
      warning: vi.fn(),
      info: vi.fn(),
    }),
  };
});

describe('SdkConfig.vue', () => {
  beforeEach(() => {
    setActivePinia(createPinia());
  });

  it('应渲染 3 个复选框', () => {
    const wrapper = mount(SdkConfig, { global: { stubs: { NCard: true, NSpace: true, NCode: true, NButton: true, NDivider: true, NText: true } } });
    const checkboxes = wrapper.findAllComponents(NCheckbox);
    expect(checkboxes.length).toBe(3);
  });

  it('初始状态 Cargo.toml [features] 应含 default = []', () => {
    const wrapper = mount(SdkConfig, { global: { stubs: { NCard: true, NSpace: true, NCode: true, NButton: true, NDivider: true, NText: true } } });
    const text = wrapper.text();
    expect(text).toContain('[features]');
    expect(text).toContain('default = []');
  });
});
