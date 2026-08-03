<script setup lang="ts">
import { computed } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import {
  NLayout,
  NLayoutSider,
  NLayoutHeader,
  NLayoutContent,
  NMenu,
  NButton,
  NSpace,
  NText,
} from 'naive-ui';
import { useAuthStore } from '@/stores/auth';
import type { MenuOption } from 'naive-ui';

const router = useRouter();
const route = useRoute();
const auth = useAuthStore();

const menuOptions = computed<MenuOption[]>(() => [
  { label: '概览', key: 'dashboard' },
  { type: 'divider', key: 'd1' },
  {
    type: 'group',
    label: '加固',
    key: 'g-harden',
    children: [
      { label: 'APK 加固', key: 'harden-upload' },
      { label: '加固任务', key: 'harden-tasks' },
      { label: '质量报告', key: 'quality-report' },
      { label: '加固配置', key: 'harden-config' },
    ],
  },
  {
    type: 'group',
    label: '应用',
    key: 'g-app',
    children: [
      { label: '应用管理', key: 'apps' },
      { label: 'APK 诊断', key: 'audit' },
    ],
  },
  {
    type: 'group',
    label: '开发者工具',
    key: 'g-dev',
    children: [
      { label: 'SDK 封装', key: 'packer' },
      { label: 'SDK 配置', key: 'sdk-config' },
      { label: 'SDK 集成指南', key: 'sdk-guide' },
    ],
  },
  { type: 'divider', key: 'd2' },
  { label: '设置', key: 'settings' },
]);

function handleMenuSelect(key: string) {
  router.push({ name: key });
}

function handleLogout() {
  auth.logout();
  router.push('/login');
}

const activeKey = computed(() => {
  if (route.name === 'app-detail') return 'apps';
  return (route.name as string) ?? '';
});
</script>

<template>
  <NLayout has-sider style="height: 100vh">
    <NLayoutSider bordered :width="220" :collapsed-width="64">
      <div class="logo">
        <h2>小城笺</h2>
      </div>
      <NMenu :options="menuOptions" :value="activeKey" @update:value="handleMenuSelect" />
    </NLayoutSider>
    <NLayout>
      <NLayoutHeader bordered class="header">
        <NSpace justify="space-between" align="center" style="height: 100%; padding: 0 24px">
          <NText depth="2">小城笺 · APK 加固平台</NText>
          <NSpace align="center">
            <NText depth="3">{{ auth.developer?.email ?? '开发者' }}</NText>
            <NButton size="small" quaternary @click="handleLogout">登出</NButton>
          </NSpace>
        </NSpace>
      </NLayoutHeader>
      <NLayoutContent class="content" content-style="padding: 24px;">
        <RouterView v-slot="{ Component }">
          <KeepAlive>
            <component :is="Component" />
          </KeepAlive>
        </RouterView>
      </NLayoutContent>
    </NLayout>
  </NLayout>
</template>

<style scoped>
.logo {
  height: 56px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-bottom: 1px solid var(--n-border-color);
}
.logo h2 {
  margin: 0;
  font-size: 18px;
  color: var(--n-text-color);
}
.header {
  height: 56px;
  display: flex;
  align-items: center;
}
.content {
  height: calc(100vh - 56px);
  overflow: auto;
  background: var(--n-body-color);
}
</style>
