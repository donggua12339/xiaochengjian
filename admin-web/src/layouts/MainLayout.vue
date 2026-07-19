<script setup lang="ts">
import { computed } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { NLayout, NLayoutSider, NLayoutHeader, NLayoutContent, NMenu, NButton, NSpace, NText } from 'naive-ui';
import { useAuthStore } from '@/stores/auth';
import type { MenuOption } from 'naive-ui';

const router = useRouter();
const route = useRoute();
const auth = useAuthStore();

const menuOptions = computed<MenuOption[]>(() => [
  { label: '概览', key: 'dashboard' },
  { label: '应用管理', key: 'apps' },
  { label: 'SDK 集成指南', key: 'sdk-guide' },
  { label: 'SDK 配置', key: 'sdk-config' },
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
      <NMenu
        :options="menuOptions"
        :value="activeKey"
        @update:value="handleMenuSelect"
      />
    </NLayoutSider>
    <NLayout>
      <NLayoutHeader bordered class="header">
        <NSpace justify="space-between" align="center" style="height: 100%; padding: 0 24px">
          <NText depth="2">卡密验证系统管理后台</NText>
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
