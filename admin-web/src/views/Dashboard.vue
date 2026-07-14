<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { NCard, NGrid, NGridItem, NStatistic, NSpace, NButton, NEmpty, NSpin } from 'naive-ui';
import { useRouter } from 'vue-router';
import { appsApi, type AppItem } from '@/api/apps';

const router = useRouter();
const loading = ref(true);
const apps = ref<AppItem[]>([]);

onMounted(async () => {
  try {
    apps.value = await appsApi.list();
  } finally {
    loading.value = false;
  }
});
</script>

<template>
  <NSpace vertical size="large">
    <NCard title="概览">
      <NGrid :cols="4" :x-gap="16" :y-gap="16">
        <NGridItem>
          <NStatistic label="应用数" :value="apps.length" />
        </NGridItem>
        <NGridItem>
          <NStatistic label="会员等级" value="免费版" />
        </NGridItem>
        <NGridItem>
          <NStatistic label="2FA 状态" value="未启用" />
        </NGridItem>
        <NGridItem>
          <NStatistic label="应用配额" :value="`${apps.length} / 5`" />
        </NGridItem>
      </NGrid>
    </NCard>

    <NCard title="我的应用">
      <template #header-extra>
        <NButton type="primary" @click="router.push('/apps')">管理应用</NButton>
      </template>
      <NSpin :show="loading">
        <NEmpty v-if="apps.length === 0 && !loading" description="还没有应用,去创建第一个吧">
          <template #extra>
            <NButton type="primary" @click="router.push('/apps')">创建应用</NButton>
          </template>
        </NEmpty>
        <NGrid v-else :cols="3" :x-gap="16" :y-gap="16">
          <NGridItem v-for="app in apps" :key="app.id">
            <NCard size="small" hoverable @click="router.push(`/apps/${app.id}`)">
              <NSpace vertical>
                <strong>{{ app.name }}</strong>
                <NSpace size="small">
                  <NText depth="3" style="font-size: 12px">{{ app.packageName }}</NText>
                </NSpace>
              </NSpace>
            </NCard>
          </NGridItem>
        </NGrid>
      </NSpin>
    </NCard>
  </NSpace>
</template>

<script lang="ts">
import { NText } from 'naive-ui';
export default { components: { NText } };
</script>
