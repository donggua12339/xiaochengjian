<script setup lang="ts">
/**
 * 加固任务列表页
 *
 * 功能:
 *  - 展示当前用户所有加固/分析任务(来自 Redis,刷新不丢)
 *  - 实时刷新进行中的任务状态
 *  - 已完成的任务可直接下载
 *  - 分析完成的任务可跳转到加固配置页
 */

import { ref, onMounted, onUnmounted } from 'vue';
import {
  NCard, NButton, NSpace, NTag, NText, NEmpty, NProgress,
  NAlert,
} from 'naive-ui';
import { useRouter } from 'vue-router';
import { getHardeningTasks, getHardeningStatus, downloadHardenedApk } from '@/api/hardening';
import type { HardeningTaskSummary } from '@/api/hardening';

const router = useRouter();
const tasks = ref<HardeningTaskSummary[]>([]);
const loading = ref(true);

let refreshTimer: ReturnType<typeof setInterval> | null = null;

onMounted(async () => {
  await loadTasks();
  // 每 3 秒刷新进行中的任务
  refreshTimer = setInterval(refreshActive, 3000);
});

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer);
});

async function loadTasks() {
  loading.value = true;
  try {
    const res = await getHardeningTasks() as any;
    tasks.value = res.tasks ?? [];
  } catch {
    // ignore
  } finally {
    loading.value = false;
  }
}

async function refreshActive() {
  const active = tasks.value.filter((t) => !['completed', 'failed'].includes(t.status));
  for (const t of active) {
    try {
      const s = await getHardeningStatus(t.id) as any;
      t.status = s.status;
      t.progress = s.progress;
      t.message = s.message;
      t.step = s.step;
      t.detail = s.detail;
    } catch { /* ignore */ }
  }
}

const statusMap: Record<string, { label: string; type: 'success' | 'error' | 'warning' | 'info' | 'default' }> = {
  queued: { label: '排队中', type: 'default' },
  analyzing: { label: '分析中', type: 'info' },
  hardening: { label: '加固中', type: 'warning' },
  signing: { label: '签名中', type: 'warning' },
  completed: { label: '已完成', type: 'success' },
  failed: { label: '失败', type: 'error' },
};

const stepIcons: Record<string, string> = {
  queued: '⏳', unzip: '📦', dex: '📄', abi: '🔧', manifest: '📋',
  hardener: '🔍', sdk: '📱', config: '⚙️', asset: '📁', so: '🔒',
  sign: '🔑', done: '✅', error: '❌',
};

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
}

function isActive(status: string): boolean {
  return !['completed', 'failed'].includes(status);
}

function downloadTask(taskId: string) {
  window.open(downloadHardenedApk(taskId), '_blank');
}
</script>

<template>
  <div style="max-width: 900px; margin: 0 auto; padding: 24px">
    <NCard title="加固任务">
      <template #header-extra>
        <NSpace>
          <NButton @click="loadTasks" :loading="loading">刷新</NButton>
          <NButton type="primary" @click="router.push('/harden-upload')">新建加固</NButton>
        </NSpace>
      </template>

      <NEmpty v-if="!loading && tasks.length === 0" description="暂无加固任务">
        <template #extra>
          <NButton type="primary" @click="router.push('/harden-upload')">上传 APK 开始加固</NButton>
        </template>
      </NEmpty>

      <NSpace v-else vertical :size="12">
        <NCard v-for="task in tasks" :key="task.id" size="small" :class="{ 'active-task': isActive(task.status) }">
          <NSpace justify="space-between" align="center">
            <!-- 左侧: 状态 + 文件名 -->
            <NSpace align="center" :size="12">
              <span style="font-size: 20px">{{ stepIcons[task.step] || '📋' }}</span>
              <div>
                <NSpace align="center" :size="8">
                  <NText strong>{{ task.apkFileName || '未知 APK' }}</NText>
                  <NTag :type="statusMap[task.status]?.type ?? 'default'" size="small" round>
                    {{ statusMap[task.status]?.label ?? task.status }}
                  </NTag>
                </NSpace>
                <NText depth="3" style="font-size: 12px">
                  {{ task.message }}
                  <template v-if="task.detail"> · {{ task.detail }}</template>
                  <br />
                  {{ formatTime(task.createdAt) }}
                </NText>
              </div>
            </NSpace>

            <!-- 右侧: 进度 + 操作 -->
            <NSpace align="center" :size="12">
              <NProgress
                v-if="isActive(task.status)"
                type="circle"
                :percentage="task.progress"
                :stroke-width="4"
                style="width: 40px"
              />
              <NButton
                v-if="task.status === 'completed'"
                type="primary"
                size="small"
                @click="downloadTask(task.id)"
              >
                下载
              </NButton>
              <NButton
                v-if="task.status === 'failed'"
                size="small"
                @click="router.push('/harden-upload')"
              >
                重试
              </NButton>
            </NSpace>
          </NSpace>

          <!-- 进行中的进度条 -->
          <NProgress
            v-if="isActive(task.status)"
            type="line"
            :percentage="task.progress"
            :show-indicator="false"
            :height="4"
            style="margin-top: 8px"
          />
        </NCard>
      </NSpace>

      <NAlert v-if="tasks.length > 0" type="info" style="margin-top: 16px">
        任务记录保存 24 小时。进行中的任务会自动刷新状态,刷新页面不会丢失进度。
      </NAlert>
    </NCard>
  </div>
</template>

<style scoped>
.active-task {
  border-left: 3px solid var(--n-color-target);
}
</style>
