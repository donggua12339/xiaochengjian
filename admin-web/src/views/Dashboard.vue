<script setup lang="ts">
import { onMounted, ref } from 'vue';
import {
  NCard, NGrid, NGridItem, NStatistic, NSpace, NButton, NEmpty, NSpin,
  NText, NAlert, NSteps, NStep,
} from 'naive-ui';
import { useRouter } from 'vue-router';
import { appsApi, type AppItem } from '@/api/apps';

const router = useRouter();
const loading = ref(true);
const apps = ref<AppItem[]>([]);
const isFirstVisit = ref(false);

onMounted(async () => {
  // 首次访问标记
  if (!localStorage.getItem('xcj_visited')) {
    isFirstVisit.value = true;
    localStorage.setItem('xcj_visited', '1');
  }

  try {
    apps.value = await appsApi.list();
  } finally {
    loading.value = false;
  }
});

function dismissWelcome() {
  isFirstVisit.value = false;
}
</script>

<template>
  <NSpace vertical size="large">
    <!-- 首次访问欢迎引导 -->
    <NCard v-if="isFirstVisit" title="欢迎使用小城笺加固平台">
      <NAlert type="info" style="margin-bottom: 16px">
        小城笺提供玄甲(开源免费)和天衍(付费高级)两套加固方案，保护您的 APK 免受逆向、篡改、脱壳等攻击。
      </NAlert>

      <NText strong style="font-size: 16px">3 步完成加固</NText>
      <NSteps :current="0" style="margin-top: 12px; margin-bottom: 20px">
        <NStep title="上传 APK" description="选择您的 APK 文件，系统自动分析结构" />
        <NStep title="选择防护模块" description="勾选需要的加固功能，或直接选预设方案" />
        <NStep title="下载加固 APK" description="使用您的 Keystore 签名，下载即可发布" />
      </NSteps>

      <NSpace>
        <NButton type="primary" size="large" @click="router.push('/harden-upload')">
          立即加固我的 APK
        </NButton>
        <NButton size="large" @click="router.push('/sdk-guide')">
          了解 SDK 集成方式
        </NButton>
        <NButton quaternary @click="dismissWelcome">关闭引导</NButton>
      </NSpace>
    </NCard>

    <!-- 核心入口：加固 APK -->
    <NCard>
      <NGrid :cols="3" :x-gap="16">
        <NGridItem>
          <NCard
            size="small"
            hoverable
            style="cursor: pointer; text-align: center; padding: 20px"
            @click="router.push('/harden-upload')"
          >
            <div style="font-size: 32px; margin-bottom: 8px">🛡️</div>
            <NText strong style="font-size: 16px">加固 APK</NText>
            <br />
            <NText depth="3" style="font-size: 12px">
              上传 APK → 选模块 → 一键加固 → 下载
            </NText>
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard
            size="small"
            hoverable
            style="cursor: pointer; text-align: center; padding: 20px"
            @click="router.push('/quality-report')"
          >
            <div style="font-size: 32px; margin-bottom: 8px">📊</div>
            <NText strong style="font-size: 16px">质量报告</NText>
            <br />
            <NText depth="3" style="font-size: 12px">
              查看加固效果评分和改进建议
            </NText>
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard
            size="small"
            hoverable
            style="cursor: pointer; text-align: center; padding: 20px"
            @click="router.push('/audit')"
          >
            <div style="font-size: 32px; margin-bottom: 8px">🔍</div>
            <NText strong style="font-size: 16px">APK 诊断</NText>
            <br />
            <NText depth="3" style="font-size: 12px">
              分析 APK 安全性和加固状态
            </NText>
          </NCard>
        </NGridItem>
      </NGrid>
    </NCard>

    <!-- 统计概览 -->
    <NCard title="账户概览">
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

    <!-- 我的应用 -->
    <NCard title="我的应用">
      <template #header-extra>
        <NSpace>
          <NButton @click="router.push('/apps')">管理应用</NButton>
          <NButton type="primary" @click="router.push('/harden-upload')">加固 APK</NButton>
        </NSpace>
      </template>
      <NSpin :show="loading">
        <NEmpty v-if="apps.length === 0 && !loading" description="还没有应用">
          <template #extra>
            <NSpace>
              <NButton @click="router.push('/apps')">创建应用</NButton>
              <NButton type="primary" @click="router.push('/harden-upload')">
                直接加固 APK(无需创建应用)
              </NButton>
            </NSpace>
          </template>
        </NEmpty>
        <NGrid v-else :cols="3" :x-gap="16" :y-gap="16">
          <NGridItem v-for="app in apps" :key="app.id">
            <NCard size="small" hoverable @click="router.push(`/apps/${app.id}`)">
              <NSpace vertical>
                <strong>{{ app.name }}</strong>
                <NText depth="3" style="font-size: 12px">{{ app.packageName }}</NText>
              </NSpace>
            </NCard>
          </NGridItem>
        </NGrid>
      </NSpin>
    </NCard>
  </NSpace>
</template>
