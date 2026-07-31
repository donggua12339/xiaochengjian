<script setup lang="ts">
/**
 * APK 加固上传页面
 *
 * 流程: 上传 APK → 异步分析(轮询进度) → 勾选模块 → Keystore → 加固 → 下载
 * 分析进度实时展示: 步骤名 + 详情(包名/DEX/ABI/Manifest)
 * 刷新页面后可从"加固任务"tab 恢复
 */

import { ref, computed, onUnmounted, onActivated, onDeactivated } from 'vue';
import {
  NCard,
  NButton,
  NSpace,
  NUpload,
  NProgress,
  NTag,
  NText,
  NCheckbox,
  NGrid,
  NGi,
  NDivider,
  NAlert,
  NSelect,
  NInput,
  NSteps,
  NStep,
  useMessage,
} from 'naive-ui';
import type { UploadFileInfo } from 'naive-ui';
import axios from 'axios';
import { chunkedUpload, analyzeApk, hardenApk, getHardeningStatus, downloadHardenedApk, MAX_FILE_SIZE } from '@/api/hardening';
import type { ApkAnalysis, HardeningRequestConfig, HardeningTaskStatus } from '@/api/hardening';

const message = useMessage();

/** 从 unknown 错误提取消息(Bug A: 优先提取后端 message 而非 axios 通用消息) */
function errMsg(e: unknown): string {
  // axios 错误: 提取后端 response.data.message
  if (axios.isAxiosError(e)) {
    const data = e.response?.data as Record<string, unknown> | undefined;
    if (data?.message) return String(data.message);
    if (data?.code) return String(data.code);
    return e.message;
  }
  if (e instanceof Error) return e.message;
  if (typeof e === 'object' && e !== null && 'message' in e) {
    return String((e as Record<string, unknown>).message ?? '');
  }
  return String(e);
}

// ========== 步骤控制 ==========
const currentStep = ref(0); // 0=上传 1=分析中 2=配置 3=签名 4=加固 5=完成

// ========== Step 0: 上传 + 分析 ==========
const apkFile = ref<File | null>(null);
const analyzing = ref(false);
const uploadProgress = ref(0);
const uploadPhase = ref<'idle' | 'uploading' | 'analyzing'>('idle');
const fileId = ref<string | null>(null);

async function handleApkUpload({ file }: { file: UploadFileInfo }) {
  if (!file.file) return;

  // 预检: 文件大小 > 1GB → 友好提示,不发请求
  if (file.file.size > MAX_FILE_SIZE) {
    globalError.value = 'APK 体积过大(上限 1GB)，请压缩资源后重试';
    message.error(globalError.value);
    return;
  }

  apkFile.value = file.file;
  analyzing.value = true;
  uploadProgress.value = 0;
  uploadPhase.value = 'uploading';
  currentStep.value = 1;
  globalError.value = '';

  try {
    // Phase 1: 分片上传(带进度条)
    const uploadResult = await chunkedUpload(file.file, (percent) => {
      uploadProgress.value = percent;
    });
    fileId.value = uploadResult.fileId;
    uploadProgress.value = 100;

    // Phase 2: 启动分析
    uploadPhase.value = 'analyzing';
    const { taskId } = await analyzeApk(uploadResult.fileId);
    taskStatus.value = {
      id: taskId,
      status: 'analyzing',
      progress: 0,
      message: '正在连接服务器...',
      step: 'queued',
      detail: '',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    } as HardeningTaskStatus;
    startPolling(taskId, 'analysis');
  } catch (e: unknown) {
    globalError.value = `上传失败: ${errMsg(e)}`;
    message.error(globalError.value);
    analyzing.value = false;
    uploadPhase.value = 'idle';
    currentStep.value = 0;
  }
}

// ========== 轮询进度 ==========
const taskStatus = ref<HardeningTaskStatus | null>(null);
let pollTimer: ReturnType<typeof setInterval> | null = null;
let pollErrorCount = 0;
const MAX_POLL_ERRORS = 5;

function startPolling(taskId: string, mode: 'analysis' | 'hardening') {
  stopPolling();
  if (!taskId) {
    message.error('任务 ID 无效,请重新上传');
    analyzing.value = false;
    currentStep.value = 0;
    return;
  }
  pollErrorCount = 0;
  pollTimer = setInterval(async () => {
    try {
      const status = (await getHardeningStatus(taskId)) as HardeningTaskStatus;
      pollErrorCount = 0; // 成功则重置计数
      taskStatus.value = status;

      if (status.status === 'completed') {
        stopPolling();
        if (mode === 'analysis') {
          analysis.value = status.analysis ?? null;
          applyRecommendedConfig(status.analysis?.recommendedConfig);
          analyzing.value = false;
          currentStep.value = 2;
          message.success('APK 分析完成');
        } else {
          analyzing.value = false;
          currentStep.value = 5;
          message.success('加固完成!');
        }
      } else if (status.status === 'failed') {
        stopPolling();
        analyzing.value = false;
        message.error(
          `${mode === 'analysis' ? '分析' : '加固'}失败: ${status.error || status.message}`,
        );
        currentStep.value = mode === 'analysis' ? 0 : 3;
      }
    } catch (e: unknown) {
      pollErrorCount++;
      if (pollErrorCount >= MAX_POLL_ERRORS) {
        stopPolling();
        analyzing.value = false;
        globalError.value = `轮询失败(${pollErrorCount} 次): ${errMsg(e)}`;
        message.error(globalError.value);
        currentStep.value = mode === 'analysis' ? 0 : 3;
      }
    }
  }, 2000);
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

onUnmounted(() => stopPolling());

// KeepAlive 钩子: 离开页面停止轮询,回来时重置卡住状态
onDeactivated(() => stopPolling());
onActivated(() => {
  // 如果当前在分析/加固步骤但轮询已停(从缓存恢复),重置到上传步骤
  if ((currentStep.value === 1 || currentStep.value === 4) && !pollTimer) {
    resetAll();
  }
});

// 全局错误消息(显示在步骤卡片下方)
const globalError = ref('');

// ========== Step 2: 配置 ==========
const analysis = ref<ApkAnalysis | null>(null);
const productLine = ref<'xuanjia' | 'tianyan'>('xuanjia');
const preset = ref<string>('standard');

const xuanjiaModules = ref<Record<string, boolean>>({
  x0_soEncrypt: true,
  x3_lifecycle: true,
  x4_antiDynamic: true,
  x5_vpnProxy: true,
  x6_dualApp: true,
  x7_privatePort: true,
  x8_fart: false,
  x9_odex: false,
});
const tianyanModules = ref<Record<string, boolean>>({
  t1_customLinker: true,
  t2_vmp: true,
  t3_segment: false,
  t4_dexStringEncrypt: false,
});

const killAction = ref('kill');
const weakThreshold = ref(70);

const presetOptions = [
  { label: '基础(核心防护)', value: 'basic' },
  { label: '标准(推荐)', value: 'standard' },
  { label: '激进(全模块)', value: 'aggressive' },
  { label: '偏执(最大防护)', value: 'paranoid' },
];

const xuanjiaLabels: Record<string, string> = {
  x0_soEncrypt: 'X0 SO 本体加密(RC4+memfd)',
  x3_lifecycle: 'X3 生命周期劫持检测',
  x4_antiDynamic: 'X4 反动态五层 + 12 层反 Frida',
  x5_vpnProxy: 'X5 VPN/代理检测',
  x6_dualApp: 'X6 双开/分身检测',
  x7_privatePort: 'X7 私人端口保护',
  x8_fart: 'X8 FART 脱壳扫描',
  x9_odex: 'X9 ODEX 修补检测',
};
const tianyanLabels: Record<string, string> = {
  t1_customLinker: 'T1 自实现 Linker(匿名映射)',
  t2_vmp: 'T2 VMP 保护解密函数',
  t3_segment: 'T3 字符串分段散列',
  t4_dexStringEncrypt: 'T4 DEX 字符串加密',
};

function applyRecommendedConfig(config?: HardeningRequestConfig) {
  if (!config) return;
  productLine.value = config.productLine;
  preset.value = config.preset ?? 'standard';
  if (config.xuanjia) xuanjiaModules.value = { ...xuanjiaModules.value, ...config.xuanjia };
  if (config.tianyan) tianyanModules.value = { ...tianyanModules.value, ...config.tianyan };
}

function onPresetChange(val: string) {
  const presets: Record<string, { x: Record<string, boolean>; t: Record<string, boolean> }> = {
    basic: {
      x: {
        x0_soEncrypt: true,
        x3_lifecycle: true,
        x4_antiDynamic: true,
        x5_vpnProxy: false,
        x6_dualApp: false,
        x7_privatePort: false,
        x8_fart: false,
        x9_odex: false,
      },
      t: { t1_customLinker: true, t2_vmp: false, t3_segment: false, t4_dexStringEncrypt: false },
    },
    standard: {
      x: {
        x0_soEncrypt: true,
        x3_lifecycle: true,
        x4_antiDynamic: true,
        x5_vpnProxy: true,
        x6_dualApp: true,
        x7_privatePort: true,
        x8_fart: false,
        x9_odex: false,
      },
      t: { t1_customLinker: true, t2_vmp: true, t3_segment: false, t4_dexStringEncrypt: false },
    },
    aggressive: {
      x: {
        x0_soEncrypt: true,
        x3_lifecycle: true,
        x4_antiDynamic: true,
        x5_vpnProxy: true,
        x6_dualApp: true,
        x7_privatePort: true,
        x8_fart: true,
        x9_odex: true,
      },
      t: { t1_customLinker: true, t2_vmp: true, t3_segment: true, t4_dexStringEncrypt: false },
    },
    paranoid: {
      x: {
        x0_soEncrypt: true,
        x3_lifecycle: true,
        x4_antiDynamic: true,
        x5_vpnProxy: true,
        x6_dualApp: true,
        x7_privatePort: true,
        x8_fart: true,
        x9_odex: true,
      },
      t: { t1_customLinker: true, t2_vmp: true, t3_segment: true, t4_dexStringEncrypt: true },
    },
  };
  const p = presets[val];
  if (p) {
    xuanjiaModules.value = { ...p.x };
    tianyanModules.value = { ...p.t };
  }
}

const enabledCount = computed(() => {
  const x = Object.values(xuanjiaModules.value).filter(Boolean).length;
  const t =
    productLine.value === 'tianyan'
      ? Object.values(tianyanModules.value).filter(Boolean).length
      : 0;
  return x + t;
});

// ========== Keystore + 合规 ==========
const keystoreFile = ref<File | null>(null);
const ksPassword = ref('');
const ksAlias = ref('');
const ksKeyPassword = ref('');
const ownershipConfirmed = ref(false);

function handleKeystoreUpload({ file }: { file: UploadFileInfo }) {
  if (file.file) keystoreFile.value = file.file;
}

// ========== 加固执行 ==========
const hardening = ref(false);

async function startHardening() {
  if (!fileId.value) {
    message.error('请先上传 APK');
    return;
  }
  if (!keystoreFile.value) {
    message.error('请选择 Keystore 文件');
    return;
  }
  if (!ksPassword.value || !ksAlias.value || !ksKeyPassword.value) {
    message.error('请填写 Keystore 信息');
    return;
  }
  if (enabledCount.value === 0) {
    message.warning('请至少选择一个加固模块');
    return;
  }
  if (!ownershipConfirmed.value) {
    message.error('请确认 APK 所有权声明');
    return;
  }

  hardening.value = true;
  currentStep.value = 4;
  globalError.value = '';

  try {
    const config: HardeningRequestConfig = {
      productLine: productLine.value,
      preset: preset.value as HardeningRequestConfig['preset'],
      xuanjia: xuanjiaModules.value,
      ...(productLine.value === 'tianyan' ? { tianyan: tianyanModules.value } : {}),
      killPolicy: {
        strongEvidence: killAction.value as NonNullable<
          HardeningRequestConfig['killPolicy']
        >['strongEvidence'],
        weakScoreThreshold: weakThreshold.value,
        delayMinMs: 0,
        delayMaxMs: 1000,
      },
    };

    const res = await hardenApk({
      fileId: fileId.value,
      keystoreFile: keystoreFile.value,
      keystorePassword: ksPassword.value,
      keyAlias: ksAlias.value,
      keyPassword: ksKeyPassword.value,
      config,
      analysis: analysis.value!,
      ownershipConfirmed: ownershipConfirmed.value,
    });

    taskStatus.value = {
      id: res.taskId,
      status: 'hardening',
      progress: 0,
      message: '正在准备加固...',
      step: 'init',
      detail: '',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    } as HardeningTaskStatus;
    startPolling(res.taskId, 'hardening');
  } catch (e: unknown) {
    message.error(`加固失败: ${errMsg(e)}`);
    hardening.value = false;
    currentStep.value = 3;
  }
}

// ========== 下载 ==========
async function downloadApk() {
  if (!taskStatus.value?.id) return;
  try {
    await downloadHardenedApk(taskStatus.value.id);
  } catch (e: unknown) {
    message.error(`下载失败: ${errMsg(e)}`);
  }
}

function resetAll() {
  stopPolling();
  currentStep.value = 0;
  apkFile.value = null;
  analysis.value = null;
  taskStatus.value = null;
  keystoreFile.value = null;
  ksPassword.value = '';
  ksAlias.value = '';
  ksKeyPassword.value = '';
  ownershipConfirmed.value = false;
  uploadProgress.value = 0;
  uploadPhase.value = 'idle';
  fileId.value = null;
  globalError.value = '';
}

/** Bug F: 重试分析(不重传文件,用已有 fileId) */
async function retryAnalysis() {
  if (!fileId.value) { resetAll(); return; }
  globalError.value = '';
  analyzing.value = true;
  uploadPhase.value = 'analyzing';
  currentStep.value = 1;
  try {
    const { taskId } = await analyzeApk(fileId.value);
    taskStatus.value = {
      id: taskId, status: 'analyzing', progress: 0,
      message: '正在重新分析...', step: 'queued', detail: '',
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    } as HardeningTaskStatus;
    startPolling(taskId, 'analysis');
  } catch (e: unknown) {
    globalError.value = `重试分析失败: ${errMsg(e)}`;
    message.error(globalError.value);
    analyzing.value = false;
  }
}

/** Bug F: 重试加固(不重传文件,用已有 fileId + keystore) */
async function retryHarden() {
  if (!fileId.value || !keystoreFile.value) { resetAll(); return; }
  globalError.value = '';
  hardening.value = true;
  currentStep.value = 4;
  try {
    const config: HardeningRequestConfig = {
      productLine: productLine.value,
      preset: preset.value as HardeningRequestConfig['preset'],
      xuanjia: xuanjiaModules.value,
      ...(productLine.value === 'tianyan' ? { tianyan: tianyanModules.value } : {}),
      killPolicy: {
        strongEvidence: killAction.value as NonNullable<HardeningRequestConfig['killPolicy']>['strongEvidence'],
        weakScoreThreshold: weakThreshold.value, delayMinMs: 0, delayMaxMs: 1000,
      },
    };
    const res = await hardenApk({
      fileId: fileId.value, keystoreFile: keystoreFile.value,
      keystorePassword: ksPassword.value, keyAlias: ksAlias.value, keyPassword: ksKeyPassword.value,
      config, analysis: analysis.value!, ownershipConfirmed: ownershipConfirmed.value,
    });
    taskStatus.value = {
      id: res.taskId, status: 'hardening', progress: 0,
      message: '正在重新加固...', step: 'init', detail: '',
      createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    } as HardeningTaskStatus;
    startPolling(res.taskId, 'hardening');
  } catch (e: unknown) {
    globalError.value = `重试加固失败: ${errMsg(e)}`;
    message.error(globalError.value);
    hardening.value = false;
    currentStep.value = 3;
  }
}

// 进度条百分比
const progressPercent = computed(() => taskStatus.value?.progress ?? 0);
const progressMessage = computed(() => taskStatus.value?.message ?? '');
const progressDetail = computed(() => taskStatus.value?.detail ?? '');
const progressStep = computed(() => taskStatus.value?.step ?? '');

// 步骤图标映射
const stepIcons: Record<string, string> = {
  queued: '⏳',
  init: '🚀',
  unzip: '📦',
  dex: '📄',
  abi: '🔧',
  manifest: '📋',
  hardener: '🔍',
  sdk: '📱',
  config: '⚙️',
  asset: '📁',
  so: '🔒',
  sign: '🔑',
  done: '✅',
  error: '❌',
};
</script>

<template>
  <div style="max-width: 900px; margin: 0 auto; padding: 24px">
    <NCard title="APK 加固">
      <!-- 步骤条 -->
      <NSteps
        :current="currentStep === 1 ? 1 : currentStep >= 5 ? 5 : currentStep"
        size="small"
        style="margin-bottom: 20px"
      >
        <NStep title="上传" />
        <NStep title="分析" />
        <NStep title="选模块" />
        <NStep title="签名" />
        <NStep title="加固" />
        <NStep title="下载" />
      </NSteps>

      <!-- Step 0: 上传 -->
      <template v-if="currentStep === 0">
        <NUpload
          :max="1"
          accept=".apk"
          :default-upload="false"
          :show-file-list="true"
          @change="handleApkUpload"
        >
          <NButton type="primary" :loading="analyzing">
            {{ analyzing ? '上传中...' : '选择 APK 文件' }}
          </NButton>
        </NUpload>
      </template>

      <!-- Step 1: 上传+分析(实时进度) -->
      <template v-if="currentStep === 1">
        <!-- 上传进度 -->
        <NCard v-if="uploadPhase === 'uploading'" size="small">
          <NSpace align="center" style="margin-bottom: 12px">
            <span style="font-size: 24px">📤</span>
            <div>
              <NText strong>正在上传 APK...</NText>
              <br />
              <NText depth="3" style="font-size: 12px">
                {{ apkFile?.name }} ({{ ((apkFile?.size ?? 0) / 1024 / 1024).toFixed(1) }} MB)
              </NText>
            </div>
          </NSpace>
          <NProgress type="line" :percentage="uploadProgress" :show-indicator="true" status="info" />
        </NCard>

        <!-- 分析进度 -->
        <NCard v-if="uploadPhase === 'analyzing'" size="small">
          <NSpace align="center" style="margin-bottom: 12px">
            <span style="font-size: 24px">{{ stepIcons[progressStep] || '⏳' }}</span>
            <div>
              <NText strong>{{ progressMessage }}</NText>
              <br />
              <NText depth="3" style="font-size: 12px">{{ progressDetail }}</NText>
            </div>
          </NSpace>
          <NProgress
            type="line"
            :percentage="progressPercent"
            :show-indicator="true"
            status="info"
          />
        </NCard>

        <!-- 实时信息面板 -->
        <NCard v-if="taskStatus?.detail" size="small" style="margin-top: 12px">
          <template #header><NText depth="3" style="font-size: 12px">已获取信息</NText></template>
          <NGrid :cols="2" :x-gap="12" :y-gap="4">
            <NGi v-if="taskStatus.detail.includes('包名')">
              <NText depth="3" style="font-size: 12px">
                📦 {{ taskStatus.detail.split(', ').find((s) => s.startsWith('包名')) }}
              </NText>
            </NGi>
            <NGi v-if="taskStatus.detail.includes('DEX')">
              <NText depth="3" style="font-size: 12px">
                📄 {{ taskStatus.detail.split(', ').find((s) => s.startsWith('DEX')) }}
              </NText>
            </NGi>
            <NGi v-if="taskStatus.detail.includes('架构') || taskStatus.detail.includes('ABI')">
              <NText depth="3" style="font-size: 12px">
                🔧
                {{
                  taskStatus.detail.split(', ').find((s) => s.includes('架构') || s.includes('ABI'))
                }}
              </NText>
            </NGi>
          </NGrid>
        </NCard>

        <NAlert v-if="taskStatus?.status === 'failed'" type="error" style="margin-top: 12px">
          {{ taskStatus.error }}
          <div style="margin-top: 8px">
            <NSpace :size="8">
              <NButton v-if="fileId" size="small" type="warning" @click="retryAnalysis">重试分析</NButton>
              <NButton size="small" @click="resetAll">重新上传</NButton>
            </NSpace>
          </div>
        </NAlert>

        <!-- 全局错误(轮询失败/网络异常等) -->
        <NAlert v-if="globalError" type="error" style="margin-top: 12px">
          {{ globalError }}
          <div style="margin-top: 8px">
            <NSpace :size="8">
              <NButton v-if="fileId" size="small" type="warning" @click="retryAnalysis">重试分析</NButton>
              <NButton size="small" @click="resetAll">重新上传</NButton>
            </NSpace>
          </div>
        </NAlert>
      </template>

      <!-- Step 2: 配置模块 -->
      <template v-if="currentStep === 2 && analysis">
        <NAlert type="success" style="margin-bottom: 16px">
          <template #header>APK 分析结果</template>
          包名: {{ analysis.packageName }} | DEX: {{ analysis.dexFiles.length }} 个 | ABI:
          {{ analysis.nativeAbis.join(', ') || '无' }} | 大小:
          {{ (analysis.apkSize / 1024 / 1024).toFixed(1) }} MB | 已加固:
          {{ analysis.alreadyHardened ? analysis.detectedHardener : '否' }}
        </NAlert>

        <NAlert v-if="analysis.alreadyHardened" type="warning" style="margin-bottom: 16px">
          该 APK 已被 {{ analysis.detectedHardener }} 加固,建议先去除加固再使用。
        </NAlert>

        <NSpace align="center" style="margin-bottom: 16px">
          <NText strong>产品线:</NText>
          <NSelect
            v-model:value="productLine"
            :options="[
              { label: '玄甲(开源免费)', value: 'xuanjia' },
              { label: '天衍(付费高级)', value: 'tianyan' },
            ]"
            style="width: 200px"
          />
          <NText strong>强度:</NText>
          <NSelect
            v-model:value="preset"
            :options="presetOptions"
            style="width: 180px"
            @update:value="onPresetChange"
          />
        </NSpace>

        <NDivider title-placement="left">玄甲 X0-X9</NDivider>
        <NGrid :cols="2" :x-gap="12" :y-gap="8">
          <NGi v-for="(label, key) in xuanjiaLabels" :key="key">
            <NCheckbox
              v-model:checked="xuanjiaModules[key]"
              :disabled="
                analysis.unavailableFeatures.some((f) => f.feature === key || f.feature === 'all')
              "
            >
              {{ label }}
            </NCheckbox>
          </NGi>
        </NGrid>

        <template v-if="productLine === 'tianyan'">
          <NDivider title-placement="left">天衍 T1-T6</NDivider>
          <NGrid :cols="2" :x-gap="12" :y-gap="8">
            <NGi v-for="(label, key) in tianyanLabels" :key="key">
              <NCheckbox v-model:checked="tianyanModules[key]">{{ label }}</NCheckbox>
            </NGi>
          </NGrid>
        </template>

        <NDivider />
        <NSpace justify="space-between" align="center">
          <NText>
            已启用
            <NTag type="primary" size="small">{{ enabledCount }}</NTag>
            个模块
          </NText>
          <NSpace>
            <NButton @click="currentStep = 0">重新上传</NButton>
            <NButton type="primary" :disabled="enabledCount === 0" @click="currentStep = 3">
              下一步
            </NButton>
          </NSpace>
        </NSpace>
      </template>

      <!-- Step 3: Keystore + 声明 -->
      <template v-if="currentStep === 3">
        <NDivider title-placement="left">签名配置</NDivider>
        <NSpace vertical :size="12">
          <NUpload
            :max="1"
            accept=".jks,.keystore"
            :default-upload="false"
            :show-file-list="false"
            @change="handleKeystoreUpload"
          >
            <NButton>{{ keystoreFile ? '重新选择 Keystore' : '选择 Keystore(.jks)' }}</NButton>
          </NUpload>
          <NText v-if="keystoreFile" depth="3" style="font-size: 12px">
            ✅ {{ keystoreFile.name }} ({{ (keystoreFile.size / 1024).toFixed(1) }} KB)
          </NText>
          <NInput
            v-model:value="ksPassword"
            type="password"
            placeholder="Keystore 密码"
            show-password-on="click"
          />
          <NInput v-model:value="ksAlias" placeholder="Key 别名" />
          <NInput
            v-model:value="ksKeyPassword"
            type="password"
            placeholder="Key 密码"
            show-password-on="click"
          />
        </NSpace>

        <NDivider title-placement="left">所有权声明(ADR 0097)</NDivider>
        <NAlert type="warning" style="margin-bottom: 12px">
          <template #header>法律声明</template>
          加固功能将修改您上传的 APK(DEX/SO/Manifest)。您必须确认 APK 为您自有或已获合法授权。
          <strong>擅自上传他人 APK 由您个人承担法律责任。</strong>
        </NAlert>
        <NCheckbox v-model:checked="ownershipConfirmed">
          我确认此 APK 为我自有或已获合法授权(ADR 0097)
        </NCheckbox>

        <NDivider />
        <NSpace justify="space-between">
          <NButton @click="currentStep = 2">返回</NButton>
          <NButton type="primary" :loading="hardening" @click="startHardening">开始加固</NButton>
        </NSpace>
      </template>

      <!-- Step 4: 加固中(实时进度) -->
      <template v-if="currentStep === 4">
        <NCard size="small">
          <NSpace align="center" style="margin-bottom: 12px">
            <span style="font-size: 24px">{{ stepIcons[progressStep] || '⚙️' }}</span>
            <div>
              <NText strong>{{ progressMessage }}</NText>
              <br />
              <NText depth="3" style="font-size: 12px">{{ progressDetail }}</NText>
            </div>
          </NSpace>
          <NProgress
            type="line"
            :percentage="progressPercent"
            :status="progressPercent >= 100 ? 'success' : 'info'"
          />
        </NCard>

        <NAlert v-if="globalError" type="error" style="margin-top: 12px">
          {{ globalError }}
          <div style="margin-top: 8px">
            <NSpace :size="8">
              <NButton v-if="fileId && keystoreFile" size="small" type="warning" @click="retryHarden">重试加固</NButton>
              <NButton size="small" @click="resetAll">重新开始</NButton>
            </NSpace>
          </div>
        </NAlert>
      </template>

      <!-- Step 5: 完成 -->
      <template v-if="currentStep === 5">
        <NAlert type="success" style="margin-bottom: 16px">
          <template #header>加固完成!</template>
          已启用 {{ enabledCount }} 个加固模块,APK 已重签。
        </NAlert>
        <NSpace vertical :size="12">
          <NButton type="primary" size="large" block @click="downloadApk">下载加固后的 APK</NButton>
          <NButton block @click="resetAll">加固另一个 APK</NButton>
        </NSpace>
      </template>
    </NCard>
  </div>
</template>
