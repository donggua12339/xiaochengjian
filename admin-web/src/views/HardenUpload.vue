<script setup lang="ts">
/**
 * APK 加固上传页面
 *
 * 流程: 上传 APK → 分析 → 勾选加固模块 → 上传 Keystore → 执行加固 → 下载
 */

import { ref, computed } from 'vue';
import {
  NCard, NButton, NSpace, NUpload, NProgress, NTag, NText,
  NCheckbox, NCheckboxGroup, NGrid, NGi, NDivider, NAlert,
  NSelect, NInput, NSteps, NStep, NCollapse, NCollapseItem,
  NDataTable, useMessage, useDialog,
} from 'naive-ui';
import type { UploadFileInfo } from 'naive-ui';
import { analyzeApk, hardenApk, getHardeningStatus } from '@/api/hardening';
import type { ApkAnalysis, HardeningRequestConfig } from '@/api/hardening';

const message = useMessage();
const dialog = useDialog();

// ========== 步骤控制 ==========
const currentStep = ref(0); // 0=上传 1=配置 2=加固 3=完成

// ========== Step 0: 上传 ==========
const apkFile = ref<File | null>(null);
const analyzing = ref(false);
const analysis = ref<ApkAnalysis | null>(null);

async function handleApkUpload({ file }: { file: UploadFileInfo }) {
  if (!file.file) return;
  apkFile.value = file.file;
  analyzing.value = true;
  analysis.value = null;

  try {
    const res = await analyzeApk(file.file) as any;
    analysis.value = res.analysis;
    // 应用推荐配置
    applyRecommendedConfig(res.analysis.recommendedConfig);
    currentStep.value = 1;
    message.success('APK 分析完成');
  } catch (e: any) {
    message.error(`分析失败: ${e?.response?.data?.message || e.message}`);
  } finally {
    analyzing.value = false;
  }
}

// ========== Step 1: 加固配置 ==========
const productLine = ref<'xuanjia' | 'tianyan'>('xuanjia');
const preset = ref<string>('standard');

// 玄甲模块
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

// 天衍模块
const tianyanModules = ref<Record<string, boolean>>({
  t1_customLinker: true,
  t2_vmp: true,
  t3_segment: false,
  t4_dexStringEncrypt: false,
});

// Kill 策略
const killAction = ref('kill');
const weakThreshold = ref(70);

const presetOptions = [
  { label: '基础(核心防护)', value: 'basic' },
  { label: '标准(推荐)', value: 'standard' },
  { label: '激进(全模块)', value: 'aggressive' },
  { label: '偏执(最大防护)', value: 'paranoid' },
];

const xuanjiaLabels: Record<string, string> = {
  x0_soEncrypt: 'X0 SO 本体加密(RC4+memfd 加载)',
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

const presetDescriptions: Record<string, string> = {
  basic: 'SO 加密 + 反动态五层 + 生命周期检测。适合对包体积敏感的场景。',
  standard: '在基础上新增 VPN/双开/端口检测。覆盖常见攻击面。',
  aggressive: '全模块启用,含 FART/ODEX 扫描 + 字符串分段散列。',
  paranoid: '所有玄甲+天衍模块全开,含 DEX 字符串加密。最大化攻击成本。',
};

function applyRecommendedConfig(config: HardeningRequestConfig) {
  productLine.value = config.productLine;
  preset.value = config.preset ?? 'standard';
  if (config.xuanjia) xuanjiaModules.value = { ...xuanjiaModules.value, ...config.xuanjia };
  if (config.tianyan) tianyanModules.value = { ...tianyanModules.value, ...config.tianyan };
}

function onPresetChange(val: string) {
  // 根据预设批量设置模块开关
  const presets: Record<string, { x: Record<string, boolean>; t: Record<string, boolean> }> = {
    basic: {
      x: { x0_soEncrypt: true, x3_lifecycle: true, x4_antiDynamic: true, x5_vpnProxy: false, x6_dualApp: false, x7_privatePort: false, x8_fart: false, x9_odex: false },
      t: { t1_customLinker: true, t2_vmp: false, t3_segment: false, t4_dexStringEncrypt: false },
    },
    standard: {
      x: { x0_soEncrypt: true, x3_lifecycle: true, x4_antiDynamic: true, x5_vpnProxy: true, x6_dualApp: true, x7_privatePort: true, x8_fart: false, x9_odex: false },
      t: { t1_customLinker: true, t2_vmp: true, t3_segment: false, t4_dexStringEncrypt: false },
    },
    aggressive: {
      x: { x0_soEncrypt: true, x3_lifecycle: true, x4_antiDynamic: true, x5_vpnProxy: true, x6_dualApp: true, x7_privatePort: true, x8_fart: true, x9_odex: true },
      t: { t1_customLinker: true, t2_vmp: true, t3_segment: true, t4_dexStringEncrypt: false },
    },
    paranoid: {
      x: { x0_soEncrypt: true, x3_lifecycle: true, x4_antiDynamic: true, x5_vpnProxy: true, x6_dualApp: true, x7_privatePort: true, x8_fart: true, x9_odex: true },
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
  const t = productLine.value === 'tianyan' ? Object.values(tianyanModules.value).filter(Boolean).length : 0;
  return x + t;
});

// ========== Keystore ==========
const keystoreFile = ref<File | null>(null);
const ksPassword = ref('');
const ksAlias = ref('');
const ksKeyPassword = ref('');

function handleKeystoreUpload({ file }: { file: UploadFileInfo }) {
  if (file.file) keystoreFile.value = file.file;
}

// ========== Step 2: 加固执行 ==========
const hardening = ref(false);
const hardenProgress = ref(0);
const hardenMessage = ref('');
const taskId = ref('');

async function startHardening() {
  if (!apkFile.value) { message.error('请上传 APK'); return; }
  if (!ksPassword.value || !ksAlias.value || !ksKeyPassword.value) {
    message.error('请填写 Keystore 信息');
    return;
  }
  if (enabledCount.value === 0) {
    message.warning('请至少选择一个加固模块');
    return;
  }

  hardening.value = true;
  currentStep.value = 2;
  hardenProgress.value = 0;
  hardenMessage.value = '正在上传并加固...';

  try {
    const config: HardeningRequestConfig = {
      productLine: productLine.value,
      preset: preset.value as any,
      xuanjia: xuanjiaModules.value,
      ...(productLine.value === 'tianyan' ? { tianyan: tianyanModules.value } : {}),
      killPolicy: {
        strongEvidence: killAction.value as any,
        weakScoreThreshold: weakThreshold.value,
        delayMinMs: 0,
        delayMaxMs: 1000,
      },
    };

    const res = await hardenApk({
      apkFile: apkFile.value,
      keystoreFile: keystoreFile.value ?? undefined,
      keystorePassword: ksPassword.value,
      keyAlias: ksAlias.value,
      keyPassword: ksKeyPassword.value,
      config,
      analysis: analysis.value!,
    }) as any;

    taskId.value = res.taskId;

    // 轮询状态
    await pollStatus(res.taskId);
  } catch (e: any) {
    message.error(`加固失败: ${e?.response?.data?.message || e.message}`);
    hardening.value = false;
    currentStep.value = 1;
  }
}

async function pollStatus(tid: string) {
  const maxAttempts = 60;
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise((r) => setTimeout(r, 3000));
    try {
      const status = await getHardeningStatus(tid) as any;
      hardenProgress.value = status.progress;
      hardenMessage.value = status.message;

      if (status.status === 'completed') {
        hardening.value = false;
        currentStep.value = 3;
        message.success('加固完成!');
        return;
      }
      if (status.status === 'failed') {
        throw new Error(status.message);
      }
    } catch (e: any) {
      if (e.message?.includes('加固失败')) throw e;
      // 网络错误,继续轮询
    }
  }
  throw new Error('加固超时');
}

// ========== Step 3: 下载 ==========
function downloadApk() {
  if (!taskId.value) return;
  const baseURL = (import.meta.env.VITE_API_BASE_URL as string) || '/api/v1';
  const token = localStorage.getItem('access_token') || '';
  const url = `${baseURL}/hardening/download/${taskId.value}?token=${encodeURIComponent(token)}`;
  window.open(url, '_blank');
}

function resetAll() {
  currentStep.value = 0;
  apkFile.value = null;
  analysis.value = null;
  keystoreFile.value = null;
  ksPassword.value = '';
  ksAlias.value = '';
  ksKeyPassword.value = '';
  hardenProgress.value = 0;
  taskId.value = '';
}

// 不可用功能表
const unavailableColumns = [
  { title: '功能', key: 'feature' },
  { title: '原因', key: 'reason' },
];
</script>

<template>
  <div style="max-width: 900px; margin: 0 auto; padding: 24px">
    <NCard title="APK 加固">
      <!-- 步骤条 -->
      <NSteps :current="currentStep + 1" style="margin-bottom: 24px">
        <NStep title="上传 APK" description="分析结构" />
        <NStep title="选择模块" description="勾选加固功能" />
        <NStep title="执行加固" description="注入 + 重签" />
        <NStep title="下载" description="获取加固 APK" />
      </NSteps>

      <!-- Step 0: 上传 APK -->
      <template v-if="currentStep === 0">
        <NUpload
          :max="1"
          accept=".apk"
          :default-upload="false"
          @change="handleApkUpload"
          :show-file-list="true"
        >
          <NButton type="primary" :loading="analyzing">
            {{ analyzing ? '分析中...' : '选择 APK 文件' }}
          </NButton>
        </NUpload>

        <NAlert v-if="analyzing" type="info" style="margin-top: 16px">
          正在分析 APK 结构(DEX 文件、原生架构、Manifest 信息)...
        </NAlert>
      </template>

      <!-- Step 1: 配置模块 -->
      <template v-if="currentStep === 1 && analysis">
        <!-- APK 信息摘要 -->
        <NAlert type="success" style="margin-bottom: 16px">
          <template #header>APK 分析结果</template>
          包名: {{ analysis.packageName }} |
          DEX: {{ analysis.dexFiles.length }} 个 |
          ABI: {{ analysis.nativeAbis.join(', ') || '无' }} |
          大小: {{ (analysis.apkSize / 1024 / 1024).toFixed(1) }} MB |
          已加固: {{ analysis.alreadyHardened ? analysis.detectedHardener : '否' }}
        </NAlert>

        <!-- 已加固警告 -->
        <NAlert v-if="analysis.alreadyHardened" type="warning" style="margin-bottom: 16px">
          该 APK 已被 {{ analysis.detectedHardener }} 加固,建议先去除加固再使用玄甲/天衍。
        </NAlert>

        <!-- 不可用功能 -->
        <template v-if="analysis.unavailableFeatures.length > 0">
          <NAlert type="warning" style="margin-bottom: 16px">
            <template #header>以下功能不可用</template>
          </NAlert>
        </template>

        <!-- 产品线选择 -->
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
          <NText strong>强度预设:</NText>
          <NSelect
            v-model:value="preset"
            :options="presetOptions"
            style="width: 180px"
            @update:value="onPresetChange"
          />
        </NSpace>

        <NAlert :type="preset === 'paranoid' ? 'error' : preset === 'aggressive' ? 'warning' : 'info'" style="margin-bottom: 16px">
          {{ presetDescriptions[preset] }}
        </NAlert>

        <!-- 玄甲模块复选框 -->
        <NDivider title-placement="left">玄甲 X0-X9 模块</NDivider>
        <NGrid :cols="2" :x-gap="12" :y-gap="8">
          <NGi v-for="(label, key) in xuanjiaLabels" :key="key">
            <NCheckbox
              v-model:checked="xuanjiaModules[key]"
              :disabled="analysis.unavailableFeatures.some(f => f.feature === key || f.feature === 'all')"
            >
              {{ label }}
            </NCheckbox>
          </NGi>
        </NGrid>

        <!-- 天衍模块复选框 -->
        <template v-if="productLine === 'tianyan'">
          <NDivider title-placement="left">天衍 T1-T6 模块</NDivider>
          <NGrid :cols="2" :x-gap="12" :y-gap="8">
            <NGi v-for="(label, key) in tianyanLabels" :key="key">
              <NCheckbox v-model:checked="tianyanModules[key]">
                {{ label }}
              </NCheckbox>
            </NGi>
          </NGrid>
        </template>

        <NDivider />

        <!-- 启用统计 -->
        <NSpace justify="space-between" align="center">
          <NText>已启用 <NTag type="primary" size="small">{{ enabledCount }}</NTag> 个加固模块</NText>
          <NSpace>
            <NButton @click="currentStep = 0">重新上传</NButton>
            <NButton type="primary" :disabled="enabledCount === 0" @click="currentStep = 1.5">
              下一步: 签名配置
            </NButton>
          </NSpace>
        </NSpace>
      </template>

      <!-- Step 1.5: Keystore 配置(过渡) -->
      <template v-if="currentStep === 1.5">
        <NDivider title-placement="left">签名配置(自备 Keystore)</NDivider>
        <NAlert type="info" style="margin-bottom: 16px">
          加固后需使用您自备的 Keystore 重签 APK(合规要求:锁 4 签名锁定)。
        </NAlert>

        <NSpace vertical :size="12">
          <NUpload :max="1" accept=".jks,.keystore" :default-upload="false" @change="handleKeystoreUpload">
            <NButton>选择 Keystore 文件(.jks)</NButton>
          </NUpload>
          <NInput v-model:value="ksPassword" type="password" placeholder="Keystore 密码" show-password-on="click" />
          <NInput v-model:value="ksAlias" placeholder="Key 别名" />
          <NInput v-model:value="ksKeyPassword" type="password" placeholder="Key 密码" show-password-on="click" />
        </NSpace>

        <NDivider />
        <NSpace justify="space-between">
          <NButton @click="currentStep = 1">返回模块配置</NButton>
          <NButton type="primary" @click="startHardening" :loading="hardening">
            开始加固
          </NButton>
        </NSpace>
      </template>

      <!-- Step 2: 加固执行 -->
      <template v-if="currentStep === 2">
        <NCard size="small">
          <NText strong>{{ hardenMessage }}</NText>
          <NProgress
            type="line"
            :percentage="hardenProgress"
            :status="hardenProgress >= 100 ? 'success' : undefined"
            style="margin-top: 12px"
          />
        </NCard>
      </template>

      <!-- Step 3: 下载 -->
      <template v-if="currentStep === 3">
        <NAlert type="success" style="margin-bottom: 16px">
          <template #header>加固完成!</template>
          已启用 {{ enabledCount }} 个加固模块,APK 已使用您的 Keystore 重签。
        </NAlert>

        <NSpace vertical :size="12">
          <NButton type="primary" size="large" @click="downloadApk" block>
            下载加固后的 APK
          </NButton>
          <NButton @click="resetAll" block>加固另一个 APK</NButton>
        </NSpace>
      </template>
    </NCard>
  </div>
</template>
