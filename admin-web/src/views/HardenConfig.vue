<script setup lang="ts">
/**
 * 加固配置页面(天衍 T5)
 *
 * 功能:
 *  - 可视化配置加固策略(检测模块开关 / 加密选项 / kill 策略 / 强度档位)
 *  - 实时生成 harden.json(供 xcj-injector harden --config 使用)
 *  - 实时生成 defender-config.json(供 SDK 运行时读取)
 *  - 提供 CLI 命令一键复制
 */

import { ref, computed, onMounted } from 'vue';
import {
  NCard,
  NSwitch,
  NSpace,
  NCode,
  NButton,
  NSelect,
  NInputNumber,
  NDivider,
  NText,
  NGrid,
  NGi,
  NTag,
  useMessage,
} from 'naive-ui';

const message = useMessage();

// API 联动
import { getHardenConfig, saveHardenConfig } from '@/api/harden';
import { appsApi } from '@/api/apps';

const apps = ref<{ label: string; value: string }[]>([]);
const selectedAppId = ref<string | null>(null);
const loading = ref(false);

onMounted(async () => {
  try {
    const list = await appsApi.list();
    apps.value = (list as any[]).map((a: any) => ({ label: `${a.name} (${a.packageName})`, value: a.id }));
  } catch { /* ignore */ }
});

async function loadConfig() {
  if (!selectedAppId.value) return;
  loading.value = true;
  try {
    const c = await getHardenConfig(selectedAppId.value) as any;
    encryptStrings.value = c.encryptStrings ?? true;
    vmpProtect.value = c.vmpProtect ?? true;
    segmentStrings.value = c.segmentStrings ?? false;
    soEncrypt.value = c.soEncrypt ?? true;
    strength.value = c.strength ?? 'standard';
    killAction.value = c.killAction ?? 'kill';
    weakThreshold.value = c.weakThreshold ?? 70;
    delayMin.value = c.delayMinMs ?? 0;
    delayMax.value = c.delayMaxMs ?? 1000;
    if (c.detectionModules) {
      for (const [k, v] of Object.entries(c.detectionModules)) {
        if (k in modules.value) (modules.value as any)[k] = v;
      }
    }
    message.success('配置已加载');
  } catch {
    message.error('加载配置失败');
  } finally {
    loading.value = false;
  }
}

async function saveConfig() {
  if (!selectedAppId.value) { message.warning('请先选择应用'); return; }
  try {
    await saveHardenConfig(selectedAppId.value, {
      encryptStrings: encryptStrings.value,
      vmpProtect: vmpProtect.value,
      segmentStrings: segmentStrings.value,
      soEncrypt: soEncrypt.value,
      detectionModules: modules.value,
      killAction: killAction.value,
      weakThreshold: weakThreshold.value,
      delayMinMs: delayMin.value,
      delayMaxMs: delayMax.value,
      strength: strength.value,
    });
    message.success('配置已保存');
  } catch {
    message.error('保存失败');
  }
}

// 加固强度
const strength = ref('standard');
const strengthOptions = [
  { label: '标准(推荐)', value: 'standard' },
  { label: '激进(高对抗)', value: 'aggressive' },
  { label: '偏执(最大防护)', value: 'paranoid' },
];

// 加密选项
const encryptStrings = ref(true);
const vmpProtect = ref(true);
const segmentStrings = ref(false);
const soEncrypt = ref(true);

// 检测模块
const modules = ref({
  antiDebug: true,
  antiFrida: true,
  antiDump: true,
  rootDetect: true,
  xposedDetect: true,
  emulatorDetect: false,
  vpnDetect: true,
  dualAppDetect: true,
  fartDetect: false,
  odexDetect: false,
});

const moduleLabels: Record<string, string> = {
  antiDebug: 'L2 反调试',
  antiFrida: 'Frida 检测',
  antiDump: 'L3 反 dump',
  rootDetect: 'Root 检测',
  xposedDetect: 'Xposed 检测',
  emulatorDetect: '模拟器检测',
  vpnDetect: 'X5 VPN/代理',
  dualAppDetect: 'X6 双开/分身',
  fartDetect: 'X8 FART 脱壳',
  odexDetect: 'X9 ODEX 修补',
};

// Kill 策略
const killAction = ref('kill');
const weakThreshold = ref(70);
const delayMin = ref(0);
const delayMax = ref(1000);

// 生成 harden.json
const hardenJson = computed(() => {
  return JSON.stringify({
    encryptStrings: encryptStrings.value,
    vmpProtect: vmpProtect.value,
    segmentStrings: segmentStrings.value,
    soEncrypt: soEncrypt.value,
    detectionModules: modules.value,
    killPolicy: {
      strongEvidence: killAction.value,
      weakScoreThreshold: weakThreshold.value,
      delayMinMs: delayMin.value,
      delayMaxMs: delayMax.value,
    },
    strength: strength.value,
  }, null, 2);
});

// 生成 CLI 命令
const cliCommand = computed(() => {
  return `xcj-injector harden --apk your-app.apk --config harden.json --output hardened.apk`;
});

function copyConfig() {
  navigator.clipboard.writeText(hardenJson.value);
  message.success('harden.json 已复制到剪贴板');
}

function copyCommand() {
  navigator.clipboard.writeText(cliCommand.value);
  message.success('CLI 命令已复制');
}

function applyPreset(val: string) {
  if (val === 'aggressive' || val === 'paranoid') {
    modules.value.fartDetect = true;
    modules.value.odexDetect = true;
    modules.value.emulatorDetect = true;
    delayMin.value = 0;
    delayMax.value = 500;
  }
  if (val === 'paranoid') {
    segmentStrings.value = true;
    weakThreshold.value = 50;
  }
}
</script>

<template>
  <div style="max-width: 900px; margin: 0 auto; padding: 24px">
    <NCard title="加固策略配置(天衍 T5)">
      <!-- 应用选择 + 加载/保存 -->
      <NSpace align="center" style="margin-bottom: 16px">
        <NSelect
          v-model:value="selectedAppId"
          :options="apps"
          placeholder="选择应用"
          style="width: 300px"
          @update:value="loadConfig"
        />
        <NButton type="primary" :loading="loading" @click="saveConfig">保存到服务器</NButton>
      </NSpace>
      <NDivider />
      <template #header-extra>
        <NTag :type="strength === 'paranoid' ? 'error' : strength === 'aggressive' ? 'warning' : 'success'">
          {{ strength }}
        </NTag>
      </template>

      <!-- 强度档位 -->
      <NText strong>强度档位</NText>
      <NSelect
        v-model:value="strength"
        :options="strengthOptions"
        style="margin: 8px 0 16px"
        @update:value="applyPreset"
      />

      <!-- 加密选项 -->
      <NDivider title-placement="left">加密选项</NDivider>
      <NSpace vertical>
        <NSwitch v-model:value="encryptStrings">
          <template #checked>T4 DEX 字符串加密 ✓</template>
          <template #unchecked>T4 DEX 字符串加密</template>
        </NSwitch>
        <NSwitch v-model:value="vmpProtect">
          <template #checked>T2 VMP 保护解密函数 ✓</template>
          <template #unchecked>T2 VMP 保护解密函数</template>
        </NSwitch>
        <NSwitch v-model:value="segmentStrings">
          <template #checked>T3 字符串分段散列 ✓</template>
          <template #unchecked>T3 字符串分段散列</template>
        </NSwitch>
        <NSwitch v-model:value="soEncrypt">
          <template #checked>X0 SO 本体加密 ✓</template>
          <template #unchecked>X0 SO 本体加密</template>
        </NSwitch>
      </NSpace>

      <!-- 检测模块 -->
      <NDivider title-placement="left">检测模块</NDivider>
      <NGrid :cols="2" :x-gap="12" :y-gap="8">
        <NGi v-for="(label, key) in moduleLabels" :key="key">
          <NSwitch v-model:value="modules[key as keyof typeof modules]" size="small">
            <template #checked>{{ label }} ✓</template>
            <template #unchecked>{{ label }}</template>
          </NSwitch>
        </NGi>
      </NGrid>

      <!-- Kill 策略 -->
      <NDivider title-placement="left">响应策略</NDivider>
      <NSpace align="center" :wrap="true">
        <NText>强证据响应:</NText>
        <NSelect
          v-model:value="killAction"
          :options="[
            { label: 'Kill(终止进程)', value: 'kill' },
            { label: 'Warn(仅告警)', value: 'warn' },
            { label: 'None(静默)', value: 'none' },
          ]"
          style="width: 160px"
        />
        <NText>弱信号阈值:</NText>
        <NInputNumber v-model:value="weakThreshold" :min="30" :max="100" style="width: 100px" />
        <NText>Kill 延迟(ms):</NText>
        <NInputNumber v-model:value="delayMin" :min="0" :max="5000" style="width: 90px" />
        <NText>~</NText>
        <NInputNumber v-model:value="delayMax" :min="0" :max="15000" style="width: 90px" />
      </NSpace>

      <!-- 输出 -->
      <NDivider title-placement="left">生成配置</NDivider>
      <NSpace>
        <NButton type="primary" @click="copyConfig">复制 harden.json</NButton>
        <NButton @click="copyCommand">复制 CLI 命令</NButton>
      </NSpace>
      <NCode :code="hardenJson" language="json" style="margin-top: 12px" />
    </NCard>
  </div>
</template>
