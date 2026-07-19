<script setup lang="ts">
/**
 * SDK 配置 Tab(ADR 0068 / ADR 0071 / ADR 0073)
 *
 * 功能:
 *  - 3 个复选框:obfstr / opaque-jni / control-flow-flattening
 *  - 实时生成定制 Cargo.toml [features] 段 + 编译命令
 *  - 不提供编译服务(开发者自己编译,ADR 0068)
 *
 * 详见:
 *  - ADR 0071 · Rust 核心设计修订(obfstr / opaque-jni 可选 features)
 *  - ADR 0073 · SDK 控制流平坦化设计(control-flow-flattening 未来工作)
 */

import { ref, computed } from 'vue';
import {
  NCard,
  NCheckbox,
  NSpace,
  NCode,
  NButton,
  NAlert,
  NText,
  NDivider,
  useMessage,
} from 'naive-ui';

const message = useMessage();

// 3 个可选 features
const enableObfstr = ref(false);
const enableOpaqueJni = ref(false);
const enableControlFlowFlatten = ref(false);

// control-flow-flattening 是未来工作(ADR 0073),暂不可用
const cffAvailable = ref(false);

/**
 * 生成定制 Cargo.toml [features] 段
 */
const cargoFeatures = computed(() => {
  const lines: string[] = ['[features]'];
  lines.push('default = []  # 默认透明模式,无反逆向设施');

  if (enableObfstr.value) {
    lines.push('# 字符串混淆(编译时加密 URL/密钥/错误码)');
    lines.push('obfstr = ["dep:obfstr"]');
  }

  if (enableOpaqueJni.value) {
    lines.push('# JNI 函数名非语义化(native01-08 别名)');
    lines.push('opaque-jni = []');
  }

  if (enableControlFlowFlatten.value && cffAvailable.value) {
    lines.push('# 控制流平坦化(ADR 0073,需自定义 proc-macro)');
    lines.push('control-flow-flattening = []');
  }

  return lines.join('\n');
});

/**
 * 生成编译命令
 */
const buildCommand = computed(() => {
  const features: string[] = [];
  if (enableObfstr.value) features.push('obfstr');
  if (enableOpaqueJni.value) features.push('opaque-jni');
  if (enableControlFlowFlatten.value && cffAvailable.value) {
    features.push('control-flow-flattening');
  }

  const featureFlag = features.length > 0 ? ` --features ${features.join(',')}` : '';

  return [
    '# 编译 3 ABI so(arm64-v8a / armeabi-v7a / x86_64)',
    `cargo build --release${featureFlag} --target aarch64-linux-android`,
    `cargo build --release${featureFlag} --target armv7-linux-androideabi`,
    `cargo build --release${featureFlag} --target x86_64-linux-android`,
    '',
    '# 复制 so 到 jniLibs',
    'cp target/aarch64-linux-android/release/libxcj_core.so \\',
    '   sdk-android/kotlin/xcj-sdk/src/main/jniLibs/arm64-v8a/',
    'cp target/armv7-linux-androideabi/release/libxcj_core.so \\',
    '   sdk-android/kotlin/xcj-sdk/src/main/jniLibs/armeabi-v7a/',
    'cp target/x86_64-linux-android/release/libxcj_core.so \\',
    '   sdk-android/kotlin/xcj-sdk/src/main/jniLibs/x86_64/',
    '',
    '# 构建 AAR',
    'cd sdk-android/kotlin && ./gradlew :xcj-sdk:assembleRelease',
  ].join('\n');
});

/**
 * 当前选中的 features 摘要
 */
const selectedSummary = computed(() => {
  const list: string[] = [];
  if (enableObfstr.value) list.push('obfstr(字符串混淆)');
  if (enableOpaqueJni.value) list.push('opaque-jni(JNI 非语义化)');
  if (enableControlFlowFlatten.value && cffAvailable.value) {
    list.push('control-flow-flattening(控制流平坦化)');
  }
  return list.length === 0 ? '无(默认透明模式)' : list.join(' + ');
});

/**
 * 风险提示
 */
const warnings = computed(() => {
  const warns: string[] = [];
  if (enableObfstr.value) {
    warns.push('obfstr:编译时加密常量,轻微影响启动性能(~5ms)');
  }
  if (enableOpaqueJni.value) {
    warns.push('opaque-jni:符号表看不到语义,但开源审计时需额外对照表');
  }
  if (enableControlFlowFlatten.value && !cffAvailable.value) {
    warns.push('control-flow-flattening:ADR 0073 未来工作,当前不可用');
  }
  return warns;
});

function copyToClipboard(text: string, label: string) {
  navigator.clipboard
    .writeText(text)
    .then(() => message.success(`${label} 已复制到剪贴板`))
    .catch(() => message.error('复制失败,请手动选择复制'));
}

function selectAll() {
  enableObfstr.value = true;
  enableOpaqueJni.value = true;
  if (cffAvailable.value) {
    enableControlFlowFlatten.value = true;
  }
}

function resetAll() {
  enableObfstr.value = false;
  enableOpaqueJni.value = false;
  enableControlFlowFlatten.value = false;
}
</script>

<template>
  <div>
    <h2>SDK 配置</h2>
    <NText depth="3" style="margin-bottom: 16px; display: block">
      按需勾选反逆向 features,生成定制 Cargo.toml + 编译命令。不提供编译服务(ADR 0068),开发者自行编译。
    </NText>

    <!-- 1. Feature 选择 -->
    <NCard title="1. 选择反逆向 features" size="small" style="margin-bottom: 16px">
      <NSpace vertical :size="12">
        <NCheckbox v-model:checked="enableObfstr">
          <strong>obfstr</strong> - 字符串混淆(编译时加密 URL/密钥/错误码,ADR 0071)
        </NCheckbox>
        <NText depth="3" style="font-size: 12px; padding-left: 24px">
          启用后 RSA 公钥指纹 / 错误信息 / URL 等常量在编译产物中不可直接搜索
        </NText>

        <NDivider style="margin: 4px 0" />

        <NCheckbox v-model:checked="enableOpaqueJni">
          <strong>opaque-jni</strong> - JNI 函数名非语义化(ADR 0071)
        </NCheckbox>
        <NText depth="3" style="font-size: 12px; padding-left: 24px">
          启用后额外导出 native01-08 别名,Kotlin 侧可用非语义化声明(语义化命名仍保留)
        </NText>

        <NDivider style="margin: 4px 0" />

        <NCheckbox v-model:checked="enableControlFlowFlatten" :disabled="!cffAvailable">
          <strong>control-flow-flattening</strong> - 控制流平坦化(ADR 0073)
          <NText v-if="!cffAvailable" depth="3" style="font-size: 12px">
            (未来工作,当前不可用)
          </NText>
        </NCheckbox>
        <NText depth="3" style="font-size: 12px; padding-left: 24px">
          启用后核心加密函数(if/else/loop)转为 state machine,逆向难度显著提升(性能开销 10-30%)
        </NText>
      </NSpace>

      <NSpace style="margin-top: 16px">
        <NButton size="small" @click="selectAll">全选(可用项)</NButton>
        <NButton size="small" quaternary @click="resetAll">重置</NButton>
      </NSpace>
    </NCard>

    <!-- 2. 风险提示 -->
    <NAlert
      v-if="warnings.length > 0"
      type="warning"
      title="启用风险提示"
      style="margin-bottom: 16px"
    >
      <ul style="margin: 0; padding-left: 20px">
        <li v-for="w in warnings" :key="w">{{ w }}</li>
      </ul>
    </NAlert>

    <!-- 3. 当前选中摘要 -->
    <NCard title="2. 当前选中" size="small" style="margin-bottom: 16px">
      <NText>{{ selectedSummary }}</NText>
    </NCard>

    <!-- 4. 生成的 Cargo.toml -->
    <NCard title="3. 定制 Cargo.toml [features] 段" size="small" style="margin-bottom: 16px">
      <NText depth="3" style="font-size: 12px; display: block; margin-bottom: 8px">
        替换 <code>sdk-android/rust/xcj-core/Cargo.toml</code> 的 [features] 段
      </NText>
      <NCode :code="cargoFeatures" language="toml" />
      <NButton
        size="small"
        style="margin-top: 8px"
        @click="copyToClipboard(cargoFeatures, 'Cargo.toml [features]')"
      >
        复制到剪贴板
      </NButton>
    </NCard>

    <!-- 5. 编译命令 -->
    <NCard title="4. 编译命令" size="small" style="margin-bottom: 16px">
      <NText depth="3" style="font-size: 12px; display: block; margin-bottom: 8px">
        前置依赖:Rust stable + Android NDK r27(详见 docs/sdk-integration.md)
      </NText>
      <NCode :code="buildCommand" language="bash" />
      <NButton
        size="small"
        style="margin-top: 8px"
        @click="copyToClipboard(buildCommand, '编译命令')"
      >
        复制到剪贴板
      </NButton>
    </NCard>

    <!-- 6. 说明 -->
    <NAlert type="info" title="说明" style="margin-bottom: 16px">
      <ul style="margin: 0; padding-left: 20px">
        <li>默认透明模式(无 feature)即可用于生产,反逆向 features 是可选项</li>
        <li>反逆向 features 与开源哲学(ADR 0042)平衡:架构公开,实现保留</li>
        <li>服务端验证是权威(ADR 0019),客户端任何 patch 最终都要回服务端验证</li>
        <li>详见 ADR 0071(Rust 核心设计修订)+ ADR 0073(控制流平坦化设计)</li>
      </ul>
    </NAlert>
  </div>
</template>
