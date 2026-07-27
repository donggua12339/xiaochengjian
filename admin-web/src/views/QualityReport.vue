<script setup lang="ts">
/**
 * 加固质量报告可视化页面(天衍 T6 配套)
 *
 * 功能:
 *  - 粘贴/上传 quality_report.json 展示 5 维评分雷达图
 *  - 等级展示(A/B/C/D)
 *  - 各维度详情(得分/满分/说明)
 *  - 改进建议
 */

import { ref, computed } from 'vue';
import {
  NCard,
  NButton,
  NInput,
  NSpace,
  NTag,
  NProgress,
  NGrid,
  NGi,
  NAlert,
  NDivider,
  NText,
  NCollapse,
  NCollapseItem,
  useMessage,
} from 'naive-ui';

const message = useMessage();
const jsonInput = ref('');
const report = ref<any>(null);

interface DimensionResult {
  score: number;
  maxScore: number;
  details?: string[];
  hits?: number;
}

function parseReport() {
  try {
    const data = JSON.parse(jsonInput.value);
    report.value = data;
    message.success('报告解析成功');
  } catch (e: any) {
    message.error('JSON 解析失败: ' + e.message);
  }
}

function handleFileUpload(e: Event) {
  const target = e.target as HTMLInputElement;
  const file = target.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    jsonInput.value = reader.result as string;
    parseReport();
  };
  reader.readAsText(file);
}

const grade = computed(() => report.value?.grade ?? '-');
const overallScore = computed(() => report.value?.overallScore ?? 0);

const gradeType = computed(() => {
  const g = grade.value;
  if (g === 'A') return 'success';
  if (g === 'B') return 'info';
  if (g === 'C') return 'warning';
  return 'error';
});

const dimensions = computed(() => {
  if (!report.value) return [];
  const dims: { name: string; label: string; data: DimensionResult }[] = [];
  const map: Record<string, string> = {
    stringResidual: '字符串残留',
    soEncryption: 'SO 加密状态',
    detectionModules: '检测模块覆盖',
    signature: '签名完整性',
    debuggable: '调试标志',
  };
  for (const [key, label] of Object.entries(map)) {
    if (report.value[key]) {
      dims.push({ name: key, label, data: report.value[key] });
    }
  }
  return dims;
});

const suggestions = computed(() => {
  const tips: string[] = [];
  if (!report.value) return tips;
  const r = report.value;
  if (r.stringResidual?.hits > 0) {
    tips.push(`发现 ${r.stringResidual.hits} 处明文字符串残留 → 运行 T4 encrypt-strings 加密`);
  }
  if (r.soEncryption?.score < r.soEncryption?.maxScore) {
    tips.push('SO 未加密 → 运行 build_x0_pack.py 加密 libxcj_defender.so');
  }
  if (r.detectionModules?.score < r.detectionModules?.maxScore) {
    tips.push('检测模块未全开 → 在 HardenConfig 页面启用所有模块');
  }
  if (r.signature?.score < r.signature?.maxScore) {
    tips.push('签名不完整 → 使用 xcj-injector sign 重签 APK');
  }
  if (r.debuggable?.score < r.debuggable?.maxScore) {
    tips.push('APK 可调试 → 确保 release 构建 isMinifyEnabled=true');
  }
  if (tips.length === 0 && overallScore.value >= 90) {
    tips.push('️ 加固质量优秀,无改进建议');
  }
  return tips;
});
</script>

<template>
  <div style="max-width: 800px; margin: 0 auto; padding: 24px">
    <NCard title="加固质量报告(天衍 T6)">
      <!-- 输入区 -->
      <NSpace vertical :size="12">
        <NText depth="3">粘贴 quality_report.json 内容或上传文件:</NText>
        <NInput
          v-model:value="jsonInput"
          type="textarea"
          placeholder='{"overallScore": 70, "grade": "C", ...}'
          :rows="4"
        />
        <NSpace>
          <NButton type="primary" @click="parseReport">解析报告</NButton>
          <NButton tag="label">
            上传文件
            <input type="file" accept=".json" hidden @change="handleFileUpload" />
          </NButton>
        </NSpace>
      </NSpace>

      <!-- 报告展示 -->
      <template v-if="report">
        <NDivider />

        <!-- 总评 -->
        <NSpace align="center" :size="24" justify="center" style="margin: 16px 0">
          <NTag :type="gradeType" size="large" round style="font-size: 32px; padding: 8px 24px">
            {{ grade }}
          </NTag>
          <div>
            <NText style="font-size: 24px; font-weight: bold">{{ overallScore }}%</NText>
            <br />
            <NText depth="3">加固质量评分</NText>
          </div>
        </NSpace>

        <NProgress
          type="line"
          :percentage="overallScore"
          :status="overallScore >= 90 ? 'success' : overallScore >= 60 ? 'warning' : 'error'"
          :height="12"
          style="margin-bottom: 24px"
        />

        <!-- 各维度 -->
        <NGrid :cols="1" :y-gap="12">
          <NGi v-for="dim in dimensions" :key="dim.name">
            <NCard size="small">
              <NSpace justify="space-between" align="center">
                <NText strong>{{ dim.label }}</NText>
                <NTag
                  :type="dim.data.score >= dim.data.maxScore ? 'success' : dim.data.score > 0 ? 'warning' : 'error'"
                  size="small"
                >
                  {{ dim.data.score }} / {{ dim.data.maxScore }}
                </NTag>
              </NSpace>
              <NProgress
                :percentage="dim.data.maxScore > 0 ? Math.round((dim.data.score / dim.data.maxScore) * 100) : 0"
                :show-indicator="false"
                :height="6"
                style="margin-top: 8px"
              />
              <div v-if="dim.data.details?.length" style="margin-top: 8px">
                <NText depth="3" style="font-size: 12px" v-for="(d, i) in dim.data.details" :key="i">
                  {{ d }}<br />
                </NText>
              </div>
            </NCard>
          </NGi>
        </NGrid>

        <!-- 改进建议 -->
        <NDivider title-placement="left">改进建议</NDivider>
        <NAlert v-for="(tip, i) in suggestions" :key="i" :type="overallScore >= 90 ? 'success' : 'warning'" style="margin-bottom: 8px">
          {{ tip }}
        </NAlert>
      </template>
    </NCard>
  </div>
</template>
