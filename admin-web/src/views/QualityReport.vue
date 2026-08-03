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

import { ref, computed, onMounted } from 'vue';
import {
  NCard,
  NButton,
  NInput,
  NSpace,
  NSelect,
  NTag,
  NProgress,
  NGrid,
  NGi,
  NAlert,
  NDivider,
  NText,
  useMessage,
} from 'naive-ui';
import { getQualityReports, submitQualityReport, type QualityReportItem } from '@/api/harden';
import { appsApi } from '@/api/apps';

const message = useMessage();
const jsonInput = ref('');

/** 单个评分维度(与 DimensionResult 对齐) */
interface ReportDimension {
  score: number;
  maxScore: number;
  details?: string[];
  hits?: number;
}

/** 前端解析的加固质量报告(JSON 结构,字段与 submitToServer 对齐) */
interface ParsedReport {
  overallScore: number;
  grade: string;
  stringResidual?: ReportDimension;
  soEncryption?: ReportDimension;
  detectionModules?: ReportDimension;
  signature?: ReportDimension;
  debuggable?: ReportDimension;
  [key: string]: unknown;
}
const report = ref<ParsedReport | null>(null);

// API 联动
const apps = ref<{ label: string; value: string }[]>([]);
const selectedAppId = ref<string | null>(null);
const historyReports = ref<QualityReportItem[]>([]);

onMounted(async () => {
  try {
    const list = await appsApi.list();
    apps.value = list.map((a) => ({
      label: `${a.name} (${a.packageName})`,
      value: a.id,
    }));
  } catch {
    /* ignore */
  }
});

async function loadHistory() {
  if (!selectedAppId.value) return;
  try {
    historyReports.value = await getQualityReports(selectedAppId.value);
  } catch {
    /* ignore */
  }
}

async function submitToServer() {
  if (!selectedAppId.value || !report.value) {
    message.warning('请先选择应用并解析报告');
    return;
  }
  try {
    await submitQualityReport(selectedAppId.value, {
      overallScore: report.value.overallScore,
      grade: report.value.grade,
      dimensions: {
        stringResidual: report.value.stringResidual,
        soEncryption: report.value.soEncryption,
        detectionModules: report.value.detectionModules,
        signature: report.value.signature,
        debuggable: report.value.debuggable,
      },
      raw: report.value,
    });
    message.success('报告已提交');
    await loadHistory();
  } catch {
    message.error('提交失败');
  }
}

interface DimensionResult {
  score: number;
  maxScore: number;
  details?: string[];
  hits?: number;
}

function parseReport() {
  try {
    const data = JSON.parse(jsonInput.value) as ParsedReport;
    report.value = data;
    message.success('报告解析成功');
  } catch (e: unknown) {
    message.error(`JSON 解析失败: ${e instanceof Error ? e.message : String(e)}`);
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
      dims.push({ name: key, label, data: report.value[key] as DimensionResult });
    }
  }
  return dims;
});

const suggestions = computed(() => {
  const tips: string[] = [];
  if (!report.value) return tips;
  const r = report.value;
  if ((r.stringResidual?.hits ?? 0) > 0) {
    tips.push(`发现 ${r.stringResidual?.hits} 处明文字符串残留 → 运行 T4 encrypt-strings 加密`);
  }
  if ((r.soEncryption?.score ?? 0) < (r.soEncryption?.maxScore ?? 0)) {
    tips.push('SO 未加密 → 运行 build_x0_pack.py 加密 libxcj_defender.so');
  }
  if ((r.detectionModules?.score ?? 0) < (r.detectionModules?.maxScore ?? 0)) {
    tips.push('检测模块未全开 → 在 HardenConfig 页面启用所有模块');
  }
  if ((r.signature?.score ?? 0) < (r.signature?.maxScore ?? 0)) {
    tips.push('签名不完整 → 使用 xcj-injector sign 重签 APK');
  }
  if ((r.debuggable?.score ?? 0) < (r.debuggable?.maxScore ?? 0)) {
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
      <!-- 应用选择 -->
      <NSpace align="center" style="margin-bottom: 16px">
        <NSelect
          v-model:value="selectedAppId"
          :options="apps"
          placeholder="选择应用"
          style="width: 300px"
          @update:value="loadHistory"
        />
        <NButton :disabled="!report" @click="submitToServer">提交到服务器</NButton>
      </NSpace>
      <NDivider />

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
                  :type="
                    dim.data.score >= dim.data.maxScore
                      ? 'success'
                      : dim.data.score > 0
                        ? 'warning'
                        : 'error'
                  "
                  size="small"
                >
                  {{ dim.data.score }} / {{ dim.data.maxScore }}
                </NTag>
              </NSpace>
              <NProgress
                :percentage="
                  dim.data.maxScore > 0 ? Math.round((dim.data.score / dim.data.maxScore) * 100) : 0
                "
                :show-indicator="false"
                :height="6"
                style="margin-top: 8px"
              />
              <div v-if="dim.data.details?.length" style="margin-top: 8px">
                <NText
                  v-for="(d, i) in dim.data.details"
                  :key="i"
                  depth="3"
                  style="font-size: 12px"
                >
                  {{ d }}
                  <br />
                </NText>
              </div>
            </NCard>
          </NGi>
        </NGrid>

        <!-- 改进建议 -->
        <NDivider title-placement="left">改进建议</NDivider>
        <NAlert
          v-for="(tip, i) in suggestions"
          :key="i"
          :type="overallScore >= 90 ? 'success' : 'warning'"
          style="margin-bottom: 8px"
        >
          {{ tip }}
        </NAlert>
      </template>

      <!-- 历史记录 -->
      <template v-if="historyReports.length > 0">
        <NDivider title-placement="left">历史报告</NDivider>
        <NGrid :cols="1" :y-gap="8">
          <NGi v-for="r in historyReports" :key="r.id">
            <NSpace align="center" justify="space-between">
              <NSpace align="center">
                <NTag
                  :type="
                    r.grade === 'A'
                      ? 'success'
                      : r.grade === 'B'
                        ? 'info'
                        : r.grade === 'C'
                          ? 'warning'
                          : 'error'
                  "
                  size="small"
                >
                  {{ r.grade }}
                </NTag>
                <NText>{{ r.overallScore }}%</NText>
                <NText depth="3" style="font-size: 12px">
                  {{ new Date(r.createdAt).toLocaleString() }}
                </NText>
              </NSpace>
            </NSpace>
          </NGi>
        </NGrid>
      </template>
    </NCard>
  </div>
</template>
