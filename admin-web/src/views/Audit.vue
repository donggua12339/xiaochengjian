<script setup lang="ts">
/**
 * 自有 APK 诊断 Tab(ADR 0077)
 *
 * 3 个子功能(NTabs):
 *  - 诊断(只读):上传 APK -> 三重校验 + 报告展示
 *  - 签名回填:上传 APK + keystore -> 重签 + 下载新 APK
 *  - 历史:查询本人诊断 / 回填记录
 *
 * 红线(ADR 0077 §2.1 例外 A):
 *  - 签名回填仅修改 META-INF/,不动 dex/resource/manifest
 *  - 必须使用开发者自有 keystore(无默认)
 *  - 回填后 hash 自动入白名单
 *  - 三重校验前置(后端强制,前端不绕过)
 */

import { ref, h, onMounted, computed } from 'vue';
import {
  NCard, NTabs, NTabPane, NUpload, NButton, NSpace, NText, NAlert,
  NForm, NFormItem, NInput, NTag, NDataTable, NCode,
  NSpin, NDescriptions, NDescriptionsItem, NPopconfirm,
  NSelect, NModal,
  useMessage, type UploadFileInfo, type DataTableColumns,
} from 'naive-ui';
import { auditApi, type AuditLogOwnItem, type AnalyzeReport, type ResignResponse, type WatermarkTraceResponse } from '@/api/audit';
import { useAuthStore } from '@/stores/auth';

const message = useMessage();
const auth = useAuthStore();
const isAdmin = computed(() => auth.developer?.role === 'ADMIN');

// ============= 诊断 Tab =============
const analyzeApkFile = ref<File | null>(null);
const analyzing = ref(false);
const analyzeReport = ref<AnalyzeReport | null>(null);
const hardenerSelect = ref<'none' | 'bangcle'>('none');

// 梆梆 EULA(锁 B 前置)
const eulaInfo = ref<{ version: string; text: string; effectiveDate: string } | null>(null);
const eulaAccepted = ref(false);
const eulaLoading = ref(false);
const showEulaModal = ref(false);

async function loadEula() {
  try {
    eulaInfo.value = await auditApi.getEula();
    eulaAccepted.value = false;
  } catch (error) {
    // EULA 加载失败不阻塞诊断 Tab(只影响梆梆自检)
  }
}

async function acceptEula() {
  if (!eulaInfo.value) return;
  eulaLoading.value = true;
  try {
    await auditApi.acceptEula(eulaInfo.value.version);
    eulaAccepted.value = true;
    showEulaModal.value = false;
    message.success(`EULA v${eulaInfo.value.version} 已接受,可使用梆梆自检`);
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    eulaLoading.value = false;
  }
}

function handleAnalyzeFileChange(data: { fileList: UploadFileInfo[] }) {
  const file = data.fileList[0]?.file;
  analyzeApkFile.value = file ?? null;
  analyzeReport.value = null;
}

async function doAnalyze() {
  if (!analyzeApkFile.value) {
    message.warning('请先选择 APK 文件');
    return;
  }
  // 梆梆自检:EULA 前置验证(锁 B)
  if (hardenerSelect.value === 'bangcle') {
    if (!eulaAccepted.value) {
      showEulaModal.value = true;
      return;
    }
  }

  analyzing.value = true;
  analyzeReport.value = null;
  try {
    const result = hardenerSelect.value === 'bangcle'
      ? await auditApi.analyzeBangcle(analyzeApkFile.value)
      : await auditApi.analyze(analyzeApkFile.value);
    analyzeReport.value = result.report;
    message.success(hardenerSelect.value === 'bangcle' ? '梆梆自检完成' : '诊断完成');
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    analyzing.value = false;
  }
}

// ============= 签名回填 Tab =============
const resignApkFile = ref<File | null>(null);
const resignKeystoreFile = ref<File | null>(null);
const resignCredentials = ref({
  keystorePassword: '',
  keyAlias: '',
  keyPassword: '',
});
const resigning = ref(false);
const resignResult = ref<ResignResponse | null>(null);

function handleResignApkChange(data: { fileList: UploadFileInfo[] }) {
  const file = data.fileList[0]?.file;
  resignApkFile.value = file ?? null;
  resignResult.value = null;
}

function handleKeystoreChange(data: { fileList: UploadFileInfo[] }) {
  const file = data.fileList[0]?.file;
  resignKeystoreFile.value = file ?? null;
}

async function doResign() {
  if (!resignApkFile.value) {
    message.warning('请选择 APK 文件');
    return;
  }
  if (!resignKeystoreFile.value) {
    message.warning('请选择 keystore 文件');
    return;
  }
  if (!resignCredentials.value.keystorePassword ||
      !resignCredentials.value.keyAlias ||
      !resignCredentials.value.keyPassword) {
    message.warning('请填写 keystore 密码 / key 别名 / key 密码');
    return;
  }
  resigning.value = true;
  resignResult.value = null;
  try {
    const result = await auditApi.resign(
      resignApkFile.value,
      resignKeystoreFile.value,
      resignCredentials.value,
    );
    resignResult.value = result;
    message.success('签名回填完成,新 hash 已自动入白名单');
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    resigning.value = false;
  }
}

function downloadResignedApk() {
  if (!resignResult.value) return;
  // base64 -> blob -> 下载
  const byteChars = atob(resignResult.value.resignedApkBase64);
  const byteNumbers = new Array(byteChars.length);
  for (let i = 0; i < byteChars.length; i++) {
    byteNumbers[i] = byteChars.charCodeAt(i);
  }
  const byteArray = new Uint8Array(byteNumbers);
  const blob = new Blob([byteArray], { type: 'application/vnd.android.package-archive' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  // 去掉 .apk 扩展名后加 -resigned.apk
  const originalName = resignApkFile.value?.name ?? 'resigned.apk';
  const baseName = originalName.replace(/\.apk$/i, '');
  a.download = `${baseName}-resigned.apk`;
  a.click();
  URL.revokeObjectURL(url);
}

// ============= 历史 Tab =============
const historyLoading = ref(false);
const historyLogs = ref<AuditLogOwnItem[]>([]);
const historyLimit = ref(50);
const historyOffset = ref(0);

async function loadHistory() {
  historyLoading.value = true;
  try {
    historyLogs.value = await auditApi.listLogs({
      limit: historyLimit.value,
      offset: historyOffset.value,
    });
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    historyLoading.value = false;
  }
}

function statusTagType(status: AuditLogOwnItem['status']): 'success' | 'warning' | 'error' | 'info' {
  switch (status) {
    case 'SUCCESS': return 'success';
    case 'RESIGN': return 'info';
    case 'REJECTED': return 'warning';
    case 'FAILED': return 'error';
    default: return 'info';
  }
}

function formatHash(hash: string): string {
  if (hash.length <= 16) return hash;
  return `${hash.slice(0, 8)}...${hash.slice(-8)}`;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString('zh-CN');
}

const historyColumns: DataTableColumns<AuditLogOwnItem> = [
  { title: '时间', key: 'createdAt', render: (row) => formatTime(row.createdAt), width: 180 },
  { title: '操作', key: 'operation', width: 90, render: (row) =>
    h(NTag, { type: row.operation === 'RESIGN' ? 'info' : 'default', size: 'small' }, () =>
      row.operation === 'RESIGN' ? '签名回填' : '诊断') },
  { title: '状态', key: 'status', width: 110, render: (row) =>
    h(NTag, { type: statusTagType(row.status), size: 'small' }, () => row.status) },
  { title: '包名', key: 'packageName', width: 200, ellipsis: { tooltip: true } },
  { title: 'APK hash', key: 'apkHash', width: 180, render: (row) => formatHash(row.apkHash) },
  { title: 'APK 大小', key: 'apkSize', width: 100, render: (row) => formatSize(row.apkSize) },
  { title: '校验 1', key: 'check1Passed', width: 80, render: (row) =>
    h(NTag, { type: row.check1Passed ? 'success' : 'error', size: 'small' }, () =>
      row.check1Passed ? '通过' : '失败') },
  { title: '校验 2', key: 'check2Passed', width: 80, render: (row) =>
    h(NTag, { type: row.check2Passed ? 'success' : 'error', size: 'small' }, () =>
      row.check2Passed ? '通过' : '失败') },
  { title: '拒绝原因', key: 'rejectReason', width: 150, ellipsis: { tooltip: true },
    render: (row) => row.rejectReason ?? '-' },
  { title: '回填后 hash', key: 'resignToHash', width: 180, render: (row) =>
    row.resignToHash ? formatHash(row.resignToHash) : '-' },
];

onMounted(() => {
  loadHistory();
  loadEula();
});

// ============= CSV 导出 =============
const exporting = ref(false);

async function exportCsv() {
  exporting.value = true;
  try {
    const result = await auditApi.exportLogsCsv(10000);
    // 触发浏览器下载
    const blob = new Blob([result.csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = result.filename;
    a.click();
    URL.revokeObjectURL(url);
    message.success(`已导出 ${result.filename}`);
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    exporting.value = false;
  }
}

// ============= 水印追溯 Tab(ADMIN only)=============
const traceApkFile = ref<File | null>(null);
const tracing = ref(false);
const traceResult = ref<WatermarkTraceResponse | null>(null);

function handleTraceFileChange(data: { fileList: UploadFileInfo[] }) {
  const file = data.fileList[0]?.file;
  traceApkFile.value = file ?? null;
  traceResult.value = null;
}

async function doTrace() {
  if (!traceApkFile.value) {
    message.warning('请先选择 APK 文件');
    return;
  }
  tracing.value = true;
  traceResult.value = null;
  try {
    const result = await auditApi.traceWatermark(traceApkFile.value);
    traceResult.value = result;
    if (result.found) {
      message.success('水印追溯成功');
    } else {
      message.warning('APK 中未找到水印文件');
    }
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    tracing.value = false;
  }
}

function formatTimestamp(ms: number): string {
  return new Date(ms).toLocaleString('zh-CN');
}
</script>

<template>
  <NCard title="自有 APK 诊断(ADR 0077)" :bordered="false">
    <template #header-extra>
      <NText depth="3" style="font-size: 12px;">
        三重校验强制 · 仅限开发者自有 APK · 例外 A 签名回填
      </NText>
    </template>

    <NTabs type="line" animated>
      <!-- Tab 1: 诊断 -->
      <NTabPane name="analyze" tab="诊断(只读)">
        <NSpace vertical size="large">
          <NAlert type="info" :show-icon="true">
            诊断对 APK 做只读分析:AndroidManifest 解析 + 签名信息 + 权限扫描。
            <strong>不修改 APK</strong>,三重校验通过后才执行。
          </NAlert>

          <NCard title="上传 APK" size="small">
            <NSpace vertical>
              <NFormItem label="加固厂商" label-placement="left">
                <NSelect
                  v-model:value="hardenerSelect"
                  :options="[
                    { label: '无加固(普通诊断)', value: 'none' },
                    { label: '梆梆加固自检(ADR 0078,需 EULA)', value: 'bangcle' },
                  ]"
                  style="width: 320px;"
                />
              </NFormItem>

              <NAlert v-if="hardenerSelect === 'bangcle' && !eulaAccepted" type="warning" :show-icon="true">
                梆梆自检需先接受 EULA(锁 B)。
                <NButton text type="primary" @click="showEulaModal = true">查看 EULA</NButton>
              </NAlert>
              <NAlert v-else-if="hardenerSelect === 'bangcle' && eulaAccepted" type="success" :show-icon="true">
                EULA v{{ eulaInfo?.version }} 已接受,可执行梆梆自检(锁 A 仅梆梆 / 锁 C 仅完整性报告)
              </NAlert>

              <NUpload
                :max="1"
                accept=".apk,application/vnd.android.package-archive"
                :default-upload="false"
                @change="handleAnalyzeFileChange"
              >
                <NButton>选择 APK 文件</NButton>
              </NUpload>

              <NSpace>
                <NButton
                  type="primary"
                  :loading="analyzing"
                  :disabled="!analyzeApkFile"
                  @click="doAnalyze"
                >
                  {{ hardenerSelect === 'bangcle' ? '执行梆梆自检' : '开始诊断' }}
                </NButton>
                <NText v-if="analyzeApkFile" depth="3">
                  {{ analyzeApkFile.name }} ({{ formatSize(analyzeApkFile.size) }})
                </NText>
              </NSpace>
            </NSpace>
          </NCard>

          <NSpin v-if="analyzing" size="large" />
          <NCard v-if="analyzeReport" title="诊断报告" size="small">
            <NSpace vertical size="large">
              <NDescriptions :column="2" label-placement="left" bordered>
                <NDescriptionsItem label="taskId">
                  <NCode :code="analyzeReport.taskId" language="text" />
                </NDescriptionsItem>
                <NDescriptionsItem label="时间">
                  {{ formatTime(analyzeReport.timestamp) }}
                </NDescriptionsItem>
                <NDescriptionsItem label="包名">
                  {{ analyzeReport.apkInfo.packageName }}
                </NDescriptionsItem>
                <NDescriptionsItem label="APK 大小">
                  {{ formatSize(analyzeReport.apkInfo.apkSize) }}
                </NDescriptionsItem>
                <NDescriptionsItem label="APK SHA-256" :span="2">
                  <NCode :code="analyzeReport.apkInfo.apkHash" language="text" />
                </NDescriptionsItem>
                <NDescriptionsItem label="签名 SHA-256" :span="2">
                  <NCode :code="analyzeReport.apkInfo.signatureHash" language="text" />
                </NDescriptionsItem>
              </NDescriptions>

              <div>
                <NText strong>Manifest 权限({{ analyzeReport.manifest.permissions.length }})</NText>
                <NSpace style="margin-top: 8px;">
                  <NTag v-for="perm in analyzeReport.manifest.permissions" :key="perm" size="small">
                    {{ perm }}
                  </NTag>
                  <NText v-if="analyzeReport.manifest.permissions.length === 0" depth="3">
                    (无)
                  </NText>
                </NSpace>
              </div>

              <NAlert v-if="analyzeReport.note" type="warning" :show-icon="true">
                {{ analyzeReport.note }}
              </NAlert>
            </NSpace>
          </NCard>
        </NSpace>
      </NTabPane>

      <!-- Tab 2: 签名回填 -->
      <NTabPane name="resign" tab="签名回填(例外 A)">
        <NSpace vertical size="large">
          <NAlert type="warning" :show-icon="true">
            <strong>例外 A 约束(ADR 0077 §2.1)</strong>:
            仅修改 META-INF/ 签名文件,不动 dex/resource/manifest;
            必须使用开发者自有 keystore;V1+V2+V3 签名;
            回填后 APK hash 自动入白名单;三重校验前置。
          </NAlert>

          <NCard title="上传 APK + keystore" size="small">
            <NSpace vertical>
              <NUpload
                :max="1"
                accept=".apk,application/vnd.android.package-archive"
                :default-upload="false"
                @change="handleResignApkChange"
              >
                <NButton>选择 APK 文件</NButton>
              </NUpload>

              <NUpload
                :max="1"
                accept=".jks,.keystore,application/octet-stream"
                :default-upload="false"
                @change="handleKeystoreChange"
              >
                <NButton>选择 keystore 文件(.jks / .keystore)</NButton>
              </NUpload>

              <NForm label-placement="left" label-width="140">
                <NFormItem label="keystore 密码">
                  <NInput
                    v-model:value="resignCredentials.keystorePassword"
                    type="password"
                    show-password-on="click"
                    placeholder="keystore 密码"
                  />
                </NFormItem>
                <NFormItem label="key 别名">
                  <NInput
                    v-model:value="resignCredentials.keyAlias"
                    placeholder="如 key0 / mykey"
                  />
                </NFormItem>
                <NFormItem label="key 密码">
                  <NInput
                    v-model:value="resignCredentials.keyPassword"
                    type="password"
                    show-password-on="click"
                    placeholder="key 密码(通常与 keystore 密码相同)"
                  />
                </NFormItem>
              </NForm>

              <NSpace>
                <NPopconfirm @positive-click="doResign">
                  <template #trigger>
                    <NButton
                      type="warning"
                      :loading="resigning"
                      :disabled="!resignApkFile || !resignKeystoreFile"
                    >
                      执行签名回填
                    </NButton>
                  </template>
                  确认 APK 是开发者自有,keystore 凭证已正确填写?
                </NPopconfirm>
                <NText v-if="resignApkFile" depth="3">
                  APK: {{ resignApkFile.name }}
                </NText>
                <NText v-if="resignKeystoreFile" depth="3">
                  keystore: {{ resignKeystoreFile.name }}
                </NText>
              </NSpace>
            </NSpace>
          </NCard>

          <NSpin v-if="resigning" size="large" />

          <NCard v-if="resignResult" title="回填结果" size="small">
            <NSpace vertical>
              <NDescriptions :column="1" label-placement="left" bordered>
                <NDescriptionsItem label="taskId">
                  <NCode :code="resignResult.taskId" language="text" />
                </NDescriptionsItem>
                <NDescriptionsItem label="原 APK hash">
                  <NCode :code="resignResult.oldHash" language="text" />
                </NDescriptionsItem>
                <NDescriptionsItem label="新 APK hash(已入白名单)">
                  <NCode :code="resignResult.newHash" language="text" />
                </NDescriptionsItem>
                <NDescriptionsItem label="重签后大小">
                  {{ formatSize(resignResult.resignedApkSize) }}
                </NDescriptionsItem>
              </NDescriptions>

              <NButton type="primary" @click="downloadResignedApk">
                下载重签后的 APK
              </NButton>
            </NSpace>
          </NCard>
        </NSpace>
      </NTabPane>

      <!-- Tab 3: 历史 -->
      <NTabPane name="history" tab="诊断历史">
        <NSpace vertical size="large">
          <NSpace>
            <NButton @click="loadHistory" :loading="historyLoading">刷新</NButton>
            <NButton @click="exportCsv" :loading="exporting" type="primary" ghost>
              导出 CSV
            </NButton>
            <NText depth="3">
              显示最近 {{ historyLimit }} 条(从第 {{ historyOffset + 1 }} 条起)
            </NText>
          </NSpace>

          <NDataTable
            :columns="historyColumns"
            :data="historyLogs"
            :loading="historyLoading"
            :bordered="true"
            :single-line="false"
            size="small"
            :scroll="{ x: 1400 }"
          />
        </NSpace>
      </NTabPane>

      <!-- Tab 4: 水印追溯(ADMIN only) -->
      <NTabPane v-if="isAdmin" name="trace" tab="水印追溯(ADMIN)">
        <NSpace vertical size="large">
          <NAlert type="warning" :show-icon="true">
            <strong>水印追溯(ADR 0030 §c 追溯闭环)</strong>:
            上传含 <code>META-INF/xcj-watermark.enc.txt</code> 的 APK,
            后端用 AES-256-GCM 解密,返回水印明文(version / watermarkId / timestamp / nonce)。
            仅 ADMIN 可用,用于滥用追溯调查。
          </NAlert>

          <NCard title="上传 APK" size="small">
            <NSpace vertical>
              <NUpload
                :max="1"
                accept=".apk,application/vnd.android.package-archive"
                :default-upload="false"
                @change="handleTraceFileChange"
              >
                <NButton>选择 APK 文件</NButton>
              </NUpload>

              <NSpace>
                <NButton
                  type="primary"
                  :loading="tracing"
                  :disabled="!traceApkFile"
                  @click="doTrace"
                >
                  追溯水印
                </NButton>
                <NText v-if="traceApkFile" depth="3">
                  {{ traceApkFile.name }} ({{ formatSize(traceApkFile.size) }})
                </NText>
              </NSpace>
            </NSpace>
          </NCard>

          <NSpin v-if="tracing" size="large" />

          <NCard v-if="traceResult" title="追溯结果" size="small">
            <NAlert
              :type="traceResult.found ? 'success' : 'warning'"
              :show-icon="true"
              style="margin-bottom: 16px;"
            >
              {{ traceResult.found ? '水印已找到并解密成功' : 'APK 中未找到水印文件(可能未用 injector sign 加水印,或被擦除)' }}
            </NAlert>

            <NDescriptions v-if="traceResult.found && traceResult.watermark" :column="1" label-placement="left" bordered>
              <NDescriptionsItem label="水印版本">
                {{ traceResult.watermark.version }}
              </NDescriptionsItem>
              <NDescriptionsItem label="水印 ID(开发者标识)">
                <NCode :code="traceResult.watermark.watermarkId" language="text" />
              </NDescriptionsItem>
              <NDescriptionsItem label="注入时间">
                {{ formatTimestamp(traceResult.watermark.timestamp) }}
                <NText depth="3" style="margin-left: 12px;">
                  (Unix ms: {{ traceResult.watermark.timestamp }})
                </NText>
              </NDescriptionsItem>
              <NDescriptionsItem label="nonce">
                <NCode :code="traceResult.watermark.nonce" language="text" />
              </NDescriptionsItem>
              <NDescriptionsItem label="提取时间">
                {{ formatTime(traceResult.extractedAt) }}
              </NDescriptionsItem>
            </NDescriptions>
          </NCard>
        </NSpace>
      </NTabPane>
    </NTabs>

    <!-- 梆梆 EULA 弹窗(锁 B 前置) -->
    <NModal
      v-model:show="showEulaModal"
      preset="card"
      :title="`梆梆加固自检 EULA v${eulaInfo?.version ?? ''}`"
      style="max-width: 700px;"
    >
      <NSpace vertical>
        <NAlert type="info" :show-icon="true">
          生效日期:{{ eulaInfo?.effectiveDate ?? '-' }}。接受后才能使用梆梆加固自检功能(锁 B)。
        </NAlert>
        <NCode :code="eulaInfo?.text ?? '加载中...'" language="text" style="white-space: pre-wrap; max-height: 400px; overflow: auto;" />
        <NSpace justify="end">
          <NButton @click="showEulaModal = false">取消</NButton>
          <NButton type="primary" :loading="eulaLoading" @click="acceptEula">
            我已阅读并接受 EULA
          </NButton>
        </NSpace>
      </NSpace>
    </NModal>
  </NCard>
</template>
