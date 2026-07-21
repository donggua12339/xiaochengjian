<script setup lang="ts">
/**
 * Packer Tab(ADR 0081,自有 APK SDK 封装器)
 *
 * 七锁架构:
 *  锁 1 对象锁定(三重校验,后端强制)
 *  锁 2 内容锁定(固定 classes-xcj.dex 白名单,后端校验)
 *  锁 3 入口锁定(Manifest 修改范围,后端校验)
 *  锁 4 签名锁定(自备 Keystore,本 Tab 上传)
 *  锁 5 权限锁定(JWT 开发者自身,后端校验)
 *  锁 6 数据锁定(SDK 配置仅 OAID + 包信息,本 Tab 限定)
 *  锁 7 客户端签名自检(后端配置预期 hash,SDK 运行时校验)
 *
 * 两个子区域:
 *  - 封装:上传 APK + Keystore + classes-xcj.dex -> 执行封装 -> 下载封装后 APK
 *  - 历史:查询封装记录(七锁校验结果)
 */

import { ref, h, onMounted } from 'vue';
import {
  NCard, NTabs, NTabPane, NUpload, NButton, NSpace, NText, NAlert,
  NForm, NFormItem, NInput, NTag, NDataTable, NCode,
  NSpin, NDescriptions, NDescriptionsItem, NPopconfirm,
  useMessage, type UploadFileInfo, type DataTableColumns,
} from 'naive-ui';
import { packerApi, type PackerLogItem, type PackResponse } from '@/api/packer';
import { useAuthStore } from '@/stores/auth';

const message = useMessage();
const auth = useAuthStore();

// ============= 封装 Tab =============
const apkFile = ref<File | null>(null);
const keystoreFile = ref<File | null>(null);
const xcjAuthSdkDexFile = ref<File | null>(null);
const credentials = ref({
  keystorePassword: '',
  keyAlias: '',
  keyPassword: '',
});
const sdkConfigText = ref(JSON.stringify({
  appId: '',
  serverUrl: 'https://xcj.winmelon.cn',
  offlineCacheDays: 7,
  oaidEnabled: true,
}, null, 2));
const packing = ref(false);
const packResult = ref<PackResponse | null>(null);

function handleApkChange(data: { fileList: UploadFileInfo[] }) {
  apkFile.value = data.fileList[0]?.file ?? null;
  packResult.value = null;
}
function handleKeystoreChange(data: { fileList: UploadFileInfo[] }) {
  keystoreFile.value = data.fileList[0]?.file ?? null;
}
function handleDexChange(data: { fileList: UploadFileInfo[] }) {
  xcjAuthSdkDexFile.value = data.fileList[0]?.file ?? null;
}

async function doPack() {
  if (!apkFile.value) { message.warning('请选择 APK 文件'); return; }
  if (!keystoreFile.value) { message.warning('请选择 Keystore 文件'); return; }
  if (!xcjAuthSdkDexFile.value) { message.warning('请选择 classes-xcj.dex 文件'); return; }
  if (!credentials.value.keystorePassword || !credentials.value.keyAlias || !credentials.value.keyPassword) {
    message.warning('请填写 Keystore 密码 / key 别名 / key 密码');
    return;
  }

  let sdkConfig: Record<string, unknown>;
  try {
    sdkConfig = JSON.parse(sdkConfigText.value);
  } catch {
    message.error('SDK 配置 JSON 解析失败');
    return;
  }

  packing.value = true;
  packResult.value = null;
  try {
    const result = await packerApi.pack(
      apkFile.value,
      keystoreFile.value,
      xcjAuthSdkDexFile.value,
      credentials.value,
      sdkConfig,
    );
    packResult.value = result;
    message.success('封装完成(七锁校验通过)');
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    packing.value = false;
  }
}

function downloadPackedApk() {
  if (!packResult.value) return;
  const byteChars = atob(packResult.value.packedApkBase64);
  const byteNumbers = new Array(byteChars.length);
  for (let i = 0; i < byteChars.length; i++) {
    byteNumbers[i] = byteChars.charCodeAt(i);
  }
  const byteArray = new Uint8Array(byteNumbers);
  const blob = new Blob([byteArray], { type: 'application/vnd.android.package-archive' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const origName = apkFile.value?.name ?? 'packed.apk';
  const baseName = origName.replace(/\.apk$/i, '');
  a.download = `${baseName}-packed.apk`;
  a.click();
  URL.revokeObjectURL(url);
}

// ============= 历史 Tab =============
const historyLoading = ref(false);
const historyLogs = ref<PackerLogItem[]>([]);

async function loadHistory() {
  historyLoading.value = true;
  try {
    historyLogs.value = await packerApi.listLogs({ limit: 50 });
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    historyLoading.value = false;
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
function statusTagType(status: PackerLogItem['status']): 'success' | 'warning' | 'error' | 'info' {
  switch (status) {
    case 'SUCCESS': return 'success';
    case 'REJECTED': return 'warning';
    case 'FAILED': return 'error';
    default: return 'info';
  }
}

const historyColumns: DataTableColumns<PackerLogItem> = [
  { title: '时间', key: 'createdAt', render: (row) => formatTime(row.createdAt), width: 180 },
  { title: '状态', key: 'status', width: 110, render: (row) =>
    h(NTag, { type: statusTagType(row.status), size: 'small' }, () => row.status) },
  { title: '包名', key: 'packageName', width: 200, ellipsis: { tooltip: true } },
  { title: '原 APK hash', key: 'apkHash', width: 180, render: (row) => formatHash(row.apkHash) },
  { title: '七锁', key: 'locks', width: 120, render: (row) => {
    const locks = [row.check1Passed, row.check2Passed, row.check3Passed, row.check4Passed, row.check5Passed, row.check6Passed, row.check7Passed];
    const passed = locks.filter(Boolean).length;
    return h(NTag, { type: passed === 7 ? 'success' : 'error', size: 'small' }, () => `${passed}/7`);
  } },
  { title: 'dex 注入', key: 'dexInjected', width: 90, render: (row) =>
    h(NTag, { type: row.dexInjected ? 'success' : 'error', size: 'small' }, () => row.dexInjected ? '是' : '否') },
  { title: '封装后 hash', key: 'resignedApkHash', width: 180, render: (row) =>
    row.resignedApkHash ? formatHash(row.resignedApkHash) : '-' },
  { title: '拒绝原因', key: 'rejectReason', width: 150, ellipsis: { tooltip: true },
    render: (row) => row.rejectReason ?? '-' },
];

onMounted(() => {
  loadHistory();
});
</script>

<template>
  <NCard title="自有 APK SDK 封装(ADR 0081)" :bordered="false">
    <template #header-extra>
      <NText depth="3" style="font-size: 12px;">
        七锁架构 · 仅限开发者自有 APK · 律师预审通过
      </NText>
    </template>

    <NTabs type="line" animated>
      <!-- 封装 Tab -->
      <NTabPane name="pack" tab="SDK 封装">
        <NSpace vertical size="large">
          <NAlert type="warning" :show-icon="true">
            <strong>七锁合规约束(ADR 0081)</strong>:
            仅限自有 APK(锁 1)· 仅注入固定 classes-xcj.dex(锁 2)·
            Manifest 修改仅限 Application 委托(锁 3)· 强制自备 Keystore(锁 4)·
            JWT 开发者自身(锁 5)· SDK 仅 OAID + 包信息(锁 6)· 客户端签名自检(锁 7)
          </NAlert>

          <NCard title="上传文件" size="small">
            <NSpace vertical>
              <NFormItem label="自有 APK" label-placement="left">
                <NUpload :max="1" accept=".apk,application/vnd.android.package-archive"
                  :default-upload="false" @change="handleApkChange">
                  <NButton>选择 APK 文件</NButton>
                </NUpload>
              </NFormItem>

              <NFormItem label="自备 Keystore" label-placement="left">
                <NUpload :max="1" accept=".jks,.keystore,application/octet-stream"
                  :default-upload="false" @change="handleKeystoreChange">
                  <NButton>选择 Keystore(.jks/.keystore)</NButton>
                </NUpload>
              </NFormItem>

              <NFormItem label="classes-xcj.dex" label-placement="left">
                <NUpload :max="1" accept=".dex,application/octet-stream"
                  :default-upload="false" @change="handleDexChange">
                  <NButton>选择 xcj-auth-sdk 编译产物(.dex)</NButton>
                </NUpload>
              </NFormItem>
            </NSpace>
          </NCard>

          <NCard title="Keystore 凭证 + SDK 配置" size="small">
            <NForm label-placement="left" label-width="140">
              <NFormItem label="Keystore 密码">
                <NInput v-model:value="credentials.keystorePassword" type="password"
                  show-password-on="click" placeholder="Keystore 密码" />
              </NFormItem>
              <NFormItem label="key 别名">
                <NInput v-model:value="credentials.keyAlias" placeholder="如 key0 / mykey" />
              </NFormItem>
              <NFormItem label="key 密码">
                <NInput v-model:value="credentials.keyPassword" type="password"
                  show-password-on="click" placeholder="key 密码" />
              </NFormItem>
              <NFormItem label="SDK 配置(JSON)">
                <NInput v-model:value="sdkConfigText" type="textarea" :rows="6"
                  placeholder='{"appId":"...","serverUrl":"...","offlineCacheDays":7,"oaidEnabled":true}' />
              </NFormItem>
            </NForm>
          </NCard>

          <NSpace>
            <NPopconfirm @positive-click="doPack">
              <template #trigger>
                <NButton type="warning" :loading="packing"
                  :disabled="!apkFile || !keystoreFile || !xcjAuthSdkDexFile">
                  执行 SDK 封装(七锁校验)
                </NButton>
              </template>
              确认 APK 是开发者自有,Keystore 凭证 + classes-xcj.dex 已正确准备?
            </NPopconfirm>
          </NSpace>

          <NSpin v-if="packing" size="large" />

          <NCard v-if="packResult" title="封装结果" size="small">
            <NSpace vertical>
              <NDescriptions :column="1" label-placement="left" bordered>
                <NDescriptionsItem label="taskId">
                  <NCode :code="packResult.taskId" language="text" />
                </NDescriptionsItem>
                <NDescriptionsItem label="封装后 APK hash">
                  <NCode :code="packResult.packedApkHash" language="text" />
                </NDescriptionsItem>
                <NDescriptionsItem label="注入 dex hash">
                  <NCode :code="packResult.injectedDexHash" language="text" />
                </NDescriptionsItem>
                <NDescriptionsItem label="Keystore 指纹">
                  <NCode :code="packResult.keystoreFingerprint" language="text" />
                </NDescriptionsItem>
                <NDescriptionsItem label="封装后大小">
                  {{ formatSize(packResult.packedApkSize) }}
                </NDescriptionsItem>
              </NDescriptions>
              <NButton type="primary" @click="downloadPackedApk">
                下载封装后 APK
              </NButton>
            </NSpace>
          </NCard>
        </NSpace>
      </NTabPane>

      <!-- 历史 Tab -->
      <NTabPane name="history" tab="封装历史">
        <NSpace vertical size="large">
          <NSpace>
            <NButton @click="loadHistory" :loading="historyLoading">刷新</NButton>
            <NText depth="3">显示最近 50 条封装记录</NText>
          </NSpace>
          <NDataTable :columns="historyColumns" :data="historyLogs" :loading="historyLoading"
            :bordered="true" :single-line="false" size="small" :scroll="{ x: 1400 }" />
        </NSpace>
      </NTabPane>
    </NTabs>
  </NCard>
</template>
