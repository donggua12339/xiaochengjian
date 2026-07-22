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
  NSwitch, NSelect, NInputNumber, NDivider,
  useMessage, type UploadFileInfo, type DataTableColumns,
} from 'naive-ui';
import { packerApi, type PackerLogItem, type PackResponse, type DefenderConfig } from '@/api/packer';
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

// ============= defender-sdk 配置(ADR 0088,可选)=============
const defenderEnabled = ref(false);
const defenderConfig = ref<DefenderConfig>({
  appId: '',
  serverUrl: 'https://xcj.winmelon.cn',
  signatureVerify: { enabled: true, onViolation: 'kill' },
  antiDebug: { enabled: false, onViolation: 'kill' },
  antiFrida: { enabled: false, onViolation: 'kill' },
  antiDump: { enabled: false, onViolation: 'kill' },
  rootDetect: { enabled: false, onViolation: 'warn' },
  xposedDetect: { enabled: false, onViolation: 'kill', killThreshold: 70 },
  emulatorDetect: { enabled: false, onViolation: 'warn' },
  integrityCheck: { enabled: true, onViolation: 'kill' },
  secureScreen: { enabled: false, excludeActivities: [] },
  onViolationKill: {
    delayMinMs: 3000,
    delayMaxMs: 15000,
    method: 'sigabrt',
    showToast: true,
    toastMessage: '检测到安全风险',
  },
  report: { enabled: false, throttleMs: 300000 },
});
const excludeActivitiesText = ref('');

const violationOptions = [
  { label: 'kill(终止进程)', value: 'kill' },
  { label: 'warn(告警+上报)', value: 'warn' },
  { label: 'none(仅记录)', value: 'none' },
];
const killMethodOptions = [
  { label: 'sigabrt(产生 tombstone)', value: 'sigabrt' },
  { label: 'exit(静默退出)', value: 'exit' },
];

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

  // defender 配置处理(ADR 0088)
  if (defenderEnabled.value) {
    const excludeActivities = excludeActivitiesText.value
      .split('\n')
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    defenderConfig.value.secureScreen = {
      enabled: defenderConfig.value.secureScreen?.enabled ?? false,
      excludeActivities,
    };
    // appId / serverUrl 从 sdkConfig 继承
    defenderConfig.value.appId = (sdkConfig.appId as string) ?? '';
    defenderConfig.value.serverUrl = (sdkConfig.serverUrl as string) ?? '';
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
      defenderEnabled.value,
      defenderConfig.value,
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

          <NCard title="defender-sdk 防护配置(ADR 0088,可选)" size="small">
            <NSpace vertical>
              <NAlert type="info" :show-icon="true">
                defender-sdk 是防守内核(9 模块),通过 Packer 注入到自有 APK。
                默认仅 signatureVerify + integrityCheck 开启(防误杀)。
                启用后 Packer 会注入 .so(30 池随机名)+ classes-defender.dex + defender-config.json。
              </NAlert>

              <NFormItem label="启用 defender-sdk" label-placement="left">
                <NSwitch v-model:value="defenderEnabled" />
                <NText depth="3" style="margin-left: 12px; font-size: 12px;">
                  {{ defenderEnabled ? '已启用(将注入 defender-sdk)' : '未启用(仅封装 auth-sdk)' }}
                </NText>
              </NFormItem>

              <template v-if="defenderEnabled">
                <NDivider title-placement="left">9 模块开关</NDivider>

                <NForm label-placement="left" label-width="140" size="small">
                  <NFormItem label="签名校验">
                    <NSpace>
                      <NSwitch v-model:value="defenderConfig.signatureVerify!.enabled" />
                      <NSelect v-model:value="defenderConfig.signatureVerify!.onViolation"
                        :options="violationOptions" style="width: 180px" />
                    </NSpace>
                  </NFormItem>

                  <NFormItem label="反调试">
                    <NSpace>
                      <NSwitch v-model:value="defenderConfig.antiDebug!.enabled" />
                      <NSelect v-model:value="defenderConfig.antiDebug!.onViolation"
                        :options="violationOptions" style="width: 180px" />
                    </NSpace>
                  </NFormItem>

                  <NFormItem label="防 Frida">
                    <NSpace>
                      <NSwitch v-model:value="defenderConfig.antiFrida!.enabled" />
                      <NSelect v-model:value="defenderConfig.antiFrida!.onViolation"
                        :options="violationOptions" style="width: 180px" />
                    </NSpace>
                  </NFormItem>

                  <NFormItem label="防 Dump">
                    <NSpace>
                      <NSwitch v-model:value="defenderConfig.antiDump!.enabled" />
                      <NSelect v-model:value="defenderConfig.antiDump!.onViolation"
                        :options="violationOptions" style="width: 180px" />
                    </NSpace>
                  </NFormItem>

                  <NFormItem label="Root 检测">
                    <NSpace>
                      <NSwitch v-model:value="defenderConfig.rootDetect!.enabled" />
                      <NSelect v-model:value="defenderConfig.rootDetect!.onViolation"
                        :options="violationOptions" style="width: 180px" />
                    </NSpace>
                  </NFormItem>

                  <NFormItem label="Xposed 检测">
                    <NSpace>
                      <NSwitch v-model:value="defenderConfig.xposedDetect!.enabled" />
                      <NSelect v-model:value="defenderConfig.xposedDetect!.onViolation"
                        :options="violationOptions" style="width: 180px" />
                      <NText depth="3" style="font-size: 12px;">kill 阈值:</NText>
                      <NInputNumber v-model:value="defenderConfig.xposedDetect!.killThreshold"
                        :min="0" :max="100" style="width: 100px" />
                    </NSpace>
                  </NFormItem>

                  <NFormItem label="模拟器检测">
                    <NSpace>
                      <NSwitch v-model:value="defenderConfig.emulatorDetect!.enabled" />
                      <NSelect v-model:value="defenderConfig.emulatorDetect!.onViolation"
                        :options="violationOptions" style="width: 180px" />
                    </NSpace>
                  </NFormItem>

                  <NFormItem label="完整性校验">
                    <NSpace>
                      <NSwitch v-model:value="defenderConfig.integrityCheck!.enabled" />
                      <NSelect v-model:value="defenderConfig.integrityCheck!.onViolation"
                        :options="violationOptions" style="width: 180px" />
                    </NSpace>
                  </NFormItem>

                  <NFormItem label="防截屏">
                    <NSwitch v-model:value="defenderConfig.secureScreen!.enabled" />
                  </NFormItem>
                </NForm>

                <NDivider title-placement="left">kill 响应策略</NDivider>
                <NForm label-placement="left" label-width="140" size="small">
                  <NFormItem label="终止方式">
                    <NSelect v-model:value="defenderConfig.onViolationKill!.method"
                      :options="killMethodOptions" style="width: 240px" />
                  </NFormItem>
                  <NFormItem label="延迟最小(ms)">
                    <NInputNumber v-model:value="defenderConfig.onViolationKill!.delayMinMs"
                      :min="0" :max="60000" style="width: 180px" />
                  </NFormItem>
                  <NFormItem label="延迟最大(ms)">
                    <NInputNumber v-model:value="defenderConfig.onViolationKill!.delayMaxMs"
                      :min="0" :max="60000" style="width: 180px" />
                  </NFormItem>
                  <NFormItem label="显示 Toast">
                    <NSwitch v-model:value="defenderConfig.onViolationKill!.showToast" />
                  </NFormItem>
                  <NFormItem label="Toast 文案">
                    <NInput v-model:value="defenderConfig.onViolationKill!.toastMessage"
                      style="width: 300px" />
                  </NFormItem>
                </NForm>

                <NDivider title-placement="left">warn 响应策略</NDivider>
                <NForm label-placement="left" label-width="140" size="small">
                  <NFormItem label="启用上报">
                    <NSwitch v-model:value="defenderConfig.report!.enabled" />
                  </NFormItem>
                  <NFormItem label="限流周期(ms)">
                    <NInputNumber v-model:value="defenderConfig.report!.throttleMs"
                      :min="0" :step="60000" style="width: 180px" />
                  </NFormItem>
                </NForm>

                <NDivider title-placement="left">防截屏排除列表</NDivider>
                <NFormItem label="excludeActivities" label-placement="top">
                  <NInput v-model:value="excludeActivitiesText" type="textarea" :rows="3"
                    placeholder="每行一个 Activity 全限定名(这些 Activity 不加 FLAG_SECURE)&#10;如:com.example.LoginActivity" />
                </NFormItem>
              </template>
            </NSpace>
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
                <NDescriptionsItem label="注入 dex hash(auth)">
                  <NCode :code="packResult.injectedDexHash" language="text" />
                </NDescriptionsItem>
                <NDescriptionsItem v-if="packResult.injectedDefenderDexHash" label="注入 dex hash(defender)">
                  <NCode :code="packResult.injectedDefenderDexHash" language="text" />
                </NDescriptionsItem>
                <NDescriptionsItem v-if="packResult.defenderSoName" label="defender .so 名(随机)">
                  <NTag type="info" size="small">{{ packResult.defenderSoName }}</NTag>
                </NDescriptionsItem>
                <NDescriptionsItem v-if="packResult.injectedSoHash" label="defender .so hash">
                  <NCode :code="packResult.injectedSoHash" language="text" />
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
