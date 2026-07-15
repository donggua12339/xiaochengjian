<script setup lang="ts">
import { ref, reactive } from 'vue';
import {
  NCard, NForm, NFormItem, NInput, NButton, NSpace, NUpload, NAlert,
  NText, NStatistic, useMessage, type UploadFileInfo,
} from 'naive-ui';
import { injectApi, type InjectResult } from '@/api/inject';
import { useAuthStore } from '@/stores/auth';

const message = useMessage();
const auth = useAuthStore();

const apkFile = ref<File | null>(null);
const keystoreFile = ref<File | null>(null);
const form = reactive({
  ksPass: '',
  ksKeyAlias: '',
  keyPass: '',
  watermarkId: `dev-${Date.now()}`,
});
const injecting = ref(false);
const result = ref<InjectResult | null>(null);

function handleApkChange({ fileList }: { fileList: UploadFileInfo[] }) {
  const file = fileList[fileList.length - 1]?.file;
  if (file) {
    if (!file.name.endsWith('.apk')) {
      message.warning('请上传 APK 文件');
      return;
    }
    apkFile.value = file;
    // 自动生成水印 ID(含文件名 + 时间戳)
    form.watermarkId = `${auth.developer?.email?.split('@')[0] ?? 'dev'}-${file.name}-${Date.now()}`;
  }
}

function handleKeystoreChange({ fileList }: { fileList: UploadFileInfo[] }) {
  const file = fileList[fileList.length - 1]?.file;
  if (file) {
    keystoreFile.value = file;
  }
}

async function handleInject() {
  if (!apkFile.value) {
    message.warning('请上传 APK 文件');
    return;
  }
  if (!keystoreFile.value) {
    message.warning('请上传 keystore 文件');
    return;
  }
  if (!form.ksPass || !form.ksKeyAlias || !form.keyPass) {
    message.warning('请填写 keystore 密码 + 别名 + key 密码');
    return;
  }

  injecting.value = true;
  result.value = null;
  try {
    result.value = await injectApi.inject(
      { apk: apkFile.value, keystore: keystoreFile.value },
      { ...form },
    );
    message.success('注入完成!5 分钟内下载有效');
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    injecting.value = false;
  }
}

function handleDownload() {
  if (!result.value) return;
  // 用 fetch 带 Authorization 头下载
  const token = localStorage.getItem('xcj_access_token') ?? '';
  fetch(`/v1/admin/inject/download?token=${result.value.downloadToken}`, {
    headers: { Authorization: `Bearer ${token}` },
  })
    .then((res) => {
      if (!res.ok) throw new Error('下载失败');
      return res.blob();
    })
    .then((blob) => {
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `xcj-injected-${Date.now()}.apk`;
      a.click();
      URL.revokeObjectURL(url);
    })
    .catch((e) => message.error(e.message));
}

function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}
</script>

<template>
  <NSpace vertical size="large">
    <NCard title="APK 注入">
      <NSpace vertical>
        <NAlert type="info" title="注入说明">
          <NText style="display: block; margin-bottom: 4px">
            上传 APK + keystore,服务器自动注入 SDK 初始化代码 + 水印 + 重签名。注入后的 APK 5 分钟后自动删除,请及时下载。
          </NText>
          <NText depth="3" style="font-size: 13px; display: block; margin-top: 4px">
            ⚠️ 仅限注入开发者自有著作权的 APK。禁止注入他人 APK(详见
            <a href="/docs/compliance/user-agreement.md" target="_blank">用户协议</a>)
          </NText>
        </NAlert>

        <NForm label-placement="left" :label-width="140">
          <NFormItem label="APK 文件">
            <NUpload
              :default-upload="false"
              :max="1"
              accept=".apk"
              @change="handleApkChange"
            >
              <NButton>选择 APK</NButton>
            </NUpload>
            <NText v-if="apkFile" depth="3" style="margin-left: 12px">
              {{ apkFile.name }} ({{ formatSize(apkFile.size) }})
            </NText>
          </NFormItem>

          <NFormItem label="Keystore 文件">
            <NUpload
              :default-upload="false"
              :max="1"
              accept=".keystore,.jks"
              @change="handleKeystoreChange"
            >
              <NButton>选择 keystore</NButton>
            </NUpload>
            <NText v-if="keystoreFile" depth="3" style="margin-left: 12px">
              {{ keystoreFile.name }}
            </NText>
          </NFormItem>

          <NFormItem label="Keystore 密码">
            <NInput v-model:value="form.ksPass" type="password" show-password-on="click" placeholder="keystore 密码" />
          </NFormItem>

          <NFormItem label="Key 别名">
            <NInput v-model:value="form.ksKeyAlias" placeholder="如:xcj-key" />
          </NFormItem>

          <NFormItem label="Key 密码">
            <NInput v-model:value="form.keyPass" type="password" show-password-on="click" placeholder="key 密码" />
          </NFormItem>

          <NFormItem label="水印 ID">
            <NInput v-model:value="form.watermarkId" placeholder="开发者 ID + 时间戳(用于追溯)" />
          </NFormItem>

          <NFormItem label=" ">
            <NButton
              type="primary"
              :loading="injecting"
              :disabled="!apkFile || !keystoreFile"
              @click="handleInject"
            >
              {{ injecting ? '注入中...(约 1-2 分钟)' : '开始注入' }}
            </NButton>
          </NFormItem>
        </NForm>
      </NSpace>
    </NCard>

    <NCard v-if="result" title="注入结果">
      <NSpace vertical size="large">
        <NSpace>
          <NStatistic label="原始大小" :value="formatSize(result.originalSize)" />
          <NStatistic label="注入后" :value="formatSize(result.injectedSize)" />
        </NSpace>

        <NAlert type="success" title="注入成功">
          <NText style="display: block; margin-bottom: 4px">
            水印 ID:{{ result.watermarkId }}
          </NText>
          <NText depth="3" style="font-size: 13px; display: block; margin-top: 4px">
            下载令牌 5 分钟内有效,过期需重新注入
          </NText>
        </NAlert>

        <NButton type="primary" size="large" @click="handleDownload">
          下载注入后的 APK
        </NButton>
      </NSpace>
    </NCard>
  </NSpace>
</template>
