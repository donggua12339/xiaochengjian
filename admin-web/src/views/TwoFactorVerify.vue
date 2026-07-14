<script setup lang="ts">
import { ref } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { NCard, NForm, NFormItem, NInput, NButton, NSpace, NTabs, NTabPane, NText, useMessage } from 'naive-ui';
import { useAuthStore } from '@/stores/auth';

const router = useRouter();
const route = useRoute();
const message = useMessage();
const auth = useAuthStore();

const pendingTotpToken = (route.query.token as string) || '';
const totpCode = ref('');
const backupCode = ref('');
const loading = ref(false);

async function handleTotpLogin() {
  if (!totpCode.value || totpCode.value.length !== 6) {
    message.warning('请输入 6 位验证码');
    return;
  }
  loading.value = true;
  try {
    await auth.verifyTotpLogin(pendingTotpToken, totpCode.value);
    message.success('登录成功');
    router.push('/dashboard');
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    loading.value = false;
  }
}

async function handleBackupLogin() {
  if (!backupCode.value || backupCode.value.length !== 8) {
    message.warning('请输入 8 位备份码');
    return;
  }
  loading.value = true;
  try {
    await auth.verifyBackupLogin(pendingTotpToken, backupCode.value);
    message.success('登录成功');
    router.push('/dashboard');
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <div class="verify-container">
    <NCard class="verify-card" title="两步验证" :bordered="false">
      <NText depth="3" style="display: block; margin-bottom: 16px">
        请输入 Authenticator 应用生成的验证码,或使用备份码
      </NText>
      <NTabs type="line">
        <NTabPane name="totp" tab="验证码">
          <NForm @keyup.enter="handleTotpLogin">
            <NFormItem label="6 位验证码">
              <NInput v-model:value="totpCode" placeholder="123456" maxlength="6" />
            </NFormItem>
            <NButton type="primary" block :loading="loading" @click="handleTotpLogin">验证</NButton>
          </NForm>
        </NTabPane>
        <NTabPane name="backup" tab="备份码">
          <NForm @keyup.enter="handleBackupLogin">
            <NFormItem label="8 位备份码">
              <NInput v-model:value="backupCode" placeholder="A1B2C3D4" maxlength="8" />
            </NFormItem>
            <NButton type="primary" block :loading="loading" @click="handleBackupLogin">使用备份码</NButton>
          </NForm>
        </NTabPane>
      </NTabs>
      <NSpace justify="center" style="margin-top: 16px">
        <NButton text @click="router.push('/login')">返回登录</NButton>
      </NSpace>
    </NCard>
  </div>
</template>

<style scoped>
.verify-container {
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}
.verify-card {
  width: 400px;
}
</style>
