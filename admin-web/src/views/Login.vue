<script setup lang="ts">
import { ref, reactive } from 'vue';
import { useRouter, useRoute } from 'vue-router';
import { NCard, NForm, NFormItem, NInput, NButton, NSpace, NText, useMessage } from 'naive-ui';
import { useAuthStore } from '@/stores/auth';

const router = useRouter();
const route = useRoute();
const message = useMessage();
const auth = useAuthStore();

const form = reactive({
  email: '',
  password: '',
});
const loading = ref(false);

async function handleSubmit() {
  if (!form.email || !form.password) {
    message.warning('请输入邮箱和密码');
    return;
  }
  loading.value = true;
  try {
    const result = await auth.login(form.email, form.password);
    if (result.requiresTotp && result.pendingTotpToken) {
      // 需要 2FA 验证
      router.push({
        name: '2fa-verify',
        query: {
          token: result.pendingTotpToken,
          developerId: result.developerId,
        },
      });
    } else {
      message.success('登录成功');
      const redirect = (route.query.redirect as string) || '/dashboard';
      router.push(redirect);
    }
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <div class="login-container">
    <NCard class="login-card" title="小城笺 · 登录" :bordered="false">
      <NForm @keyup.enter="handleSubmit">
        <NFormItem label="邮箱">
          <NInput v-model:value="form.email" placeholder="developer@xcj.dev" />
        </NFormItem>
        <NFormItem label="密码">
          <NInput v-model:value="form.password" type="password" show-password-on="click" placeholder="密码" />
        </NFormItem>
        <NSpace vertical>
          <NButton type="primary" block :loading="loading" @click="handleSubmit">登录</NButton>
          <NSpace justify="space-between">
            <NText depth="3" style="font-size: 13px">还没有账号?</NText>
            <NButton text type="primary" @click="router.push('/register')">立即注册</NButton>
          </NSpace>
        </NSpace>
      </NForm>
    </NCard>
  </div>
</template>

<style scoped>
.login-container {
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}
.login-card {
  width: 400px;
}
</style>
