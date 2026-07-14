<script setup lang="ts">
import { ref, reactive } from 'vue';
import { useRouter } from 'vue-router';
import { NCard, NForm, NFormItem, NInput, NButton, NSpace, useMessage } from 'naive-ui';
import { useAuthStore } from '@/stores/auth';

const router = useRouter();
const message = useMessage();
const auth = useAuthStore();

const form = reactive({
  email: '',
  password: '',
  confirmPassword: '',
});
const loading = ref(false);

async function handleSubmit() {
  if (!form.email || !form.password) {
    message.warning('请填写邮箱和密码');
    return;
  }
  if (form.password !== form.confirmPassword) {
    message.warning('两次密码不一致');
    return;
  }
  if (form.password.length < 8) {
    message.warning('密码至少 8 位');
    return;
  }
  loading.value = true;
  try {
    await auth.register(form.email, form.password);
    message.success('注册成功,请登录');
    router.push('/login');
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <div class="register-container">
    <NCard class="register-card" title="小城笺 · 注册" :bordered="false">
      <NForm @keyup.enter="handleSubmit">
        <NFormItem label="邮箱">
          <NInput v-model:value="form.email" placeholder="developer@xcj.dev" />
        </NFormItem>
        <NFormItem label="密码">
          <NInput v-model:value="form.password" type="password" show-password-on="click" placeholder="至少 8 位" />
        </NFormItem>
        <NFormItem label="确认密码">
          <NInput v-model:value="form.confirmPassword" type="password" show-password-on="click" placeholder="再次输入密码" />
        </NFormItem>
        <NSpace vertical>
          <NButton type="primary" block :loading="loading" @click="handleSubmit">注册</NButton>
          <NButton block quaternary @click="router.push('/login')">已有账号?去登录</NButton>
        </NSpace>
      </NForm>
    </NCard>
  </div>
</template>

<style scoped>
.register-container {
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}
.register-card {
  width: 400px;
}
</style>
