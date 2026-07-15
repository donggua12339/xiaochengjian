<script setup lang="ts">
import { ref, onMounted } from 'vue';
import {
  NCard, NSpace, NForm, NFormItem, NInput, NButton, NTag, NAlert,
  NDescriptions, NDescriptionsItem, useMessage,
} from 'naive-ui';
import { useAuthStore } from '@/stores/auth';

const message = useMessage();
const auth = useAuthStore();

// 修改密码
const passwordForm = ref({
  currentPassword: '',
  newPassword: '',
  confirmPassword: '',
});
const changingPassword = ref(false);

// 2FA
const totpSetup = ref<{ secret: string; otpauthUrl: string } | null>(null);
const totpCode = ref('');
const backupCodes = ref<string[] | null>(null);
const settingUpTotp = ref(false);

async function handleChangePassword() {
  if (!passwordForm.value.currentPassword || !passwordForm.value.newPassword) {
    message.warning('请填写完整');
    return;
  }
  if (passwordForm.value.newPassword !== passwordForm.value.confirmPassword) {
    message.warning('两次新密码不一致');
    return;
  }
  if (passwordForm.value.newPassword.length < 8) {
    message.warning('新密码至少 8 位');
    return;
  }
  if (!/[a-zA-Z]/.test(passwordForm.value.newPassword) || !/\d/.test(passwordForm.value.newPassword)) {
    message.warning('新密码必须包含字母和数字');
    return;
  }
  changingPassword.value = true;
  try {
    await auth.changePassword(passwordForm.value.currentPassword, passwordForm.value.newPassword);
    message.success('密码修改成功');
    passwordForm.value = { currentPassword: '', newPassword: '', confirmPassword: '' };
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    changingPassword.value = false;
  }
}

async function handleSetupTotp() {
  settingUpTotp.value = true;
  try {
    totpSetup.value = await auth.setupTotp();
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    settingUpTotp.value = false;
  }
}

async function handleVerifyTotp() {
  if (!totpCode.value || totpCode.value.length !== 6) {
    message.warning('请输入 6 位验证码');
    return;
  }
  try {
    const result = await auth.verifyTotpSetup(totpCode.value);
    backupCodes.value = result.backupCodes;
    message.success('2FA 已启用');
    totpSetup.value = null;
    totpCode.value = '';
  } catch (error) {
    message.error(auth.handleError(error));
  }
}

function copyBackupCodes() {
  if (backupCodes.value) {
    navigator.clipboard.writeText(backupCodes.value.join('\n'));
    message.success('已复制');
  }
}

onMounted(async () => {
  try {
    await auth.loadProfile();
  } catch (error) {
    message.error(auth.handleError(error));
  }
});
</script>

<template>
  <NSpace vertical size="large">
    <NCard title="个人信息">
      <NDescriptions :column="2" label-placement="left" bordered>
        <NDescriptionsItem label="邮箱">{{ auth.developer?.email ?? '未加载' }}</NDescriptionsItem>
        <NDescriptionsItem label="角色">
          <NTag size="small">开发者</NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="会员等级">
          <NTag size="small" type="info">免费版</NTag>
        </NDescriptionsItem>
        <NDescriptionsItem label="注册时间">{{ auth.developer?.createdAt ? new Date(auth.developer.createdAt).toLocaleString() : '-' }}</NDescriptionsItem>
      </NDescriptions>
    </NCard>

    <NCard title="修改密码">
      <NForm label-placement="left" :label-width="140" style="max-width: 500px">
        <NFormItem label="当前密码">
          <NInput v-model:value="passwordForm.currentPassword" type="password" show-password-on="click" />
        </NFormItem>
        <NFormItem label="新密码">
          <NInput v-model:value="passwordForm.newPassword" type="password" show-password-on="click" placeholder="至少 8 位" />
        </NFormItem>
        <NFormItem label="确认新密码">
          <NInput v-model:value="passwordForm.confirmPassword" type="password" show-password-on="click" />
        </NFormItem>
        <NButton type="primary" :loading="changingPassword" @click="handleChangePassword">修改密码</NButton>
      </NForm>
    </NCard>

    <NCard title="两步验证(2FA)">
      <NSpace vertical>
        <NAlert v-if="!auth.needs2FA && !totpSetup" type="warning" title="2FA 未启用">
          启用两步验证可显著提升账号安全性。登录时除密码外,还需输入 Authenticator 应用生成的验证码。
        </NAlert>
        <NAlert v-if="auth.needs2FA" type="success" title="2FA 已启用">
          你的账号已启用两步验证。登录时需要输入验证码或备份码。
        </NAlert>

        <!-- 启用 2FA 流程 -->
        <template v-if="totpSetup">
          <NCard title="步骤 1:扫描二维码" size="small" :bordered="false">
            <NSpace vertical>
              <NText depth="3">用 Google Authenticator / Microsoft Authenticator 扫描以下 otpauth URL:</NText>
              <NInput :value="totpSetup.otpauthUrl" readonly type="textarea" :rows="2" />
              <NText depth="3">或手动输入密钥:</NText>
              <NInput :value="totpSetup.secret" readonly style="font-family: monospace" />
            </NSpace>
          </NCard>
          <NCard title="步骤 2:输入验证码" size="small" :bordered="false">
            <NSpace>
              <NInput v-model:value="totpCode" placeholder="6 位验证码" maxlength="6" style="max-width: 200px" />
              <NButton type="primary" @click="handleVerifyTotp">验证并启用</NButton>
            </NSpace>
          </NCard>
        </template>

        <!-- 备份码显示(仅启用时一次性) -->
        <NCard v-if="backupCodes" title="备份码(仅此一次,请保存)" size="small" :bordered="false">
          <NSpace vertical>
            <NAlert type="warning">每个备份码只能用一次。丢失后无法找回,只能联系管理员重置 2FA。</NAlert>
            <NInput :value="backupCodes.join('\n')" readonly type="textarea" :rows="5" style="font-family: monospace" />
            <NButton @click="copyBackupCodes">复制全部</NButton>
          </NSpace>
        </NCard>

        <NButton v-if="!auth.needs2FA && !totpSetup" type="primary" :loading="settingUpTotp" @click="handleSetupTotp">
          启用 2FA
        </NButton>
      </NSpace>
    </NCard>

    <NCard title="订阅">
      <NDescriptions :column="2" label-placement="left" bordered>
        <NDescriptionsItem label="当前方案">免费版</NDescriptionsItem>
        <NDescriptionsItem label="应用配额">{{ auth.developer?.maxApps ?? '-' }} 个</NDescriptionsItem>
        <NDescriptionsItem label="卡密数量">无限制</NDescriptionsItem>
        <NDescriptionsItem label="API 调用">无限制</NDescriptionsItem>
      </NDescriptions>
      <NSpace style="margin-top: 16px">
        <NButton type="primary" disabled>升级会员(即将开放)</NButton>
      </NSpace>
    </NCard>
  </NSpace>
</template>

<script lang="ts">
import { NText } from 'naive-ui';
export default { components: { NText } };
</script>
