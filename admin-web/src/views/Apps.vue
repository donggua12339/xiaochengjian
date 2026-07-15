<script setup lang="ts">
import { onMounted, ref, h } from 'vue';
import { useRouter } from 'vue-router';
import {
  NCard, NButton, NSpace, NDataTable, NModal, NForm, NFormItem, NInput,
  NTag, NPopconfirm, useMessage, type DataTableColumns,
} from 'naive-ui';
import { appsApi, type AppItem } from '@/api/apps';
import { useAuthStore } from '@/stores/auth';

const router = useRouter();
const message = useMessage();
const auth = useAuthStore();

const loading = ref(true);
const apps = ref<AppItem[]>([]);
const showModal = ref(false);
const creating = ref(false);
const newApp = ref({ name: '', packageName: '' });
const newAppSecret = ref<string | null>(null);

async function loadApps() {
  loading.value = true;
  try {
    apps.value = await appsApi.list();
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    loading.value = false;
  }
}

async function handleCreate() {
  if (!newApp.value.name || !newApp.value.packageName) {
    message.warning('请填写应用名称和包名');
    return;
  }
  creating.value = true;
  try {
    const result = await appsApi.create(newApp.value);
    newAppSecret.value = result.appSecret;
    message.success('应用创建成功');
    showModal.value = false;
    newApp.value = { name: '', packageName: '' };
    await loadApps();
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    creating.value = false;
  }
}

async function handleDelete(app: AppItem) {
  try {
    await appsApi.delete(app.id);
    message.success('已删除');
    await loadApps();
  } catch (error) {
    message.error(auth.handleError(error));
  }
}

function copySecret() {
  if (newAppSecret.value) {
    // clipboard API 在非 HTTPS 下不可用,加 fallback
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(newAppSecret.value);
    } else {
      const ta = document.createElement('textarea');
      ta.value = newAppSecret.value;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    message.success('已复制到剪贴板,请妥善保存');
  }
}

const columns: DataTableColumns<AppItem> = [
  { title: '应用名称', key: 'name', render: (row) => h('a', { onClick: () => router.push(`/apps/${row.id}`) }, row.name) },
  { title: '包名', key: 'packageName' },
  { title: 'appSecret 前缀', key: 'appSecretPrefix', render: (row) => h(NTag, { size: 'small' }, () => row.appSecretPrefix) },
  { title: '离线缓存(天)', key: 'offlineCacheDays' },
  { title: '创建时间', key: 'createdAt', render: (row) => new Date(row.createdAt).toLocaleString() },
  {
    title: '操作',
    key: 'actions',
    render: (row) =>
      h(NSpace, {}, () => [
        h(NButton, { size: 'small', onClick: () => router.push(`/apps/${row.id}`) }, () => '管理'),
        h(NPopconfirm, { onPositiveClick: () => handleDelete(row) }, {
          trigger: () => h(NButton, { size: 'small', type: 'error', quaternary: true }, () => '删除'),
          default: () => `确认删除应用「${row.name}」?此操作会级联删除所有卡密和设备记录,不可恢复。`,
        }),
      ]),
  },
];

onMounted(loadApps);
</script>

<template>
  <NSpace vertical size="large">
    <NCard title="应用管理">
      <template #header-extra>
        <NButton type="primary" @click="showModal = true">创建应用</NButton>
      </template>
      <NDataTable :columns="columns" :data="apps" :loading="loading" :bordered="false" />
    </NCard>

    <NModal v-model:show="showModal" title="创建应用" preset="dialog" style="width: 500px">
      <NForm>
        <NFormItem label="应用名称">
          <NInput v-model:value="newApp.name" placeholder="如:我的工具箱" />
        </NFormItem>
        <NFormItem label="应用包名">
          <NInput v-model:value="newApp.packageName" placeholder="如:com.example.myapp" />
        </NFormItem>
      </NForm>
      <template #action>
        <NSpace>
          <NButton @click="showModal = false">取消</NButton>
          <NButton type="primary" :loading="creating" @click="handleCreate">创建</NButton>
        </NSpace>
      </template>
    </NModal>

    <NModal :show="!!newAppSecret" title="appSecret(仅此一次,请保存)" preset="dialog" style="width: 600px">
      <NSpace vertical>
        <NInput :value="newAppSecret ?? ''" type="textarea" readonly :rows="3" />
        <NButton type="primary" block @click="copySecret">复制到剪贴板</NButton>
      </NSpace>
      <template #action>
        <NButton type="primary" @click="newAppSecret = null">我已保存</NButton>
      </template>
    </NModal>
  </NSpace>
</template>

<script lang="ts">
import { NText } from 'naive-ui';
export default { components: { NText } };
</script>
