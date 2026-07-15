<script setup lang="ts">
import { onMounted, ref, h, computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import {
  NCard, NTabs, NTabPane, NDataTable, NButton, NSpace, NModal, NForm, NFormItem,
  NInput, NInputNumber, NSelect, NTag, NPopconfirm,
  NStatistic, NGrid, NGridItem, useMessage, type DataTableColumns,
} from 'naive-ui';
import { appsApi, type AppDetail } from '@/api/apps';
import { cardsApi, type CardKeyItem, type GenerateCardsDto } from '@/api/cards';
import {
  CARD_KEY_TYPE_LABELS, BINDING_STRATEGY_LABELS, CARD_STATUS_LABELS,
  type CardKeyType, type BindingStrategy,
} from '@/api/types';
import { useAuthStore } from '@/stores/auth';

const route = useRoute();
const router = useRouter();
const message = useMessage();
const auth = useAuthStore();

const appId = computed(() => route.params.id as string);
const loading = ref(true);
const app = ref<AppDetail | null>(null);

// 卡密列表
const cardsLoading = ref(false);
const cards = ref<CardKeyItem[]>([]);
const cardsTotal = ref(0);
const cardsPage = ref(1);
const cardsPageSize = ref(20);

// 生成卡密弹窗
const showGenerate = ref(false);
const generating = ref(false);
const genForm = ref<GenerateCardsDto>({
  type: 'MONTH',
  bindingStrategy: 'FIRST_BIND',
  maxDevices: 1,
  count: 100,
});
const generatedKeys = ref<string[] | null>(null);
const generatedBatchId = ref('');

// 重置 appSecret
const newAppSecret = ref<string | null>(null);

// 设置表单
const settingsForm = ref({
  rateLimitIpPerMinute: 60,
  rateLimitDevicePerMinute: 30,
  offlineCacheDays: 7,
});

async function loadApp() {
  loading.value = true;
  try {
    app.value = await appsApi.getById(appId.value);
    settingsForm.value = {
      rateLimitIpPerMinute: app.value.rateLimitIpPerMinute ?? 60,
      rateLimitDevicePerMinute: app.value.rateLimitDevicePerMinute ?? 30,
      offlineCacheDays: app.value.offlineCacheDays,
    };
  } catch (error) {
    message.error(auth.handleError(error));
    router.push('/apps');
  } finally {
    loading.value = false;
  }
}

async function loadCards() {
  cardsLoading.value = true;
  try {
    const result = await cardsApi.list(appId.value, {
      page: cardsPage.value,
      pageSize: cardsPageSize.value,
    });
    cards.value = result.items;
    cardsTotal.value = result.total;
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    cardsLoading.value = false;
  }
}

async function handleGenerate() {
  generating.value = true;
  try {
    const result = await cardsApi.generate(appId.value, genForm.value);
    generatedKeys.value = result.cardKeys;
    generatedBatchId.value = result.batchId;
    message.success(`成功生成 ${result.count} 张卡密`);
    showGenerate.value = false;
    await loadCards();
  } catch (error) {
    message.error(auth.handleError(error));
  } finally {
    generating.value = false;
  }
}

async function handleDisableCard(card: CardKeyItem) {
  try {
    await cardsApi.disable(appId.value, card.id);
    message.success('已禁用');
    await loadCards();
  } catch (error) {
    message.error(auth.handleError(error));
  }
}

async function handleEnableCard(card: CardKeyItem) {
  try {
    await cardsApi.enable(appId.value, card.id);
    message.success('已启用');
    await loadCards();
  } catch (error) {
    message.error(auth.handleError(error));
  }
}

async function handleRotateSecret() {
  try {
    const result = await appsApi.rotateSecret(appId.value);
    newAppSecret.value = result.appSecret;
    await loadApp();
  } catch (error) {
    message.error(auth.handleError(error));
  }
}

async function handleSaveSettings() {
  if (!app.value) return;
  try {
    await appsApi.update(appId.value, settingsForm.value);
    message.success('设置已保存');
    await loadApp();
  } catch (error) {
    message.error(auth.handleError(error));
  }
}

async function handleDeleteApp() {
  try {
    await appsApi.delete(appId.value);
    message.success('应用已删除');
    router.push('/apps');
  } catch (error) {
    message.error(auth.handleError(error));
  }
}

function copyGeneratedKeys() {
  if (generatedKeys.value) {
    const text = generatedKeys.value.join('\n');
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    message.success('已复制全部卡密');
  }
}

function downloadGeneratedKeys() {
  if (!generatedKeys.value) return;
  const blob = new Blob([generatedKeys.value.join('\n')], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `cards-${generatedBatchId.value}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}

const cardColumns: DataTableColumns<CardKeyItem> = [
  { title: '前缀', key: 'cardKeyPrefix', width: 80, render: (r) => h(NTag, { size: 'small' }, () => r.cardKeyPrefix) },
  { title: '类型', key: 'type', width: 80, render: (r) => CARD_KEY_TYPE_LABELS[r.type as CardKeyType] },
  { title: '绑定', key: 'bindingStrategy', width: 120, render: (r) => BINDING_STRATEGY_LABELS[r.bindingStrategy as BindingStrategy] },
  { title: '状态', key: 'status', width: 80, render: (r) => {
      const label = CARD_STATUS_LABELS[r.status] ?? r.status;
      const type = r.status === 'ACTIVE' ? 'success' : r.status === 'DISABLED' ? 'error' : 'default';
      return h(NTag, { size: 'small', type }, () => label);
    }
  },
  { title: '已绑设备', key: 'boundDevicesCount', width: 80 },
  { title: '激活时间', key: 'activatedAt', width: 160, render: (r) => r.activatedAt ? new Date(r.activatedAt).toLocaleString() : '-' },
  { title: '创建时间', key: 'createdAt', width: 160, render: (r) => new Date(r.createdAt).toLocaleString() },
  {
    title: '操作', key: 'actions', width: 120,
    render: (r) => h(NSpace, { size: 'small' }, () => [
      r.status === 'ACTIVE'
        ? h(NButton, { size: 'tiny', type: 'warning', quaternary: true, onClick: () => handleDisableCard(r) }, () => '禁用')
        : h(NButton, { size: 'tiny', type: 'success', quaternary: true, onClick: () => handleEnableCard(r) }, () => '启用'),
    ]),
  },
];

const typeOptions = Object.entries(CARD_KEY_TYPE_LABELS).map(([value, label]) => ({ value, label }));
const bindingOptions = Object.entries(BINDING_STRATEGY_LABELS).map(([value, label]) => ({ value, label }));

onMounted(async () => {
  await loadApp();
  await loadCards();
});
</script>

<template>
  <NSpace v-if="app" vertical size="large">
    <NCard>
      <NSpace justify="space-between" align="center">
        <NSpace vertical size="small">
          <h2 style="margin: 0">{{ app.name }}</h2>
          <NSpace size="small">
            <NTag size="small">{{ app.packageName }}</NTag>
            <NTag size="small" type="info">appSecret: {{ app.appSecretPrefix }}****</NTag>
          </NSpace>
        </NSpace>
        <NButton @click="router.push('/apps')">返回列表</NButton>
      </NSpace>
    </NCard>

    <NCard>
      <NTabs type="line">
        <!-- 卡密管理 -->
        <NTabPane name="cards" tab="卡密管理">
          <NSpace vertical>
            <NSpace justify="space-between">
              <NStatistic label="卡密总数" :value="cardsTotal" />
              <NButton type="primary" @click="showGenerate = true">批量生成卡密</NButton>
            </NSpace>
            <NDataTable
              :columns="cardColumns"
              :data="cards"
              :loading="cardsLoading"
              :bordered="false"
              :pagination="{
                page: cardsPage,
                pageSize: cardsPageSize,
                itemCount: cardsTotal,
                showSizePicker: true,
                pageSizes: [20, 50, 100],
                onUpdatePage: (p: number) => { cardsPage = p; loadCards(); },
                onUpdatePageSize: (s: number) => { cardsPageSize = s; cardsPage = 1; loadCards(); },
              }"
            />
          </NSpace>
        </NTabPane>

        <!-- 统计 -->
        <NTabPane name="stats" tab="统计">
          <NGrid :cols="4" :x-gap="16" :y-gap="16">
            <NGridItem><NStatistic label="卡密总数" :value="cardsTotal" /></NGridItem>
            <NGridItem><NStatistic label="活跃设备" :value="0" /></NGridItem>
            <NGridItem><NStatistic label="今日验证" :value="0" /></NGridItem>
            <NGridItem><NStatistic label="今日激活" :value="0" /></NGridItem>
          </NGrid>
          <NText depth="3" style="display: block; margin-top: 16px">
            详细统计图表在 M1.7 后端接口完成后接入
          </NText>
        </NTabPane>

        <!-- 设置 -->
        <NTabPane name="settings" tab="设置">
          <NSpace vertical size="large">
            <NCard title="限流与缓存配置" size="small">
              <NForm label-placement="left" :label-width="180">
                <NFormItem label="IP 限流(次/分钟)">
                  <NInputNumber v-model:value="settingsForm.rateLimitIpPerMinute" :min="1" :max="10000" />
                </NFormItem>
                <NFormItem label="设备限流(次/分钟)">
                  <NInputNumber v-model:value="settingsForm.rateLimitDevicePerMinute" :min="1" :max="10000" />
                </NFormItem>
                <NFormItem label="离线缓存天数">
                  <NInputNumber v-model:value="settingsForm.offlineCacheDays" :min="1" :max="30" />
                </NFormItem>
                <NButton type="primary" @click="handleSaveSettings">保存设置</NButton>
              </NForm>
            </NCard>

            <NCard title="appSecret" size="small">
              <NSpace vertical>
                <NText depth="3">重置 appSecret 后,旧 SDK 集成将无法验证。请通知所有客户端更新。</NText>
                <NPopconfirm @positive-click="handleRotateSecret">
                  <template #trigger>
                    <NButton type="warning">重置 appSecret</NButton>
                  </template>
                  确认重置?旧 appSecret 立即失效。
                </NPopconfirm>
              </NSpace>
            </NCard>

            <NCard title="危险操作" size="small">
              <NPopconfirm @positive-click="handleDeleteApp">
                <template #trigger>
                  <NButton type="error">删除应用</NButton>
                </template>
                确认删除应用「{{ app.name }}」?此操作不可恢复,所有卡密和设备记录将被级联删除。
              </NPopconfirm>
            </NCard>
          </NSpace>
        </NTabPane>
      </NTabs>
    </NCard>

    <!-- 生成卡密弹窗 -->
    <NModal v-model:show="showGenerate" title="批量生成卡密" preset="dialog" style="width: 500px">
      <NForm label-placement="left" :label-width="120">
        <NFormItem label="卡密类型">
          <NSelect v-model:value="genForm.type" :options="typeOptions" />
        </NFormItem>
        <NFormItem label="绑定策略">
          <NSelect v-model:value="genForm.bindingStrategy" :options="bindingOptions" />
        </NFormItem>
        <NFormItem v-if="genForm.bindingStrategy === 'N_DEVICES'" label="最大设备数">
          <NInputNumber v-model:value="genForm.maxDevices" :min="1" :max="5" />
        </NFormItem>
        <NFormItem label="生成数量">
          <NInputNumber v-model:value="genForm.count" :min="1" :max="10000" />
        </NFormItem>
        <NFormItem label="备注">
          <NInput v-model:value="genForm.remark" placeholder="可选" />
        </NFormItem>
      </NForm>
      <template #action>
        <NSpace>
          <NButton @click="showGenerate = false">取消</NButton>
          <NButton type="primary" :loading="generating" @click="handleGenerate">生成</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- 生成结果弹窗 -->
    <NModal :show="!!generatedKeys" title="卡密已生成(仅此一次,请保存)" preset="dialog" style="width: 700px">
      <NSpace vertical>
        <NText depth="3">批次 ID: {{ generatedBatchId }}</NText>
        <NInput
          :value="generatedKeys?.join('\n') ?? ''"
          type="textarea"
          readonly
          :rows="10"
          style="font-family: monospace"
        />
        <NSpace>
          <NButton @click="copyGeneratedKeys">复制全部</NButton>
          <NButton type="primary" @click="downloadGeneratedKeys">下载 TXT</NButton>
        </NSpace>
      </NSpace>
      <template #action>
        <NButton type="primary" @click="generatedKeys = null">我已保存</NButton>
      </template>
    </NModal>

    <!-- 新 appSecret 弹窗 -->
    <NModal :show="!!newAppSecret" title="新 appSecret(仅此一次)" preset="dialog" style="width: 600px">
      <NInput :value="newAppSecret ?? ''" type="textarea" readonly :rows="3" />
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
