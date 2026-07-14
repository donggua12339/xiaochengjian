<script setup lang="ts">
import { NConfigProvider, NMessageProvider, NDialogProvider, NLoadingBarProvider, zhCN, dateZhCN } from 'naive-ui';
</script>

<template>
  <NConfigProvider :locale="zhCN" :date-locale="dateZhCN">
    <NLoadingBarProvider>
      <NDialogProvider>
        <NMessageProvider>
          <RouterView />
        </NMessageProvider>
      </NDialogProvider>
    </NLoadingBarProvider>
  </NConfigProvider>
</template>
