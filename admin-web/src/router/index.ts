import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router';
import { getAccessToken } from '@/api/client';

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/Login.vue'),
    meta: { public: true },
  },
  {
    path: '/register',
    name: 'register',
    component: () => import('@/views/Register.vue'),
    meta: { public: true },
  },
  {
    path: '/2fa-verify',
    name: '2fa-verify',
    component: () => import('@/views/TwoFactorVerify.vue'),
    meta: { public: true },
  },
  {
    path: '/',
    component: () => import('@/layouts/MainLayout.vue'),
    redirect: '/dashboard',
    children: [
      {
        path: 'dashboard',
        name: 'dashboard',
        component: () => import('@/views/Dashboard.vue'),
      },
      {
        path: 'apps',
        name: 'apps',
        component: () => import('@/views/Apps.vue'),
      },
      {
        path: 'sdk-guide',
        name: 'sdk-guide',
        component: () => import('@/views/SdkGuide.vue'),
      },
      {
        path: 'sdk-config',
        name: 'sdk-config',
        component: () => import('@/views/SdkConfig.vue'),
      },
      {
        path: 'audit',
        name: 'audit',
        component: () => import('@/views/Audit.vue'),
      },
      {
        path: 'packer',
        name: 'packer',
        component: () => import('@/views/Packer.vue'),
      },
      {
        path: 'harden-config',
        name: 'harden-config',
        component: () => import('@/views/HardenConfig.vue'),
      },
      {
        path: 'quality-report',
        name: 'quality-report',
        component: () => import('@/views/QualityReport.vue'),
      },
      {
        path: 'harden-upload',
        name: 'harden-upload',
        component: () => import('@/views/HardenUpload.vue'),
      },
      {
        path: 'harden-tasks',
        name: 'harden-tasks',
        component: () => import('@/views/HardenTasks.vue'),
      },
      {
        path: 'apps/:id',
        name: 'app-detail',
        component: () => import('@/views/AppDetail.vue'),
      },
      {
        path: 'settings',
        name: 'settings',
        component: () => import('@/views/Settings.vue'),
      },
    ],
  },
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

/** 解码 JWT payload 检查是否过期(不验签,仅前端预检) */
function isTokenExpired(token: string | null): boolean {
  if (!token) return true;
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    if (payload.exp && payload.exp * 1000 < Date.now()) return true;
  } catch {
    return true;
  }
  return false;
}

router.beforeEach((to) => {
  const token = getAccessToken();
  const loggedIn = !!token && !isTokenExpired(token);

  // token 过期: 清除并跳转登录
  if (token && isTokenExpired(token)) {
    localStorage.removeItem('xcj_access_token');
    localStorage.removeItem('xcj_refresh_token');
  }

  if (!to.meta.public && !loggedIn) {
    return { name: 'login', query: { redirect: to.fullPath } };
  }
  if (to.meta.public && loggedIn && to.name !== '2fa-verify') {
    return { name: 'dashboard' };
  }
});

export default router;
