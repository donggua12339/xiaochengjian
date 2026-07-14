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

router.beforeEach((to) => {
  const loggedIn = !!getAccessToken();
  if (!to.meta.public && !loggedIn) {
    return { name: 'login', query: { redirect: to.fullPath } };
  }
  if (to.meta.public && loggedIn && to.name !== '2fa-verify') {
    return { name: 'dashboard' };
  }
});

export default router;
