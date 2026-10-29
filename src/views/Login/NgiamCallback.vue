<template>
  <div class="min-h-screen flex items-center justify-center bg-[var(--el-bg-color-page)]">
    <el-card class="w-420px max-w-[90vw]">
      <template #header>公司统一登录</template>
      <div v-if="loading" v-loading="loading" class="h-100px text-center"
        >正在验证身份并加载权限…</div
      >
      <el-result v-else icon="error" title="登录未完成" :sub-title="errorMessage">
        <template #extra>
          <el-button type="primary" @click="restart">重新登录</el-button>
        </template>
      </el-result>
    </el-card>
  </div>
</template>
<script setup lang="ts">
import type { RouteRecordRaw } from 'vue-router'
import { socialLogin } from '@/api/login'
import { setToken, removeToken } from '@/utils/auth'
import { deleteUserCache } from '@/hooks/web/useCache'
import { useUserStore } from '@/store/modules/user'
import { usePermissionStore } from '@/store/modules/permission'
import { useDictStore } from '@/store/modules/dict'
import { currentNgiamTenant, takeNgiamCallback } from '@/utils/ngiam'
import { isLocalNgiamPath } from '@/utils/ngiamState'

defineOptions({ name: 'NgiamCallback' })
const router = useRouter()
const loading = ref(true)
const errorMessage = ref('')
const restart = () => {
  removeToken()
  deleteUserCache()
  useUserStore().resetState()
  return router.replace('/login')
}

onMounted(async () => {
  let tokenSaved = false
  try {
    const callback = takeNgiamCallback()
    const response = await socialLogin(35, callback.ticket, callback.state)
    if (callback.tenantId !== currentNgiamTenant()) throw new Error('登录租户已变化，请重新登录')
    const userStore = useUserStore()
    const permissions = usePermissionStore()
    // Drop any old identity and routes before loading the CAS-bound local account.
    for (const route of permissions.getAddRouters) {
      if (route.name && router.hasRoute(route.name)) router.removeRoute(route.name)
    }
    deleteUserCache()
    userStore.resetState()
    const dictStore = useDictStore()
    dictStore.$reset()
    setToken(response)
    tokenSaved = true
    await dictStore.setDictMap()
    await userStore.setUserInfoAction()
    await permissions.generateRoutes()
    if (callback.tenantId !== currentNgiamTenant()) throw new Error('登录租户已变化，请重新登录')
    permissions.getAddRouters.forEach((route) => router.addRoute(route as RouteRecordRaw))
    const target = response.redirectPath || '/'
    if (!isLocalNgiamPath(target)) throw new Error('登录后的跳转地址无效，请联系管理员')
    await router.replace(target)
  } catch (error) {
    if (tokenSaved) {
      removeToken()
      deleteUserCache()
      useUserStore().resetState()
    }
    errorMessage.value =
      error instanceof Error
        ? error.message
        : typeof error === 'string'
          ? error
          : 'IAM 登录失败，请重新发起登录或联系管理员'
  } finally {
    loading.value = false
  }
})
</script>
