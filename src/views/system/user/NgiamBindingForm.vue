<template>
  <Dialog v-model="visible" title="IAM 绑定">
    <el-form ref="formRef" v-loading="loading" :model="form" :rules="rules" label-width="110px">
      <el-form-item label="本地用户">{{ userLabel }}</el-form-item>
      <el-form-item label="IAM 账户名" prop="iamUsername">
        <el-input
          v-model="form.iamUsername"
          :disabled="bound || !canUpdate"
          maxlength="32"
          placeholder="请输入 IAM 账户名，区分大小写"
        />
      </el-form-item>
      <el-alert
        v-if="bound"
        title="已绑定。更换 IAM 账户须先解绑。"
        type="info"
        :closable="false"
      />
    </el-form>
    <template #footer>
      <el-button
        v-if="!bound"
        v-hasPermi="['system:ngiam-binding:update']"
        type="primary"
        :disabled="loading || !loaded"
        @click="save"
        >绑定</el-button
      >
      <el-button
        v-else
        v-hasPermi="['system:ngiam-binding:update']"
        type="danger"
        :disabled="loading || !loaded"
        @click="unbind"
        >解绑</el-button
      >
      <el-button @click="visible = false">关闭</el-button>
    </template>
  </Dialog>
</template>
<script setup lang="ts">
import * as Api from '@/api/system/user/ngiamBinding'
import { checkPermi } from '@/utils/permission'
import type { UserVO } from '@/api/system/user'

defineOptions({ name: 'NgiamBindingForm' })
const message = useMessage()
const visible = ref(false)
const loading = ref(false)
const loaded = ref(false)
const bound = ref(false)
const userId = ref(0)
const userLabel = ref('')
const formRef = ref()
const form = reactive({ iamUsername: '' })
const canUpdate = computed(() => checkPermi(['system:ngiam-binding:update']))
const rules = {
  iamUsername: [
    {
      validator: (_rule, value, callback) =>
        callback(
          typeof value === 'string' && value.trim().length > 0 && value.length <= 32
            ? undefined
            : new Error('请输入 1-32 字符的 IAM 账户名')
        ),
      trigger: 'blur'
    }
  ]
}
const load = async () => {
  const result = await Api.getNgiamBinding(userId.value)
  form.iamUsername = result.iamUsername || ''
  bound.value = result.iamUsername !== null
  loaded.value = true
}
const open = async (user: UserVO) => {
  userId.value = user.id
  userLabel.value = `${user.nickname} (${user.username})`
  form.iamUsername = ''
  bound.value = false
  loaded.value = false
  visible.value = true
  loading.value = true
  try {
    await load()
  } finally {
    loading.value = false
  }
}
const save = async () => {
  if (!(await formRef.value.validate())) return
  loading.value = true
  try {
    await Api.bindNgiam(userId.value, form.iamUsername)
    message.success('IAM 绑定成功')
    await load()
  } finally {
    loading.value = false
  }
}
const unbind = async () => {
  await message.confirm('确认解除此用户的 IAM 绑定？解绑后将无法使用该 IAM 账户登录。')
  loading.value = true
  try {
    await Api.unbindNgiam(userId.value)
    message.success('IAM 已解绑')
    await load()
  } finally {
    loading.value = false
  }
}
defineExpose({ open })
</script>
