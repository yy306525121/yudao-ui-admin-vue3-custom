<template>
  <Dialog v-model="dialogVisible" :title="dialogTitle">
    <el-form
      ref="formRef"
      v-loading="formLoading"
      :model="formData"
      :rules="formRules"
      label-width="120px"
    >
      <el-form-item label="应用名" prop="name">
        <el-input v-model="formData.name" placeholder="请输入应用名" />
      </el-form-item>
      <el-form-item label="社交平台" prop="socialType">
        <el-radio-group v-model="formData.socialType">
          <el-radio
            v-for="dict in getIntDictOptions(DICT_TYPE.SYSTEM_SOCIAL_TYPE)"
            :key="dict.value"
            :value="dict.value"
          >
            {{ dict.label }}
          </el-radio>
        </el-radio-group>
      </el-form-item>
      <el-form-item label="用户类型" prop="userType">
        <el-radio-group v-model="formData.userType">
          <el-radio v-for="dict in userTypes" :key="dict.value" :value="dict.value">
            {{ dict.label }}
          </el-radio>
        </el-radio-group>
      </el-form-item>
      <el-form-item :label="isCas ? '应用编码（可选）' : '客户端编号'" prop="clientId">
        <el-input
          v-model="formData.clientId"
          :placeholder="
            isCas ? '例如 ljsc，仅作记录，不参与 CAS 登录' : '请输入客户端编号,对应各平台的appKey'
          "
        />
      </el-form-item>
      <el-form-item v-if="!isCas" label="客户端密钥" prop="clientSecret">
        <el-input
          v-model="formData.clientSecret"
          placeholder="请输入客户端密钥,对应各平台的appSecret"
        />
      </el-form-item>
      <el-form-item label="agentId" prop="agentId" v-if="formData!.socialType === 30">
        <el-input v-model="formData.agentId" placeholder="授权方的网页应用 ID，有则填" />
      </el-form-item>
      <template v-if="isCas">
        <el-form-item label="对接地址" prop="casBaseUrl">
          <el-input
            v-model="formData.casBaseUrl"
            placeholder="例如 http://10.1.102.64:80，只填协议、主机及端口"
            maxlength="2048"
          />
        </el-form-item>
        <el-form-item label="固定回调地址" prop="casService">
          <el-input
            v-model="formData.casService"
            placeholder="IAM 注册的管理端回调地址，须与访问站点同源"
            maxlength="2048"
          />
        </el-form-item>
        <el-form-item label="请求超时(ms)" prop="casTimeoutMillis">
          <el-input-number
            v-model="formData.casTimeoutMillis"
            :min="100"
            :max="60000"
            :step="100"
          />
        </el-form-item>
      </template>
      <el-form-item label="状态" prop="status">
        <el-radio-group v-model="formData.status">
          <el-radio
            v-for="dict in getIntDictOptions(DICT_TYPE.COMMON_STATUS)"
            :key="dict.value"
            :value="dict.value"
          >
            {{ dict.label }}
          </el-radio>
        </el-radio-group>
      </el-form-item>
    </el-form>
    <template #footer>
      <el-button :disabled="formLoading" type="primary" @click="submitForm">确 定</el-button>
      <el-button @click="dialogVisible = false">取 消</el-button>
    </template>
  </Dialog>
</template>
<script lang="ts" setup>
import { DICT_TYPE, getIntDictOptions } from '@/utils/dict'
import * as SocialClientApi from '@/api/system/social/client'
import { isNgiamBaseUrl } from '@/utils/ngiamState'

const { t } = useI18n() // 国际化
const message = useMessage() // 消息弹窗

const dialogVisible = ref(false) // 弹窗的是否展示
const dialogTitle = ref('') // 弹窗的标题
const formLoading = ref(false) // 表单的加载中：1）修改时的数据加载；2）提交的按钮禁用
const formType = ref('') // 表单的类型：create - 新增；update - 修改
const formData = ref<Partial<SocialClientApi.SocialClientVO>>({
  id: undefined,
  name: undefined,
  socialType: undefined,
  userType: undefined,
  clientId: undefined,
  clientSecret: undefined,
  agentId: undefined,
  casBaseUrl: undefined,
  casService: undefined,
  casTimeoutMillis: 5000,
  status: 0
})
const isCas = computed(() => formData.value.socialType === 35)
const userTypes = computed(() =>
  getIntDictOptions(DICT_TYPE.USER_TYPE).filter((item) => !isCas.value || item.value === 2)
)
const casUrlRule = (_rule, value, callback) => {
  if (!isCas.value) return callback()
  try {
    const url = new URL(value)
    if (
      !['http:', 'https:'].includes(url.protocol) ||
      url.username ||
      url.password ||
      url.hash ||
      value.length > 2048
    )
      throw new Error()
    callback()
  } catch {
    callback(new Error('请输入完整有效的 http/https 地址'))
  }
}
watch(isCas, (value) => {
  if (value) formData.value.userType = 2
  formRef.value?.clearValidate()
})
const formRules = computed(() => ({
  name: [{ required: true, message: '应用名不能为空', trigger: 'blur' }],
  socialType: [{ required: true, message: '社交平台不能为空', trigger: 'blur' }],
  userType: [{ required: true, message: '用户类型不能为空', trigger: 'blur' }],
  clientId: [{ required: !isCas.value, message: '客户端编号不能为空', trigger: 'blur' }],
  clientSecret: [{ required: !isCas.value, message: '客户端密钥不能为空', trigger: 'blur' }],
  casBaseUrl: [
    {
      validator: (_rule, value, callback) =>
        callback(
          !isCas.value || isNgiamBaseUrl(value)
            ? undefined
            : new Error('请仅填写 http/https 协议、主机和端口，不带路径或参数')
        ),
      trigger: 'blur'
    }
  ],
  casService: [{ validator: casUrlRule, trigger: 'blur' }],
  status: [{ required: true, message: '状态不能为空', trigger: 'blur' }]
}))
const formRef = ref() // 表单 Ref

/** 打开弹窗 */
const open = async (type: string, id?: number) => {
  dialogVisible.value = true
  dialogTitle.value = t('action.' + type)
  formType.value = type
  resetForm()
  // 修改时，设置数据
  if (id) {
    formLoading.value = true
    try {
      formData.value = await SocialClientApi.getSocialClient(id)
    } finally {
      formLoading.value = false
    }
  }
}
defineExpose({ open }) // 提供 open 方法，用于打开弹窗

/** 提交表单 */
const emit = defineEmits(['success']) // 定义 success 事件，用于操作成功后的回调
const submitForm = async () => {
  // 校验表单
  if (!formRef) return
  const valid = await formRef.value.validate()
  if (!valid) return
  // 提交请求
  formLoading.value = true
  try {
    const data = { ...formData.value } as unknown as SocialClientApi.SocialClientVO
    if (isCas.value) {
      data.clientId = data.clientId ?? ''
      data.clientSecret = ''
      data.agentId = ''
      data.userType = 2
    } else {
      data.casBaseUrl = undefined
      data.casService = undefined
      data.casTimeoutMillis = undefined
    }
    if (formType.value === 'create') {
      await SocialClientApi.createSocialClient(data)
      message.success(t('common.createSuccess'))
    } else {
      await SocialClientApi.updateSocialClient(data)
      message.success(t('common.updateSuccess'))
    }
    dialogVisible.value = false
    // 发送操作成功的事件
    emit('success')
  } finally {
    formLoading.value = false
  }
}

/** 重置表单 */
const resetForm = () => {
  formData.value = {
    id: undefined,
    name: undefined,
    socialType: undefined,
    userType: undefined,
    clientId: undefined,
    clientSecret: undefined,
    agentId: undefined,
    casBaseUrl: undefined,
    casService: undefined,
    casTimeoutMillis: 5000,
    status: 0
  }
  formRef.value?.resetFields()
}
</script>
