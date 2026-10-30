import { createFieldCrypto } from './index.js'

// 密钥格式和协议见 docs/api加解密.md；无字段配置时不会使用密钥。
export const fieldCrypto = createFieldCrypto({
  algorithm: import.meta.env.VITE_API_FIELD_CRYPTO_ALGORITHM || 'SM4',
  requestKey: import.meta.env.VITE_API_FIELD_CRYPTO_REQUEST_KEY || '',
  responseKey: import.meta.env.VITE_API_FIELD_CRYPTO_RESPONSE_KEY || ''
})
