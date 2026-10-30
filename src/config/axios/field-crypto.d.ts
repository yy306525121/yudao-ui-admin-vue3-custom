import 'axios'
import type { FieldCryptoRule } from '@/utils/field-crypto'
declare module 'axios' {
  interface AxiosRequestConfig {
    fieldCrypto?: FieldCryptoRule
    __fieldCryptoPlainData?: unknown
  }
}
