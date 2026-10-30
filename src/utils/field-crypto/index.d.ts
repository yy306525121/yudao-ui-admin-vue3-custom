export interface FieldCryptoRule {
  request?: string[]
  response?: string[]
}
export interface FieldCryptoSettings {
  algorithm?: string
  requestKey: string
  responseKey: string
}
export interface FieldCryptoClient {
  encrypt(value: string): Promise<string>
  decrypt(value: string): Promise<string>
  encryptFields(input: unknown, paths: string[]): Promise<any>
  decryptFields(input: unknown, paths: string[]): Promise<any>
}
export function createFieldCrypto(settings: FieldCryptoSettings): FieldCryptoClient
export function transformFields(
  input: unknown,
  paths: string[],
  operation: (value: string) => string | Promise<string>
): Promise<any>
export function prepareFieldRequest<T>(
  config: T,
  rule: FieldCryptoRule | undefined,
  crypto: FieldCryptoClient
): Promise<T>
