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
  encrypt(value: string | number): Promise<string>
  decrypt(value: string): Promise<string | number>
  encryptFields(input: unknown, paths: string[]): Promise<any>
  decryptFields(input: unknown, paths: string[]): Promise<any>
}
export function createFieldCrypto(settings: FieldCryptoSettings): FieldCryptoClient
export function transformFields(
  input: unknown,
  paths: string[],
  operation: (value: string | number) => string | number | Promise<string | number>
): Promise<any>
export function prepareFieldRequest<T>(
  config: T,
  rule: FieldCryptoRule | undefined,
  crypto: FieldCryptoClient
): Promise<T>
