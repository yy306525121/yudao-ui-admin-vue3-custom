export const NGIAM_PENDING_KEY = 'NGIAM_CAS_PENDING'
export const NGIAM_ERROR_KEY = 'NGIAM_CAS_ERROR'

export interface NgiamPending {
  state: string
  tenantId: string
  service: string
  createdAt: number
}

export interface NgiamCallback {
  ticket: string
  state: string
  tenantId: string
}

export const isLocalNgiamPath = (path: string): boolean =>
  path.startsWith('/') && !path.startsWith('//') && !/[\\%\u0000-\u001f\u007f]/.test(path)

export function isNgiamBaseUrl(value: unknown): value is string {
  if (
    typeof value !== 'string' ||
    value.length > 2048 ||
    !/^https?:\/\/[^/?#]+\/?$/.test(value) ||
    /[\s%]/.test(value)
  ) {
    return false
  }
  try {
    const url = new URL(value)
    const authority = value.replace(/^https?:\/\//, '').replace(/\/$/, '')
    return !url.username && !url.password && !authority.endsWith(':') && url.port !== '0'
  } catch {
    return false
  }
}

/** Keep the actual IAM navigation URL aligned with the registered CAS service. */
export function prepareNgiamAuthorizeUrl(authorizeUrl: string, serviceUrl: string): string {
  const url = new URL(authorizeUrl)
  if (!['http:', 'https:'].includes(url.protocol) || url.hash || url.username || url.password) {
    throw new Error('IAM 授权地址无效，请联系管理员')
  }
  // These belong to IAM's internal login page, not the external CAS entry.
  url.searchParams.delete('appId')
  url.searchParams.delete('loginType')
  const services = url.searchParams.getAll('service')
  if (services.some((value) => value && value !== serviceUrl)) {
    throw new Error('IAM 授权地址中的 service 与固定回调地址不一致，请重新登录或联系管理员')
  }
  // URLSearchParams encodes the complete service once, including its own query parameters.
  url.searchParams.set('service', serviceUrl)
  return url.href
}

export function validateNgiamCallback(
  url: URL,
  pending: NgiamPending | null,
  tenantId: string,
  now = Date.now()
): NgiamCallback {
  if (!pending || !pending.state || !pending.service || !Number.isFinite(pending.createdAt)) {
    throw new Error('登录状态缺失，请重新发起公司统一登录')
  }
  if (now < pending.createdAt || now - pending.createdAt > 5 * 60 * 1000) {
    throw new Error('登录状态已过期，请重新发起公司统一登录')
  }
  if (pending.tenantId !== tenantId) {
    throw new Error('登录租户已变化，请重新选择租户并登录')
  }
  const service = new URL(pending.service)
  if (service.origin !== url.origin || service.pathname !== url.pathname || service.hash) {
    throw new Error('登录回调地址不匹配，请重新登录')
  }
  // Compare the complete registered URL after removing only the CAS callback parameters.
  const actual = new URL(url)
  for (const key of ['ticket', 'params', 'accountId', 'callbackUrl'])
    actual.searchParams.delete(key)
  if (
    actual.hash !== service.hash ||
    actual.searchParams.toString() !== service.searchParams.toString()
  ) {
    throw new Error('登录回调地址参数不匹配，请重新登录')
  }
  if (
    url.searchParams.getAll('params').length !== 1 ||
    url.searchParams.get('params') !== pending.state
  ) {
    throw new Error('登录状态不匹配，请重新发起公司统一登录')
  }
  const ticket = url.searchParams.get('ticket')
  if (url.searchParams.getAll('ticket').length !== 1 || !ticket || ticket.length > 256) {
    throw new Error('登录票据缺失或无效，请重新登录')
  }
  return { ticket, state: pending.state, tenantId: pending.tenantId }
}
