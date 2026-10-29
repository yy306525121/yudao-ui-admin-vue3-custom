import { getTenantId } from '@/utils/auth'
import {
  NGIAM_PENDING_KEY,
  NGIAM_ERROR_KEY,
  validateNgiamCallback,
  prepareNgiamAuthorizeUrl,
  type NgiamPending,
  type NgiamCallback
} from './ngiamState'

let callback: NgiamCallback | undefined

export const currentNgiamTenant = () => String(getTenantId() ?? '')

export function saveNgiamPending(authorizeUrl: string, serviceUrl: string, tenantId: string) {
  const service = new URL(serviceUrl)
  if (service.origin !== location.origin || service.hash) {
    throw new Error('IAM 固定回调地址必须属于当前管理端站点，请联系管理员')
  }
  if (
    ['ticket', 'params', 'accountId', 'callbackUrl'].some((key) => service.searchParams.has(key))
  ) {
    throw new Error('IAM 固定回调地址不能包含登录回调参数，请联系管理员')
  }
  const redirectUrl = prepareNgiamAuthorizeUrl(authorizeUrl, serviceUrl)
  const state = new URL(redirectUrl).searchParams.get('params')
  if (!state) throw new Error('IAM 授权地址缺少登录状态，请联系管理员')
  if (tenantId !== currentNgiamTenant()) throw new Error('租户已变化，请重新登录')
  const pending: NgiamPending = { state, service: service.href, tenantId, createdAt: Date.now() }
  sessionStorage.setItem(NGIAM_PENDING_KEY, JSON.stringify(pending))
  sessionStorage.removeItem(NGIAM_ERROR_KEY)
  return redirectUrl
}

// Runs before the ordinary authentication guard, including when service is the site root.
export function captureNgiamCallback(): boolean {
  const url = new URL(location.href)
  if (
    !url.searchParams.has('ticket') &&
    !(url.searchParams.has('params') && sessionStorage.getItem(NGIAM_PENDING_KEY))
  ) {
    return false
  }
  callback = undefined
  try {
    const pending = JSON.parse(
      sessionStorage.getItem(NGIAM_PENDING_KEY) || 'null'
    ) as NgiamPending | null
    callback = validateNgiamCallback(url, pending, currentNgiamTenant())
    sessionStorage.removeItem(NGIAM_ERROR_KEY)
  } catch (error) {
    sessionStorage.setItem(
      NGIAM_ERROR_KEY,
      error instanceof Error ? error.message : '登录状态无效，请重新登录'
    )
  } finally {
    sessionStorage.removeItem(NGIAM_PENDING_KEY)
    for (const key of ['ticket', 'params', 'accountId', 'callbackUrl']) url.searchParams.delete(key)
    history.replaceState(history.state, '', url.pathname + url.search + url.hash)
  }
  return true
}

export function takeNgiamCallback(): NgiamCallback {
  const result = callback
  callback = undefined
  if (!result) {
    const error = sessionStorage.getItem(NGIAM_ERROR_KEY)
    sessionStorage.removeItem(NGIAM_ERROR_KEY)
    throw new Error(error || '登录回调已失效，请重新发起公司统一登录')
  }
  if (result.tenantId !== currentNgiamTenant()) throw new Error('租户已变化，请重新登录')
  return result
}
