import request from '@/config/axios'

export interface NgiamBinding {
  userId: number
  iamUsername: string | null
}

export const getNgiamBinding = (userId: number) =>
  request.get<NgiamBinding>({ url: '/system/ngiam-binding/get', params: { userId } })
export const bindNgiam = (userId: number, iamUsername: string) =>
  request.post<boolean>({ url: '/system/ngiam-binding/bind', data: { userId, iamUsername } })
export const unbindNgiam = (userId: number) =>
  request.delete<boolean>({ url: '/system/ngiam-binding/unbind', params: { userId } })
