import forge from 'node-forge'
import { gcm } from '@noble/ciphers/aes'
import { sm2, sm4 } from 'sm-crypto-v2'

const forbidden = new Set(['__proto__', 'prototype', 'constructor'])
const bytes = (value) => Uint8Array.from(value, (c) => c.charCodeAt(0))
const binary = (value) => Array.from(value, (v) => String.fromCharCode(v)).join('')
const hex = (value) => Array.from(value, (v) => v.toString(16).padStart(2, '0')).join('')
const unhex = (value) => {
  if (typeof value !== 'string' || !/^(?:[a-f\d]{2})+$/i.test(value))
    throw new Error('密钥 HEX 格式无效')
  return Uint8Array.from(value.match(/../g), (v) => parseInt(v, 16))
}
const utf8 = (value) => bytes(forge.util.encodeUtf8(value))
const text = (value) => forge.util.decodeUtf8(binary(value))
const base64 = (value) => forge.util.encode64(binary(value))
const unbase64 = (value) => {
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))
    throw new Error('密文 Base64 无效')
  return bytes(forge.util.decode64(value))
}
const concat = (...arrays) => Uint8Array.from(arrays.flatMap((v) => Array.from(v)))

// 不使用 Math.random；小程序通过平台安全随机数 API 获取熵。
async function randomBytes(length) {
  if (globalThis.crypto?.getRandomValues)
    return globalThis.crypto.getRandomValues(new Uint8Array(length))
  if (typeof wx !== 'undefined' && wx.getRandomValues) {
    return new Promise((resolve, reject) =>
      wx.getRandomValues({
        length,
        success: (res) => resolve(new Uint8Array(res.randomValues)),
        fail: reject
      })
    )
  }
  throw new Error('当前运行平台不提供安全随机数 API')
}

export function transformFields(input, paths, operation) {
  // async traversal returns a fresh JSON value, never mutates the caller's object.
  return (async () => {
    const partsList = paths.map((path) => {
      if (
        typeof path !== 'string' ||
        !/^[A-Za-z_][A-Za-z0-9_]*(\[\*\])?(\.[A-Za-z_][A-Za-z0-9_]*(\[\*\])?)*$/.test(path)
      )
        throw new Error(`非法字段路径: ${path}`)
      const parts = path.split('.')
      if (parts.some((v) => forbidden.has(v.replace('[*]', ''))))
        throw new Error(`非法字段路径: ${path}`)
      return parts
    })
    if (
      !input ||
      typeof input !== 'object' ||
      (!Array.isArray(input) &&
        Object.getPrototypeOf(input) !== Object.prototype &&
        Object.getPrototypeOf(input) !== null)
    )
      throw new Error('字段加解密仅支持 JSON 对象或数组')
    const result = JSON.parse(JSON.stringify(input))
    const visited = new Set()
    async function leaf(parent, key, location) {
      if (parent[key] == null || visited.has(location)) return
      if (typeof parent[key] !== 'string') throw new Error(`加密字段必须是字符串: ${location}`)
      visited.add(location)
      parent[key] = await operation(parent[key])
    }
    async function walk(node, parts, offset, location) {
      if (node == null) return
      if (typeof node !== 'object' || Array.isArray(node))
        throw new Error(`字段路径经过非对象: ${location}`)
      const part = parts[offset],
        array = part.endsWith('[*]'),
        name = array ? part.slice(0, -3) : part
      if (!Object.prototype.hasOwnProperty.call(node, name) || node[name] == null) return
      const child = node[name],
        next = `${location}/${name}`
      if (array) {
        if (!Array.isArray(child)) throw new Error(`字段不是数组: ${next}`)
        for (let i = 0; i < child.length; i++) {
          if (offset === parts.length - 1) await leaf(child, i, `${next}/${i}`)
          else await walk(child[i], parts, offset + 1, `${next}/${i}`)
        }
      } else if (offset === parts.length - 1) await leaf(node, name, next)
      else await walk(child, parts, offset + 1, next)
    }
    for (const parts of partsList) await walk(result, parts, 0, '')
    return result
  })()
}

export function createFieldCrypto(settings) {
  const algorithm = (settings.algorithm || 'SM4').toUpperCase()
  if (!['AES', 'SM4', 'RSA', 'SM2'].includes(algorithm)) throw new Error('不支持的字段加密算法')
  const prefix = `fc:v1:${algorithm}:`
  async function encrypt(value) {
    let encrypted
    const plain = utf8(JSON.stringify(value)),
      key = settings.requestKey
    if (algorithm === 'AES' || algorithm === 'SM4') {
      const rawKey = unhex(key),
        nonce = await randomBytes(12)
      if (algorithm === 'SM4' && rawKey.length !== 16) throw new Error('SM4 密钥必须是 16 字节')
      if (algorithm === 'AES') encrypted = concat(nonce, gcm(rawKey, nonce).encrypt(plain))
      else {
        const result = sm4.encrypt(plain, rawKey, { mode: 'gcm', iv: nonce, output: 'array' })
        encrypted = concat(nonce, result.output, result.tag)
      }
    } else if (algorithm === 'RSA') {
      const publicKey = forge.pki.publicKeyFromAsn1(forge.asn1.fromDer(forge.util.decode64(key)))
      const max = Math.ceil(publicKey.n.bitLength() / 8) - 66
      if (publicKey.n.bitLength() < 2048) throw new Error('RSA 至少 2048 位')
      if (plain.length > max) throw new Error(`RSA 字段超过单块长度限制: ${max} bytes`)
      encrypted = bytes(
        publicKey.encrypt(binary(plain), 'RSA-OAEP', {
          md: forge.md.sha256.create(),
          mgf1: { md: forge.md.sha256.create() },
          seed: binary(await randomBytes(32))
        })
      )
    } else {
      if (!/^04[0-9a-f]{128}$/i.test(key) || !sm2.verifyPublicKey(key))
        throw new Error('SM2 公钥格式无效')
      await sm2.initRNGPool()
      // sm-crypto omits C1's 04 prefix; wire format includes it, matching BC.
      encrypted = unhex('04' + sm2.doEncrypt(plain, key, 1))
    }
    return prefix + base64(encrypted)
  }
  async function decrypt(value) {
    if (!value.startsWith(prefix)) throw new Error('字段密文版本或算法不匹配')
    const data = unbase64(value.slice(prefix.length)),
      key = settings.responseKey
    let plain
    if (algorithm === 'AES' || algorithm === 'SM4') {
      const rawKey = unhex(key)
      if (data.length < 28) throw new Error('字段密文过短')
      if (algorithm === 'SM4' && rawKey.length !== 16) throw new Error('SM4 密钥必须是 16 字节')
      const nonce = data.slice(0, 12),
        ciphertext = data.slice(12)
      plain =
        algorithm === 'AES'
          ? gcm(rawKey, nonce).decrypt(ciphertext)
          : sm4.decrypt(ciphertext.slice(0, -16), rawKey, {
              mode: 'gcm',
              iv: nonce,
              tag: ciphertext.slice(-16),
              output: 'array'
            })
    } else if (algorithm === 'RSA') {
      const privateKey = forge.pki.privateKeyFromAsn1(forge.asn1.fromDer(forge.util.decode64(key)))
      if (
        privateKey.n.bitLength() < 2048 ||
        data.length !== Math.ceil(privateKey.n.bitLength() / 8)
      )
        throw new Error('RSA 密钥或单块密文长度无效')
      // Feed platform entropy for forge's private-key blinding, including on mini programs.
      forge.random.collect(binary(await randomBytes(1024)))
      plain = bytes(
        privateKey.decrypt(binary(data), 'RSA-OAEP', {
          md: forge.md.sha256.create(),
          mgf1: { md: forge.md.sha256.create() }
        })
      )
    } else {
      if (!/^[0-9a-f]{64}$/i.test(key) || data.length < 97 || data[0] !== 4)
        throw new Error('SM2 密钥或密文格式无效')
      plain = sm2.doDecrypt(hex(data.slice(1)), key, 1, { output: 'array' })
      if (plain.length === 0) throw new Error('SM2 字段认证失败')
    }
    const decoded = JSON.parse(text(plain))
    if (typeof decoded !== 'string') throw new Error('字段明文必须是 JSON 字符串')
    return decoded
  }
  return {
    encrypt,
    decrypt,
    encryptFields: (input, paths) => transformFields(input, paths, encrypt),
    decryptFields: (input, paths) => transformFields(input, paths, decrypt)
  }
}

// Keep plain JSON for a 401 replay, then encrypt afresh exactly once on every send.
export async function prepareFieldRequest(config, rule, crypto) {
  if (
    rule?.response?.length &&
    (['blob', 'arraybuffer'].includes(config.responseType) ||
      ['UPLOAD', 'DOWNLOAD'].includes(String(config.method).toUpperCase()))
  )
    throw new Error('字段解密仅支持 JSON 响应')
  if (!rule?.request?.length) return config
  if (['GET', 'HEAD', 'UPLOAD', 'DOWNLOAD'].includes(String(config.method).toUpperCase()))
    throw new Error('字段加密仅支持 JSON 请求体')
  const headers = config.headers || config.header || {}
  const type = String(headers['Content-Type'] || headers['content-type'] || '').toLowerCase()
  if (!type.includes('application/json') && !type.includes('+json'))
    throw new Error('字段加密仅支持 JSON 请求体')
  const storage = config.custom || config
  if (!Object.prototype.hasOwnProperty.call(storage, '__fieldCryptoPlainData')) {
    storage.__fieldCryptoPlainData = JSON.parse(JSON.stringify(config.data))
  }
  config.data = await crypto.encryptFields(storage.__fieldCryptoPlainData, rule.request)
  return config
}
