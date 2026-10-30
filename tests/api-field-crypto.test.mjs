import assert from 'node:assert/strict'
import fs from 'node:fs'
const { createFieldCrypto, transformFields, prepareFieldRequest } = await import(
  new URL('../src/utils/field-crypto/index.js', import.meta.url)
)
const key = '0123456789abcdeffedcba9876543210'
for (const algorithm of ['AES', 'SM4']) {
  const crypto = createFieldCrypto({ algorithm, requestKey: key, responseKey: key })
  const plain = {
    code: 0,
    data: {
      mobile: '',
      list: [{ mobile: '手机号13800138000' }, { mobile: null }, {}],
      tags: ['a', null]
    }
  }
  const original = JSON.stringify(plain)
  const paths = ['data.mobile', 'data.list[*].mobile', 'data.tags[*]', 'data.mobile', 'missing']
  const encrypted = await crypto.encryptFields(plain, paths)
  assert.equal(JSON.stringify(plain), original)
  assert.equal(encrypted.code, 0)
  assert.deepEqual(await crypto.decryptFields(encrypted, paths), plain)
  const long = '长字段'.repeat(10000)
  assert.equal(await crypto.decrypt(await crypto.encrypt(long)), long)
  await assert.rejects(crypto.decrypt('plain'))
  await assert.rejects(crypto.decrypt('fc:v2:' + algorithm + ':AAAA'))
  const cipher = await crypto.encrypt('tamper'),
    data = Buffer.from(cipher.split(':').at(-1), 'base64')
  data[data.length - 1] ^= 1
  await assert.rejects(crypto.decrypt(`fc:v1:${algorithm}:` + data.toString('base64')))
  for (const path of [
    '$',
    'data..mobile',
    'data[0]',
    '__proto__.x',
    'data.list',
    'data.list.mobile',
    'data.mobile[*]'
  ]) {
    await assert.rejects(transformFields(plain, [path], (v) => v))
  }
  for (const mini of [false, true]) {
    let config = {
      method: 'POST',
      data: { mobile: '138' },
      ...(mini
        ? { header: { 'Content-Type': 'application/json' }, custom: {} }
        : { headers: { 'Content-Type': 'application/json' } })
    }
    const rule = { request: ['mobile'] }
    await prepareFieldRequest(config, rule, crypto)
    const first = config.data.mobile
    // luch-request discards unknown top-level keys; axios serializes data before a replay.
    config = mini
      ? {
          method: config.method,
          header: config.header,
          data: config.data,
          custom: { ...config.custom }
        }
      : { ...config, data: JSON.stringify(config.data) }
    await prepareFieldRequest(config, rule, crypto)
    assert.notEqual(config.data.mobile, first)
    assert.equal(await crypto.decrypt(config.data.mobile), '138')
  }
}
{
  const vectors = JSON.parse(
    fs.readFileSync(process.argv[2] || new URL('./fixtures/field-crypto-v1.json', import.meta.url))
  )
  for (const vector of vectors) {
    const crypto = createFieldCrypto(vector)
    for (const item of vector.cases) {
      assert.equal(await crypto.decrypt(item.cipher), item.plain)
      item.jsCipher = await crypto.encrypt(item.plain)
      assert.equal(await crypto.decrypt(item.jsCipher), item.plain)
      const corrupted = Buffer.from(item.jsCipher.split(':').at(-1), 'base64')
      corrupted[corrupted.length - 1] ^= 1
      await assert.rejects(
        crypto.decrypt(`fc:v1:${vector.algorithm}:` + corrupted.toString('base64'))
      )
    }
    if (vector.algorithm === 'RSA') await assert.rejects(crypto.encrypt('长'.repeat(100)))
    console.log(vector.algorithm + ' Java -> JavaScript passed')
  }
  if (process.argv[3]) fs.writeFileSync(process.argv[3], JSON.stringify(vectors))
}
console.log('JavaScript fields, authentication, long strings and request replay checks passed')
