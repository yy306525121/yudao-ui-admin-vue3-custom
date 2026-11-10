import { createCipheriv, randomBytes } from 'node:crypto'
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
      amount: 12.34,
      numericString: '123',
      numbers: [0, -123, 12.34, '123', null],
      nested: [{ count: 123 }, { count: null }, {}],
      list: [{ mobile: '手机号13800138000' }, { mobile: null }, {}],
      tags: ['a', null]
    }
  }
  const original = JSON.stringify(plain)
  const paths = [
    'data.amount',
    'data.numericString',
    'data.numbers[*]',
    'data.nested[*].count',
    'data.amount',
    'data.mobile',
    'data.list[*].mobile',
    'data.tags[*]',
    'data.mobile',
    'missing'
  ]
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
      data: { mobile: '138', count: 123, amount: 12.34 },
      ...(mini
        ? { header: { 'Content-Type': 'application/json' }, custom: {} }
        : { headers: { 'Content-Type': 'application/json' } })
    }
    const rule = { request: ['mobile', 'count', 'amount'] }
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
    assert.equal(await crypto.decrypt(config.data.count), 123)
    assert.equal(await crypto.decrypt(config.data.amount), 12.34)
  }
}

// Non-JSON numbers must fail before copying or recording a replay snapshot.
for (const algorithm of ['AES', 'SM4']) {
  const crypto = createFieldCrypto({ algorithm, requestKey: key, responseKey: key })
  for (const invalid of [
    NaN,
    Infinity,
    -Infinity,
    Number.MAX_SAFE_INTEGER + 1,
    Number.MIN_SAFE_INTEGER - 1,
    true,
    {},
    [],
    1n
  ]) {
    await assert.rejects(crypto.encrypt(invalid))
    await assert.rejects(crypto.encryptFields({ nested: { value: invalid } }, ['nested.value']))
    await assert.rejects(crypto.encryptFields({ values: [invalid] }, ['values[*]']))
    for (const mini of [false, true]) {
      const config = {
        method: 'POST',
        data: { amount: invalid },
        ...(mini
          ? { header: { 'Content-Type': 'application/json' }, custom: {} }
          : { headers: { 'Content-Type': 'application/json' } })
      }
      await assert.rejects(prepareFieldRequest(config, { request: ['amount'] }, crypto))
      assert.equal(Object.hasOwn(config.custom || config, '__fieldCryptoPlainData'), false)
      assert.equal(config.data.amount, invalid)
    }
  }
  await assert.rejects(crypto.decryptFields({ amount: 123 }, ['amount']))
}
// Validly authenticated ciphertext must still contain a supported JSON scalar.
function rawAesCipher(plain) {
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-128-gcm', Buffer.from(key, 'hex'), nonce)
  const encrypted = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()])
  return 'fc:v1:AES:' + Buffer.concat([nonce, encrypted, cipher.getAuthTag()]).toString('base64')
}
const aes = createFieldCrypto({ algorithm: 'AES', requestKey: key, responseKey: key })
for (const invalid of [
  'true',
  'false',
  'null',
  '{}',
  '[]',
  '9007199254740992',
  '-9007199254740992',
  '1e400',
  '123 456',
  'invalid'
]) {
  await assert.rejects(aes.decrypt(rawAesCipher(invalid)))
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

    for (const plain of [
      0,
      -123,
      123,
      12.34,
      -0.000001,
      Number.MAX_SAFE_INTEGER,
      Number.MIN_SAFE_INTEGER,
      '123'
    ]) {
      assert.equal(await crypto.decrypt(await crypto.encrypt(plain)), plain)
    }
    if (vector.algorithm === 'RSA') await assert.rejects(crypto.encrypt('长'.repeat(100)))
    console.log(vector.algorithm + ' Java -> JavaScript passed')
  }
  if (process.argv[3]) fs.writeFileSync(process.argv[3], JSON.stringify(vectors))
}
console.log('JavaScript fields, authentication, long strings and request replay checks passed')
