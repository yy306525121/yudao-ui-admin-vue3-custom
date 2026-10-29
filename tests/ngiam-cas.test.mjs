import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import ts from 'typescript'

const source = await readFile(new URL('../src/utils/ngiamState.ts', import.meta.url), 'utf8')
const { outputText: code } = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 }
})
const { validateNgiamCallback, isLocalNgiamPath, prepareNgiamAuthorizeUrl, isNgiamBaseUrl } =
  await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`)
const now = 1000000
const pending = {
  state: 'random-state',
  tenantId: '7',
  service: 'https://app.example.com/',
  createdAt: now
}
const callback = new URL(
  'https://app.example.com/?ticket=ST-1&params=random-state&accountId=untrusted&callbackUrl='
)

test('site-root callback maps ticket and params without trusting accountId', () => {
  assert.deepEqual(validateNgiamCallback(callback, pending, '7', now), {
    ticket: 'ST-1',
    state: 'random-state',
    tenantId: '7'
  })
})
test('registered callback supports a non-root path and encoded static query', () => {
  const target = { ...pending, service: 'https://app.example.com/sso/callback?a=hello%20world' }
  assert.equal(
    validateNgiamCallback(
      new URL(`${target.service}&ticket=ST-2&params=random-state`),
      target,
      '7',
      now
    ).ticket,
    'ST-2'
  )
})
test('missing state, mismatch, duplicate state and duplicate tickets are rejected', () => {
  assert.throws(() => validateNgiamCallback(callback, null, '7', now))
  assert.throws(() => validateNgiamCallback(callback, { ...pending, state: 'other' }, '7', now))
  assert.throws(() =>
    validateNgiamCallback(new URL(`${callback}&params=random-state`), pending, '7', now)
  )
  assert.throws(() => validateNgiamCallback(new URL(`${callback}&ticket=ST-2`), pending, '7', now))
  assert.throws(() =>
    validateNgiamCallback(
      new URL('https://app.example.com/?params=random-state'),
      pending,
      '7',
      now
    )
  )
})
test('expired state, tenant change and changed callback are rejected', () => {
  assert.throws(() => validateNgiamCallback(callback, pending, '7', now + 300001))
  assert.throws(() => validateNgiamCallback(callback, pending, '8', now))
  assert.throws(() =>
    validateNgiamCallback(callback, { ...pending, service: 'https://evil.example.com/' }, '7', now)
  )
  assert.throws(() =>
    validateNgiamCallback(
      callback,
      { ...pending, service: 'https://app.example.com/other' },
      '7',
      now
    )
  )
  assert.throws(() => validateNgiamCallback(new URL(`${callback}&extra=1`), pending, '7', now))
})
test('return path preserves query and rejects external or ambiguous URLs', () => {
  assert.equal(isLocalNgiamPath('/system/menu?a=1'), true)
  for (const path of [
    'https://evil.example.com',
    '//evil.example.com',
    '/%2f%2fevil',
    '/\\evil',
    '/\n'
  ]) {
    assert.equal(isLocalNgiamPath(path), false)
  }
})

test('CAS navigation adds a missing service and preserves params without appId', () => {
  const result = new URL(
    prepareNgiamAuthorizeUrl(
      'https://iam.example.com/ngiam-rst/cas/login?params=random-state',
      'https://app.example.com/'
    )
  )
  assert.equal(result.searchParams.get('service'), 'https://app.example.com/')
  assert.equal(result.searchParams.has('loginType'), false)
  assert.equal(result.searchParams.has('appId'), false)
  assert.equal(result.searchParams.get('params'), 'random-state')
})

test('IAM navigation encodes service exactly once, including nested query and an empty parameter', () => {
  const service = 'https://app.example.com/callback?a=1&b=hello%20world'
  const result = new URL(
    prepareNgiamAuthorizeUrl(
      'https://iam.example.com/ngiam-rst/cas/login?service=&params=random-state',
      service
    )
  )
  assert.equal(result.searchParams.get('service'), service)
  const second = new URL(prepareNgiamAuthorizeUrl(result.href, service))
  assert.equal(second.searchParams.get('service'), service)
  assert.equal(second.searchParams.getAll('service').length, 1)
})

test('IAM navigation rejects a conflicting service and invalid destination', () => {
  assert.throws(() =>
    prepareNgiamAuthorizeUrl(
      'https://iam.example.com/ngiam-rst/cas/login?service=https%3A%2F%2Fother.example.com',
      'https://app.example.com/'
    )
  )
  assert.throws(() => prepareNgiamAuthorizeUrl('javascript:alert(1)', 'https://app.example.com/'))
})

test('CAS navigation strips obsolete IAM internal login parameters', () => {
  const result = new URL(
    prepareNgiamAuthorizeUrl(
      'https://iam.example.com/ngiam-rst/cas/login?appId=obsolete&loginType=SSOLOGIN&params=random-state',
      'https://app.example.com/'
    )
  )
  assert.equal(result.searchParams.has('appId'), false)
  assert.equal(result.searchParams.has('loginType'), false)
  assert.equal(result.searchParams.get('params'), 'random-state')
  assert.equal(result.searchParams.get('service'), 'https://app.example.com/')
})

test('IAM base URL accepts only an http(s) origin with optional port and trailing slash', () => {
  for (const value of [
    'http://10.1.102.64:80',
    'http://10.1.102.64:80/',
    'https://iam.example.com',
    'https://iam.example.com/',
    'http://[::1]:8080/'
  ]) {
    assert.equal(isNgiamBaseUrl(value), true, value)
  }
  for (const value of [
    undefined,
    null,
    '',
    'iam.example.com',
    'ftp://iam.example.com',
    'https://iam.example.com/ngiam-rst',
    'https://iam.example.com//',
    'https://iam.example.com/../',
    'https://iam.example.com?',
    'https://iam.example.com?a=1',
    'https://iam.example.com#',
    'https://iam.example.com#x',
    'http://u:p@iam.example.com',
    'http://iam.example.com:0',
    'http://iam.example.com:70000',
    'http://iam.example.com:',
    ' https://iam.example.com'
  ]) {
    assert.equal(isNgiamBaseUrl(value), false, String(value))
  }
})
