'use strict'

/**
 * Bateria de testes ofensivos / auditoria ética contra o gateway.
 * Usa fastify.inject (sem rede) salvo onde indicado.
 */

const path = require('path')
require('dotenv').config({ path: path.join(__dirname, '..', '.env') })

process.env.NODE_ENV = 'test'
process.env.RATE_LIMIT_MAX = '500'
process.env.RATE_LIMIT_TIME_WINDOW_MS = '600000'
if (!process.env.CORS_ORIGINS) {
  process.env.CORS_ORIGINS = 'http://localhost:3000'
}
if (!process.env.JWT_SECRET) {
  process.env.JWT_SECRET =
    'test_secret_minimum_length_32_chars_ok_1234567890'
}

const jwt = require('jsonwebtoken')
const { buildServer } = require('../server')

function assert(cond, msg) {
  if (!cond) {
    throw new Error(msg || 'Assertion failed')
  }
}

function signValidToken(payload, secret, expiresIn = '5m') {
  const o = { algorithm: 'HS256', expiresIn }
  if (process.env.JWT_ISSUER) o.issuer = process.env.JWT_ISSUER
  if (process.env.JWT_AUDIENCE) o.audience = process.env.JWT_AUDIENCE
  return jwt.sign(payload, secret, o)
}

async function run() {
  const app = await buildServer()
  const secret = process.env.JWT_SECRET

  let r = await app.inject({ method: 'GET', url: '/health' })
  assert(r.statusCode === 200, `health status ${r.statusCode}`)
  const body = JSON.parse(r.body)
  assert(body.status === 'ok' && body.gateway === 'online', 'health body')

  r = await app.inject({
    method: 'GET',
    url: '/api/pedidos/1',
    headers: {}
  })
  assert(r.statusCode === 401, `sem token deve 401, veio ${r.statusCode}`)

  r = await app.inject({ method: 'GET', url: '/api/usuarios/login' })
  assert(
    r.statusCode === 401,
    `GET em rota de login (apenas POST público) deve exigir JWT, veio ${r.statusCode}`
  )

  r = await app.inject({
    method: 'GET',
    url: '/api/pedidos/1',
    headers: { authorization: 'Bearer invalid.token.here' }
  })
  assert(r.statusCode === 401, `jwt invalido deve 401, veio ${r.statusCode}`)

  const signOpts = { algorithm: 'HS256', expiresIn: '-120s' }
  if (process.env.JWT_ISSUER) signOpts.issuer = process.env.JWT_ISSUER
  if (process.env.JWT_AUDIENCE) signOpts.audience = process.env.JWT_AUDIENCE
  const expired = jwt.sign({ sub: '99' }, secret, signOpts)
  r = await app.inject({
    method: 'GET',
    url: '/api/pedidos/1',
    headers: { authorization: `Bearer ${expired}` }
  })
  assert(r.statusCode === 401, `jwt expirado deve 401, veio ${r.statusCode}`)

  const noneHeader = Buffer.from(
    JSON.stringify({ alg: 'none', typ: 'JWT' })
  ).toString('base64url')
  const nonePayload = Buffer.from(JSON.stringify({ sub: '1' })).toString(
    'base64url'
  )
  r = await app.inject({
    method: 'GET',
    url: '/api/pedidos/1',
    headers: { authorization: `Bearer ${noneHeader}.${nonePayload}.` }
  })
  assert(r.statusCode === 401, `alg none deve 401, veio ${r.statusCode}`)

  r = await app.inject({
    method: 'GET',
    url: "/api/pedidos/%2e%2e%2fsecrets",
    headers: { authorization: `Bearer ${signValidToken({ sub: '1' }, secret)}` }
  })
  assert(
    r.statusCode === 400,
    `path traversal deve 400, veio ${r.statusCode}`
  )

  r = await app.inject({
    method: 'TRACE',
    url: '/health'
  })
  assert(r.statusCode === 405, `TRACE deve 405, veio ${r.statusCode}`)

  r = await app.inject({
    method: 'POST',
    url: '/api/usuarios/login',
    payload: { user: "' OR 1=1 --" },
    headers: { 'content-type': 'application/json' }
  })
  assert(
    r.statusCode === 503 || r.statusCode === 502 || r.statusCode === 504,
    `login publico com upstream offline deve 5xx controlado, veio ${r.statusCode}`
  )
  const loginBody = JSON.parse(r.body)
  assert(
    !String(r.body).includes('ECONNREFUSED') &&
      !String(r.body).includes('stack'),
    'corpo nao deve vazar stack ou ECONNREFUSED'
  )
  assert(
    loginBody.error === 'Serviço temporariamente indisponível' ||
      loginBody.error === 'Erro interno',
    `corpo login upstream: ${r.body}`
  )

  r = await app.inject({
    method: 'GET',
    url: '/api/pedidos/1',
    headers: {
      authorization: `Bearer ${signValidToken({ sub: '1' }, secret)}`,
      'x-forwarded-for': '127.0.0.1, evil.com'
    }
  })
  assert(
    r.statusCode === 503 || r.statusCode === 502 || r.statusCode === 504,
    `proxy autenticado offline deve 5xx, veio ${r.statusCode}`
  )

  await app.close()

  process.env.RATE_LIMIT_MAX = '5'
  const appRate = await buildServer()
  let lastHealth = { statusCode: 0 }
  for (let i = 0; i < 6; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    lastHealth = await appRate.inject({ method: 'GET', url: '/health' })
  }
  assert(
    lastHealth.statusCode === 429,
    `rate limit deve 429 após 6 requisições com max=5, veio ${lastHealth.statusCode}`
  )
  await appRate.close()
  // eslint-disable-next-line no-console
  console.log('security-audit: todos os testes passaram')
}

run().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('security-audit FALHOU:', err)
  process.exit(1)
})
