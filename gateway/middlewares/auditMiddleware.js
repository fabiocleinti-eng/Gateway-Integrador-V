'use strict'

const { insertAuditLog } = require('../config/db')
const { normalizePath } = require('./authMiddleware')

function clientIp(request) {
  const trust = String(process.env.TRUST_PROXY || '').toLowerCase() === 'true'
  const xff = request.headers['x-forwarded-for']
  if (trust && xff && typeof xff === 'string') {
    const first = xff.split(',')[0].trim()
    if (first) return first.slice(0, 128)
  }
  return (
    request.ip ||
    request.socket?.remoteAddress ||
    'unknown'
  ).slice(0, 128)
}

function resolveUsuario(request) {
  if (request.user && request.user.sub) return request.user.sub
  if (request.user && request.user.id) return request.user.id
  return 'anon'
}

function truncate(str, max) {
  if (str == null) return null
  const s = String(str)
  return s.length > max ? s.slice(0, max) : s
}

function registerAuditHooks(fastify) {
  fastify.addHook('onRequest', async (request) => {
    request.auditStartedAt = Date.now()
  })

  fastify.addHook('onResponse', async (request, reply) => {
    const tempo =
      typeof reply.elapsedTime === 'number'
        ? Math.round(reply.elapsedTime)
        : Math.max(0, Date.now() - (request.auditStartedAt || Date.now()))

    const rawUrl = request.raw.url || request.url || '/'
    const rota = truncate(normalizePath(rawUrl), 2048)
    const metodo = (request.method || 'GET').toUpperCase()
    const status = reply.statusCode
    const ip = clientIp(request)
    const usuario = truncate(resolveUsuario(request), 255)

    let erro = null
    if (status >= 400) {
      erro = truncate(`HTTP ${status}`, 4000)
    }

    await insertAuditLog({
      ip,
      rota,
      metodo,
      status,
      tempo,
      usuario,
      erro
    })
  })
}

module.exports = {
  registerAuditHooks,
  clientIp
}
