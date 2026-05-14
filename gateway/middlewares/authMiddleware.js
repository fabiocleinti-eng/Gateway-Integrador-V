'use strict'

const jwt = require('jsonwebtoken')
const { publicAuthRoutes } = require('../config/routes')

function normalizePath(url) {
  if (!url) return '/'
  const q = url.indexOf('?')
  const pathOnly = q === -1 ? url : url.slice(0, q)
  if (pathOnly.length > 1 && pathOnly.endsWith('/')) {
    return pathOnly.replace(/\/+$/, '') || '/'
  }
  return pathOnly
}

function decodePathForInspection(pathname) {
  let decoded = pathname
  for (let i = 0; i < 4; i += 1) {
    try {
      const next = decodeURIComponent(decoded)
      if (next === decoded) break
      decoded = next
    } catch {
      break
    }
  }
  return decoded
}

function isSuspiciousPath(pathname) {
  const decoded = decodePathForInspection(pathname)
  const lower = decoded.toLowerCase()
  if (lower.includes('..')) return true
  if (lower.includes('\\')) return true
  if (/[\u0000-\u001f]/.test(decoded)) return true
  return false
}

function isPublicRoute(method, pathname) {
  const norm = normalizePath(pathname).toLowerCase()
  const m = (method || 'GET').toUpperCase()
  return publicAuthRoutes.some(
    (r) =>
      r.method === m && normalizePath(r.path).toLowerCase() === norm
  )
}

function shouldSkipJwt(request) {
  const method = (request.method || 'GET').toUpperCase()
  if (method === 'OPTIONS') return true
  const pathname = normalizePath(request.raw.url || request.url || '/')
  if (pathname.toLowerCase() === '/health') return true
  if (isPublicRoute(method, pathname)) return true
  return false
}

async function authOnRequest(fastify, request, reply) {
  const pathname = normalizePath(request.raw.url || request.url || '/')
  if (isSuspiciousPath(pathname)) {
    return reply.code(400).send({ error: 'Requisição inválida' })
  }

  if (shouldSkipJwt(request)) {
    return
  }

  const auth = request.headers.authorization
  if (!auth || typeof auth !== 'string' || !auth.startsWith('Bearer ')) {
    return reply.code(401).send({ error: 'Token ausente ou inválido' })
  }

  const token = auth.slice('Bearer '.length).trim()
  if (!token) {
    return reply.code(401).send({ error: 'Token ausente ou inválido' })
  }

  const verifyOpts = {
    algorithms: ['HS256'],
    clockTolerance: 30
  }
  if (process.env.JWT_ISSUER) verifyOpts.issuer = process.env.JWT_ISSUER
  if (process.env.JWT_AUDIENCE) verifyOpts.audience = process.env.JWT_AUDIENCE

  // Dev bypass: aceita token sem verificar assinatura — NUNCA em produção
  const isDevBypass =
    process.env.DEV_BYPASS === 'true' &&
    process.env.NODE_ENV !== 'production'

  if (isDevBypass) {
    try {
      const payload = jwt.decode(token)
      if (!payload) {
        return reply.code(401).send({ error: 'Token inválido (dev)' })
      }
      request.user = {
        sub: payload.sub != null ? String(payload.sub) : null,
        id: payload.id != null ? String(payload.id) : null,
        raw: payload
      }
      return
    } catch {
      return reply.code(401).send({ error: 'Token inválido (dev)' })
    }
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, verifyOpts)
    request.user = {
      sub: payload.sub != null ? String(payload.sub) : null,
      id: payload.id != null ? String(payload.id) : null,
      raw: payload
    }
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return reply.code(401).send({ error: 'Token expirado' })
    }
    return reply.code(401).send({ error: 'Token inválido' })
  }
}

function registerAuthHook(fastify) {
  fastify.addHook('onRequest', async (request, reply) => {
    await authOnRequest(fastify, request, reply)
  })
}

module.exports = {
  registerAuthHook,
  shouldSkipJwt,
  normalizePath,
  isPublicRoute,
  isSuspiciousPath
}
