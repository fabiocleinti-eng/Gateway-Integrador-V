'use strict'

require('dotenv').config()

const Fastify = require('fastify')
const helmet = require('@fastify/helmet')
const cors = require('@fastify/cors')
const rateLimit = require('@fastify/rate-limit')
const { logger } = require('./utils/logger')
const { createPool } = require('./config/db')
const { registerErrorHandler } = require('./middlewares/errorMiddleware')
const { registerAuditHooks } = require('./middlewares/auditMiddleware')
const { registerAuthHook } = require('./middlewares/authMiddleware')

function validateEnv() {
  const secret = process.env.JWT_SECRET
  if (!secret || typeof secret !== 'string') {
    throw new Error('JWT_SECRET é obrigatório')
  }
  if (process.env.NODE_ENV === 'production' && secret.length < 32) {
    throw new Error('JWT_SECRET deve ter no mínimo 32 caracteres em produção')
  }

  const origins = (process.env.CORS_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
  if (origins.length === 0) {
    throw new Error(
      'CORS_ORIGINS deve listar origens explícitas separadas por vírgula (wildcard não permitido)'
    )
  }
  if (origins.some((o) => o === '*' || o.toLowerCase() === 'null')) {
    throw new Error('CORS_ORIGINS não pode usar wildcard (*) nem origem "null"')
  }
}

async function buildServer() {
  validateEnv()

  const trustProxy =
    String(process.env.TRUST_PROXY || '').toLowerCase() === 'true'

  const app = Fastify({
    loggerInstance: logger,
    trustProxy,
    bodyLimit: Number(process.env.BODY_LIMIT_BYTES || 1048576),
    requestTimeout: Number(process.env.REQUEST_TIMEOUT_MS || 30000),
    keepAliveTimeout: 72000
  })

  await app.register(helmet, {
    global: true,
    contentSecurityPolicy: false,
    crossOriginResourcePolicy: { policy: 'cross-origin' }
  })

  const origins = (process.env.CORS_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)

  await app.register(cors, {
    origin: origins,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
    allowedHeaders: [
      'Authorization',
      'Content-Type',
      'Accept',
      'X-Request-Id',
      'X-Requested-With'
    ],
    exposedHeaders: ['X-Request-Id'],
    maxAge: 600
  })

  await app.register(rateLimit, {
    max: Number(process.env.RATE_LIMIT_MAX || 100),
    timeWindow: Number(process.env.RATE_LIMIT_TIME_WINDOW_MS || 900000),
    keyGenerator: (request) => {
      if (trustProxy) {
        const xff = request.headers['x-forwarded-for']
        if (xff && typeof xff === 'string') {
          const first = xff.split(',')[0].trim()
          if (first) return first
        }
      }
      return request.ip
    },
    errorResponseBuilder: (req, context) => {
      const err = new Error('Muitas requisições')
      err.statusCode = context.statusCode || 429
      return err
    }
  })

  registerErrorHandler(app)
  registerAuditHooks(app)
  registerAuthHook(app)

  app.get('/health', async () => ({
    status: 'ok',
    gateway: 'online'
  }))

  const { registerProxies } = require('./services/proxyService')
  await registerProxies(app)

  return app
}

async function start() {
  createPool()
  const app = await buildServer()
  const port = Number(process.env.PORT || 3080)
  await app.listen({ port, host: '0.0.0.0' })
  logger.info({ port }, 'Gateway em execução')
}

if (require.main === module) {
  start().catch((err) => {
    logger.fatal(err, 'Falha ao iniciar gateway')
    process.exit(1)
  })
}

module.exports = { buildServer, start }
