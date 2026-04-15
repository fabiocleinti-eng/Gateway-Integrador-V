'use strict'

const { logger } = require('../utils/logger')

function isUpstreamFailure(err) {
  const code = err && (err.code || err.cause?.code)
  if (
    code === 'ECONNREFUSED' ||
    code === 'ENOTFOUND' ||
    code === 'ECONNRESET' ||
    code === 'ETIMEDOUT' ||
    code === 'EPIPE'
  ) {
    return true
  }
  const msg = String(err && err.message ? err.message : '')
  if (/fetch failed|ECONNREFUSED|network/i.test(msg)) return true
  return false
}

function registerErrorHandler(fastify) {
  fastify.setErrorHandler((error, request, reply) => {
    const statusFromError =
      error.statusCode && Number.isInteger(error.statusCode)
        ? error.statusCode
        : null

    if (isUpstreamFailure(error)) {
      logger.warn(
        { err: error.message, path: request.url },
        'Microsserviço indisponível'
      )
      return reply
        .status(503)
        .send({ error: 'Serviço temporariamente indisponível' })
    }

    if (statusFromError === 401) {
      return reply.status(401).send({ error: 'Não autorizado' })
    }

    if (
      statusFromError === 429 ||
      error.code === 'FST_ERR_RATE_LIMIT' ||
      (error.message && String(error.message).includes('Rate limit'))
    ) {
      return reply.status(429).send({ error: 'Muitas requisições' })
    }

    logger.error(
      {
        err: error,
        path: request.url,
        method: request.method
      },
      'Erro não tratado no gateway'
    )

    const expose =
      process.env.NODE_ENV !== 'production' &&
      error.message &&
      !/secret|password|token/i.test(error.message)

    if (expose) {
      return reply.status(statusFromError || 500).send({
        error: 'Erro interno',
        detail: error.message
      })
    }

    return reply.status(statusFromError || 500).send({
      error: 'Erro interno'
    })
  })
}

module.exports = {
  registerErrorHandler,
  isUpstreamFailure
}
