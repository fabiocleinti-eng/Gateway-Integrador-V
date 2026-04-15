'use strict'

const httpProxy = require('@fastify/http-proxy')
const { serviceRoutes, resolveUpstream } = require('../config/routes')
const { logger } = require('../utils/logger')

const DISALLOWED_METHODS = new Set(['TRACE', 'TRACK', 'CONNECT'])

async function registerProxies(fastify) {
  fastify.addHook('onRequest', async (request, reply) => {
    const m = (request.method || 'GET').toUpperCase()
    if (DISALLOWED_METHODS.has(m)) {
      return reply.code(405).send({ error: 'Método não permitido' })
    }
  })

  for (const route of serviceRoutes) {
    const upstream = resolveUpstream(route)

    await fastify.register(httpProxy, {
      upstream,
      prefix: route.prefix,
      http2: false,
      http: {
        requestOptions: {
          timeout: Number(process.env.PROXY_HTTP_TIMEOUT_MS || 30000)
        }
      },
      replyOptions: {
        onError: (reply, { error }) => {
          const cause = error && (error.cause || error)
          const code = cause && cause.code
          logger.warn(
            { code, upstream, name: route.name, msg: error && error.message },
            'Falha ao contatar microsserviço'
          )
          if (reply.sent) return
          reply.code(503).type('application/json').send({
            error: 'Serviço temporariamente indisponível'
          })
        },
        rewriteRequestHeaders: (originalReq, headers) => {
          const out = { ...headers }
          const auth = originalReq.headers.authorization
          if (auth) {
            out.authorization = auth
          }
          const ct = originalReq.headers['content-type']
          if (ct) out['content-type'] = ct
          const accept = originalReq.headers.accept
          if (accept) out.accept = accept
          const rid = originalReq.headers['x-request-id']
          if (rid) out['x-request-id'] = rid
          out['x-forwarded-host'] = originalReq.headers.host || ''
          return out
        }
      }
    })

    logger.info(
      { prefix: route.prefix, upstream, name: route.name },
      'Proxy registrado'
    )
  }
}

module.exports = {
  registerProxies
}
