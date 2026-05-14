'use strict'

/**
 * Mapeamento dinâmico: prefixo público → upstream do microsserviço.
 * Caminhos de autenticação pública (sem JWT) são validados em authMiddleware.
 */
const serviceRoutes = [
  {
    name: 'restaurantes',
    prefix: '/api/restaurantes',
    upstreamEnv: 'UPSTREAM_RESTAURANTES',
    defaultUpstream: 'http://127.0.0.1:3001'
  },
  {
    name: 'usuarios',
    prefix: '/api/usuarios',
    rewritePrefix: '/users',
    upstreamEnv: 'UPSTREAM_USUARIOS',
    defaultUpstream: 'http://127.0.0.1:3002'
  },
  {
    name: 'pedidos',
    prefix: '/api/pedidos',
    rewritePrefix: '/pedidos',
    upstreamEnv: 'UPSTREAM_PEDIDOS',
    defaultUpstream: 'http://127.0.0.1:3003'
  },
  {
    name: 'entregadores',
    prefix: '/api/entregadores',
    upstreamEnv: 'UPSTREAM_ENTREGADORES',
    defaultUpstream: 'http://127.0.0.1:3004'
  },
  {
    name: 'pagamentos',
    prefix: '/api/pagamentos',
    upstreamEnv: 'UPSTREAM_PAGAMENTOS',
    defaultUpstream: 'http://127.0.0.1:3005'
  }
]

/**
 * Rotas públicas (sem JWT).
 * Método explícito evita bypass por verb tampering em rotas sensíveis.
 */
const publicAuthRoutes = [
  { method: 'POST', path: '/api/usuarios/login' },
  { method: 'POST', path: '/api/usuarios/register' },
  { method: 'POST', path: '/api/usuarios/esqueci-senha' },
  { method: 'POST', path: '/api/usuarios/redefinir-senha' },
  { method: 'POST', path: '/api/usuarios/login/google' }
]

function resolveUpstream(route) {
  const fromEnv = process.env[route.upstreamEnv]
  return (fromEnv && fromEnv.trim()) || route.defaultUpstream
}

module.exports = {
  serviceRoutes,
  publicAuthRoutes,
  resolveUpstream
}
