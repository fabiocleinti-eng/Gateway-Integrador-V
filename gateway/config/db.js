'use strict'

/**
 * Auditoria em `tb_logs_auditoria` (INSERT parametrizado).
 * Espera colunas: ip, rota, metodo, status, tempo, usuario, erro (VARCHAR/TEXT/INT).
 * Ajuste o mapeamento se o legado usar nomes diferentes.
 */

const mysql = require('mysql2/promise')
const { logger } = require('../utils/logger')

let pool = null

function createPool() {
  if (pool) return pool

  const host = process.env.MYSQL_HOST || '127.0.0.1'
  const port = Number(process.env.MYSQL_PORT || 3306)
  const user = process.env.MYSQL_USER || 'gateway'
  const password = process.env.MYSQL_PASSWORD || ''
  const database = process.env.MYSQL_DATABASE || 'delivery_auditoria'

  pool = mysql.createPool({
    host,
    port,
    user,
    password,
    database,
    waitForConnections: true,
    connectionLimit: Number(process.env.MYSQL_POOL_LIMIT || 10),
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
  })

  pool
    .getConnection()
    .then((conn) => {
      conn.release()
      logger.info({ host, port, database }, 'Pool MySQL conectado com sucesso')
    })
    .catch((err) => {
      logger.warn(
        { err: err.message },
        'MySQL indisponível na inicialização — auditoria será apenas em log até reconectar'
      )
    })

  return pool
}

async function insertAuditLog(row) {
  const p = createPool()
  const sql = `
    INSERT INTO tb_logs_auditoria
      (\`ip\`, \`rota\`, \`metodo\`, \`status\`, \`tempo\`, \`usuario\`, \`erro\`)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `
  const values = [
    row.ip,
    row.rota,
    row.metodo,
    row.status,
    row.tempo,
    row.usuario,
    row.erro
  ]
  try {
    await p.execute(sql, values)
  } catch (err) {
    logger.error(
      { err: err.message, row },
      'Falha ao persistir auditoria no MySQL'
    )
  }
}

module.exports = {
  createPool,
  insertAuditLog
}
