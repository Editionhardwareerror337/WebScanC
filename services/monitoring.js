// services/monitoring.js
// Gestiona los dominios que cada licencia Pro/Agencia quiere monitorizar
const { getPool } = require('./db');

const MAX_DOMAINS = { pro: 10, agency: Infinity };

// Añade un dominio a la lista de monitorizados de una licencia
async function addMonitoredDomain({ licenseCode, domain, email, frequency }) {
  const pool = getPool();
  if (!pool) throw new Error('Base de datos no disponible');

  // Comprobar límite de dominios según el plan
  const { rows: licenseRows } = await pool.query(`SELECT plan FROM licenses WHERE code = $1 AND active = true`, [licenseCode]);
  if (!licenseRows.length) throw new Error('Licencia no válida o inactiva');

  const plan = licenseRows[0].plan;
  const maxDomains = MAX_DOMAINS[plan] ?? 10;

  const { rows: countRows } = await pool.query(
    `SELECT COUNT(*) FROM monitored_domains WHERE license_code = $1 AND active = true`,
    [licenseCode]
  );
  const currentCount = parseInt(countRows[0].count, 10);

  if (maxDomains !== Infinity && currentCount >= maxDomains) {
    throw new Error(`Has alcanzado el límite de ${maxDomains} dominios de tu plan ${plan === 'pro' ? 'Pro' : 'Agencia'}`);
  }

  const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/$/, '').toLowerCase();
  const validFreq = ['daily', 'weekly', 'monthly'].includes(frequency) ? frequency : 'weekly';

  const { rows } = await pool.query(
    `INSERT INTO monitored_domains (license_code, domain, email, frequency)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (license_code, domain) DO UPDATE SET frequency = $4, active = true
     RETURNING *`,
    [licenseCode, cleanDomain, email, validFreq]
  );
  return rows[0];
}

// Lista los dominios monitorizados de una licencia
async function listMonitoredDomains(licenseCode) {
  const pool = getPool();
  if (!pool) return [];
  const { rows } = await pool.query(
    `SELECT * FROM monitored_domains WHERE license_code = $1 AND active = true ORDER BY created_at DESC`,
    [licenseCode]
  );
  return rows;
}

// Elimina (desactiva) un dominio monitorizado
async function removeMonitoredDomain({ licenseCode, domain }) {
  const pool = getPool();
  if (!pool) return false;
  const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/\/$/, '').toLowerCase();
  const { rowCount } = await pool.query(
    `UPDATE monitored_domains SET active = false WHERE license_code = $1 AND domain = $2`,
    [licenseCode, cleanDomain]
  );
  return rowCount > 0;
}

// Devuelve todos los dominios activos que tocan ser revisados hoy según su frecuencia
async function getDomainsDueForCheck() {
  const pool = getPool();
  if (!pool) return [];

  const { rows } = await pool.query(`
    SELECT md.*, l.plan
    FROM monitored_domains md
    JOIN licenses l ON l.code = md.license_code AND l.active = true
    WHERE md.active = true
      AND (
        md.last_checked_at IS NULL
        OR (md.frequency = 'daily'   AND md.last_checked_at < now() - interval '1 day')
        OR (md.frequency = 'weekly'  AND md.last_checked_at < now() - interval '7 days')
        OR (md.frequency = 'monthly' AND md.last_checked_at < now() - interval '30 days')
      )
    ORDER BY md.last_checked_at ASC NULLS FIRST
    LIMIT 50
  `);
  return rows;
}

// Guarda el resultado de un escaneo automático en el historial
async function recordScanResult({ monitoredDomainId, score, letter, passed, failed, criticalFailures }) {
  const pool = getPool();
  if (!pool) return;

  await pool.query(
    `INSERT INTO scan_history (monitored_domain_id, score, letter, passed, failed, critical_failures)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [monitoredDomainId, score, letter, passed, failed, JSON.stringify(criticalFailures || [])]
  );

  await pool.query(
    `UPDATE monitored_domains SET last_score = $1, last_checked_at = now() WHERE id = $2`,
    [score, monitoredDomainId]
  );
}

// Devuelve el score anterior de un dominio monitorizado (para comparar y detectar cambios)
async function getPreviousScore(monitoredDomainId) {
  const pool = getPool();
  if (!pool) return null;
  const { rows } = await pool.query(
    `SELECT score, letter FROM scan_history WHERE monitored_domain_id = $1 ORDER BY scanned_at DESC LIMIT 1`,
    [monitoredDomainId]
  );
  return rows[0] || null;
}

// Historial completo de un dominio (para el panel SaaS, grafico de tendencia)
async function getScanHistory(monitoredDomainId, limit = 30) {
  const pool = getPool();
  if (!pool) return [];
  const { rows } = await pool.query(
    `SELECT score, letter, passed, failed, scanned_at FROM scan_history
     WHERE monitored_domain_id = $1 ORDER BY scanned_at ASC LIMIT $2`,
    [monitoredDomainId, limit]
  );
  return rows;
}

module.exports = {
  addMonitoredDomain,
  listMonitoredDomains,
  removeMonitoredDomain,
  getDomainsDueForCheck,
  recordScanResult,
  getPreviousScore,
  getScanHistory,
};
