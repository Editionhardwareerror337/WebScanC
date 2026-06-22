// services/licenses.js
// Genera y valida codigos de activacion usando PostgreSQL.
// Si no hay base de datos configurada, funciona en modo "solo demo" (no falla, pero avisa).
const crypto = require('crypto');
const { getPool } = require('./db');

// Genera un código único tipo WEBSCAN-PRO-XXXX-XXXX
function generateCode(plan) {
  const prefix = plan === 'agency' ? 'AGN' : 'PRO';
  const rand = crypto.randomBytes(6).toString('hex').toUpperCase();
  return `WEBSCAN-${prefix}-${rand.slice(0, 4)}-${rand.slice(4, 8)}`;
}

// Crea una licencia nueva en la base de datos
async function createLicense({ email, plan, stripeCustomerId, stripeSubscriptionId }) {
  const pool = getPool();
  if (!pool) {
    console.warn('⚠️  No hay base de datos: no se puede persistir la licencia.');
    return null;
  }

  // Reintentar si por casualidad el código ya existe (extremadamente improbable, pero por seguridad)
  for (let attempt = 0; attempt < 3; attempt++) {
    const code = generateCode(plan);
    try {
      await pool.query(
        `INSERT INTO licenses (code, email, plan, stripe_customer_id, stripe_subscription_id, active)
         VALUES ($1, $2, $3, $4, $5, true)`,
        [code, email, plan, stripeCustomerId || null, stripeSubscriptionId || null]
      );
      console.log(`✅ Licencia creada: ${code} para ${email} (${plan})`);
      return code;
    } catch (err) {
      if (err.code === '23505') continue; // codigo duplicado, reintentar
      console.error('❌ Error creando licencia:', err.message);
      throw err;
    }
  }
  throw new Error('No se pudo generar un código único tras varios intentos');
}

// Valida un código y devuelve la licencia si es válida y activa
async function validateLicense(code) {
  const pool = getPool();
  if (!pool) return null;

  try {
    const { rows } = await pool.query(
      `SELECT * FROM licenses WHERE code = $1 AND active = true LIMIT 1`,
      [code.toUpperCase()]
    );
    return rows[0] || null;
  } catch (err) {
    console.error('❌ Error validando licencia:', err.message);
    return null;
  }
}

// Marca el primer uso de una licencia (informativo)
async function markUsed(code) {
  const pool = getPool();
  if (!pool) return;
  try {
    await pool.query(
      `UPDATE licenses SET used_at = now() WHERE code = $1 AND used_at IS NULL`,
      [code.toUpperCase()]
    );
  } catch (err) {
    console.error('❌ Error marcando licencia como usada:', err.message);
  }
}

// Desactiva todas las licencias asociadas a una suscripción cancelada
async function deactivateLicense({ stripeSubscriptionId }) {
  const pool = getPool();
  if (!pool || !stripeSubscriptionId) return null;

  try {
    const { rows } = await pool.query(
      `UPDATE licenses SET active = false WHERE stripe_subscription_id = $1 RETURNING code`,
      [stripeSubscriptionId]
    );
    if (rows.length) {
      console.log(`⚠️  Licencia(s) desactivada(s): ${rows.map(r => r.code).join(', ')}`);
    }
    return rows.map(r => r.code);
  } catch (err) {
    console.error('❌ Error desactivando licencia:', err.message);
    return null;
  }
}

// Comprueba si un evento de Stripe ya fue procesado (evita duplicados si Stripe reintenta)
async function isEventProcessed(eventId) {
  const pool = getPool();
  if (!pool) return false;
  try {
    const { rows } = await pool.query(`SELECT 1 FROM stripe_events WHERE id = $1`, [eventId]);
    return rows.length > 0;
  } catch {
    return false;
  }
}

async function markEventProcessed(eventId, type) {
  const pool = getPool();
  if (!pool) return;
  try {
    await pool.query(
      `INSERT INTO stripe_events (id, type) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING`,
      [eventId, type]
    );
  } catch (err) {
    console.error('❌ Error registrando evento de Stripe:', err.message);
  }
}

// Lista todas las licencias (uso interno / panel admin futuro)
async function listLicenses() {
  const pool = getPool();
  if (!pool) return [];
  try {
    const { rows } = await pool.query(`SELECT * FROM licenses ORDER BY created_at DESC LIMIT 200`);
    return rows;
  } catch {
    return [];
  }
}

module.exports = {
  createLicense,
  validateLicense,
  markUsed,
  deactivateLicense,
  isEventProcessed,
  markEventProcessed,
  listLicenses,
};
