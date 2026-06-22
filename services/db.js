// services/db.js
// Conexión a PostgreSQL (Railway la provee automáticamente como DATABASE_URL)
const { Pool } = require('pg');

let pool = null;

function getPool() {
  if (pool) return pool;

  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) {
    console.warn('⚠️  DATABASE_URL no configurada. Las licencias no se guardarán de forma persistente.');
    return null;
  }

  pool = new Pool({
    connectionString,
    ssl: connectionString.includes('railway') || process.env.NODE_ENV === 'production'
      ? { rejectUnauthorized: false }
      : false,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });

  pool.on('error', (err) => {
    console.error('❌ Error inesperado en el pool de Postgres:', err.message);
  });

  return pool;
}

// Crea las tablas necesarias si no existen — se llama al arrancar el servidor
async function initDB() {
  const p = getPool();
  if (!p) return false;

  try {
    await p.query(`
      CREATE TABLE IF NOT EXISTS licenses (
        code TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        plan TEXT NOT NULL CHECK (plan IN ('pro', 'agency')),
        stripe_customer_id TEXT,
        stripe_subscription_id TEXT,
        active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        used_at TIMESTAMPTZ
      );
    `);
    await p.query(`CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(email);`);
    await p.query(`CREATE INDEX IF NOT EXISTS idx_licenses_subscription ON licenses(stripe_subscription_id);`);

    await p.query(`
      CREATE TABLE IF NOT EXISTS stripe_events (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        processed_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);

    // Dominios que un cliente Pro/Agencia quiere monitorizar automáticamente
    await p.query(`
      CREATE TABLE IF NOT EXISTS monitored_domains (
        id SERIAL PRIMARY KEY,
        license_code TEXT NOT NULL REFERENCES licenses(code) ON DELETE CASCADE,
        domain TEXT NOT NULL,
        email TEXT NOT NULL,
        frequency TEXT NOT NULL DEFAULT 'weekly' CHECK (frequency IN ('daily','weekly','monthly')),
        last_score INTEGER,
        last_checked_at TIMESTAMPTZ,
        active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        UNIQUE(license_code, domain)
      );
    `);
    await p.query(`CREATE INDEX IF NOT EXISTS idx_monitored_license ON monitored_domains(license_code);`);

    // Historial de cada escaneo automatico, para detectar cambios y mostrar tendencias
    await p.query(`
      CREATE TABLE IF NOT EXISTS scan_history (
        id SERIAL PRIMARY KEY,
        monitored_domain_id INTEGER NOT NULL REFERENCES monitored_domains(id) ON DELETE CASCADE,
        score INTEGER NOT NULL,
        letter TEXT NOT NULL,
        passed INTEGER NOT NULL,
        failed INTEGER NOT NULL,
        critical_failures JSONB,
        scanned_at TIMESTAMPTZ NOT NULL DEFAULT now()
      );
    `);
    await p.query(`CREATE INDEX IF NOT EXISTS idx_scan_history_domain ON scan_history(monitored_domain_id);`);

    console.log('✅ Base de datos lista (tablas verificadas)');
    return true;
  } catch (err) {
    console.error('❌ Error inicializando la base de datos:', err.message);
    return false;
  }
}

module.exports = { getPool, initDB };
