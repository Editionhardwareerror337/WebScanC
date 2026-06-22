const express = require('express');
const rateLimit = require('express-rate-limit');
const router = express.Router();
const { runScan } = require('../services/scanner');
const { validateLicense, markUsed } = require('../services/licenses');
const { checkFreeLimit, incrementFreeUsage } = require('../services/db');

function validateURL(input) {
  if (!input || typeof input !== 'string') return null;
  let s = input.trim().slice(0, 2048);
  if (!s) return null;

  // Bloquear protocolos peligrosos antes de parsear
  if (/^(file|javascript|data|vbscript|ftp|ftps|dict|gopher|sftp|ldap):/i.test(s)) return null;

  if (!s.startsWith('http')) s = 'https://' + s;
  let u;
  try {
    u = new URL(s);
  } catch {
    return null;
  }

  if (!['http:', 'https:'].includes(u.protocol)) return null;
  const h = u.hostname.toLowerCase();

  // Bloquear IPs privadas, loopback y localhost (proteccion SSRF)
  if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|169\.254\.|::1|0\.)/.test(h)) return null;
  // Bloquear dominios internos
  if (/\.(local|internal|lan|corp|home|intranet)$/.test(h)) return null;
  // Bloquear si el hostname es una IP directa (no un dominio)
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return null;
  // Bloquear hostnames vacios o sospechosamente cortos
  if (h.length < 3 || !h.includes('.')) return null;

  return u.href;
}

// Codigos de demostracion, siempre disponibles para pruebas sin pagar
const DEMO_CODES = {
  'WEBSCAN-DEMO-PRO': 'pro',
  'WEBSCAN-DEMO-AGN': 'agency',
};

router.get('/health', (req, res) => res.json({ ok: true, timestamp: new Date().toISOString() }));

// Rate limit especifico y mas estricto para activacion de codigos
// (evita que alguien intente fuerza bruta de codigos)
const activateLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { valid: false, message: 'Demasiados intentos. Espera unos minutos.' },
});

router.post('/activate', activateLimiter, async (req, res) => {
  const { code } = req.body || {};
  if (!code || typeof code !== 'string' || code.length > 64) {
    return res.status(400).json({ valid: false, message: 'Código no válido' });
  }

  const clean = code.trim().toUpperCase();

  if (DEMO_CODES[clean]) {
    return res.json({ valid: true, plan: DEMO_CODES[clean], demo: true });
  }

  try {
    const license = await validateLicense(clean);
    if (license) {
      markUsed(clean).catch(() => {}); // no bloqueante, solo informativo
      return res.json({ valid: true, plan: license.plan });
    }
    return res.json({ valid: false, message: 'Código no válido o inactivo' });
  } catch (err) {
    console.error('Error validando codigo:', err.message);
    return res.status(500).json({ valid: false, message: 'Error verificando el código. Inténtalo de nuevo.' });
  }
});

router.post('/scan', async (req, res) => {
  const url = validateURL(req.body?.url);
  if (!url) {
    return res.status(400).json({
      error: true,
      message: 'URL no válida. Usa un formato como https://tuempresa.com (no se permiten IPs privadas).',
    });
  }

  // Control de uso gratuito por IP
  // Si el cliente envía un código de licencia válido en el body, saltamos el límite
  const licenseCode = req.body?.license ? String(req.body.license).trim().toUpperCase() : null;
  let hasLicense = false;

  if (licenseCode) {
    if (DEMO_CODES[licenseCode]) {
      hasLicense = true;
    } else {
      try {
        const lic = await validateLicense(licenseCode);
        if (lic) hasLicense = true;
      } catch {}
    }
  }

  if (!hasLicense) {
    const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';
    const { allowed, remaining } = await checkFreeLimit(ip);
    if (!allowed) {
      return res.status(429).json({
        error: true,
        limitReached: true,
        message: `Has usado los ${3} análisis gratuitos de este mes. Activa un plan para continuar.`,
      });
    }
    // Incrementamos antes de lanzar el scan para evitar abusos por peticiones paralelas
    await incrementFreeUsage(ip);
  }

  // Timeout de seguridad: si el escaneo tarda mas de 45s, abortar con error claro
  // en lugar de dejar la peticion colgada indefinidamente
  let finished = false;
  const timeout = setTimeout(() => {
    if (!finished && !res.headersSent) {
      finished = true;
      res.status(504).json({ error: true, message: 'El análisis está tardando demasiado. Inténtalo de nuevo.' });
    }
  }, 45000);

  try {
    const result = await runScan(url);
    finished = true;
    clearTimeout(timeout);
    if (!res.headersSent) res.json(result);
  } catch (err) {
    finished = true;
    clearTimeout(timeout);
    console.error('Scan error:', err.message);
    if (!res.headersSent) {
      const isUnreachable = /No se pudo conectar/.test(err.message);
      res.status(isUnreachable ? 400 : 500).json({
        error: true,
        message: isUnreachable ? err.message : 'No se pudo completar el análisis. Verifica que la URL sea accesible.',
      });
    }
  }
});

module.exports = { router };
