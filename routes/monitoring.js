// routes/monitoring.js
const express = require('express');
const rateLimit = require('express-rate-limit');
const router = express.Router();
const { validateLicense } = require('../services/licenses');
const {
  addMonitoredDomain,
  listMonitoredDomains,
  removeMonitoredDomain,
  getScanHistory,
} = require('../services/monitoring');

const monitorLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});
router.use(monitorLimiter);

// Verifica que el codigo de licencia es valido y tiene monitorizacion incluida (pro/agency)
async function requireValidLicense(req, res, next) {
  const code = (req.body?.licenseCode || req.query?.licenseCode || '').trim().toUpperCase();
  if (!code) {
    return res.status(401).json({ error: true, message: 'Código de licencia requerido' });
  }

  // Permitir tambien los codigos demo (no persisten dominios, pero permiten probar la UI)
  if (code === 'WEBSCAN-DEMO-PRO' || code === 'WEBSCAN-DEMO-AGN') {
    req.license = { code, plan: code.includes('AGN') ? 'agency' : 'pro', email: 'demo@webscan.app', demo: true };
    return next();
  }

  try {
    const license = await validateLicense(code);
    if (!license) {
      return res.status(403).json({ error: true, message: 'Licencia no válida o inactiva' });
    }
    req.license = license;
    next();
  } catch (err) {
    res.status(500).json({ error: true, message: 'Error verificando la licencia' });
  }
}

function isValidDomain(d) {
  if (!d || typeof d !== 'string') return false;
  const clean = d.replace(/^https?:\/\//, '').replace(/\/$/, '');
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(clean);
}

// Listar dominios monitorizados de una licencia
router.get('/monitoring/domains', requireValidLicense, async (req, res) => {
  if (req.license.demo) {
    return res.json({ domains: [], demo: true, message: 'Modo demo: los dominios no se guardan de forma persistente.' });
  }
  try {
    const domains = await listMonitoredDomains(req.license.code);
    res.json({ domains });
  } catch (err) {
    res.status(500).json({ error: true, message: 'Error obteniendo dominios monitorizados' });
  }
});

// Añadir un dominio a monitorizar
router.post('/monitoring/domains', requireValidLicense, async (req, res) => {
  const { domain, frequency } = req.body || {};

  if (!isValidDomain(domain)) {
    return res.status(400).json({ error: true, message: 'Dominio no válido' });
  }

  if (req.license.demo) {
    return res.json({
      success: true,
      demo: true,
      message: 'Modo demo: esta acción no se guarda de forma persistente. Activa tu plan real para monitorización efectiva.',
      domain: { domain: domain.replace(/^https?:\/\//, ''), frequency: frequency || 'weekly' },
    });
  }

  // Plan Free no puede monitorizar, aunque llegue aqui por error
  if (req.license.plan !== 'pro' && req.license.plan !== 'agency') {
    return res.status(403).json({ error: true, message: 'La monitorización solo está disponible en planes Pro y Agencia' });
  }

  try {
    const added = await addMonitoredDomain({
      licenseCode: req.license.code,
      domain,
      email: req.license.email,
      frequency: frequency || 'weekly',
    });
    res.json({ success: true, domain: added });
  } catch (err) {
    res.status(400).json({ error: true, message: err.message });
  }
});

// Eliminar un dominio monitorizado
router.delete('/monitoring/domains/:domain', requireValidLicense, async (req, res) => {
  if (req.license.demo) {
    return res.json({ success: true, demo: true });
  }
  try {
    const removed = await removeMonitoredDomain({ licenseCode: req.license.code, domain: req.params.domain });
    res.json({ success: removed });
  } catch (err) {
    res.status(500).json({ error: true, message: 'Error eliminando dominio' });
  }
});

// Historial de un dominio monitorizado (para grafico de tendencia)
router.get('/monitoring/history/:domainId', requireValidLicense, async (req, res) => {
  if (req.license.demo) {
    return res.json({ history: [], demo: true });
  }
  try {
    const history = await getScanHistory(parseInt(req.params.domainId, 10));
    res.json({ history });
  } catch (err) {
    res.status(500).json({ error: true, message: 'Error obteniendo historial' });
  }
});

module.exports = { router };
