// routes/pdf.js — Endpoint de generación de PDF profesional
// POST /api/pdf — recibe los datos del scan y devuelve un PDF binario
const express = require('express');
const rateLimit = require('express-rate-limit');
const router = express.Router();
const { validateLicense } = require('../services/licenses');
const { generatePDF } = require('../services/pdf');

const pdfLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hora
  max: 30,
  message: { error: true, message: 'Demasiadas peticiones de PDF. Espera un momento.' },
});

router.post('/pdf', pdfLimiter, async (req, res) => {
  const { licenseCode, domain, scannedAt, summary, categories } = req.body || {};

  // Validar licencia — solo Pro y Agencia pueden generar PDF
  if (!licenseCode) {
    return res.status(401).json({ error: true, message: 'Se requiere licencia activa para generar PDF.' });
  }

  let license = null;
  try {
    license = await validateLicense(licenseCode.trim().toUpperCase());
  } catch {}

  if (!license) {
    return res.status(403).json({ error: true, message: 'Licencia no válida o expirada.' });
  }

  // Validar datos del scan
  if (!domain || !summary || !categories || !Array.isArray(categories)) {
    return res.status(400).json({ error: true, message: 'Datos del análisis incompletos.' });
  }

  const whiteLabel = license.plan === 'agency';

  try {
    const pdf = await generatePDF({
      domain,
      scannedAt: scannedAt || new Date().toISOString(),
      summary,
      categories,
      whiteLabel,
    });

    const filename = `webscan-${domain}-${new Date().toISOString().slice(0, 10)}.pdf`;
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Length', pdf.length);
    res.send(pdf);

  } catch (err) {
    console.error('❌ Error generando PDF:', err.message);
    res.status(500).json({ error: true, message: 'No se pudo generar el PDF. Inténtalo de nuevo.' });
  }
});

module.exports = { router: router };
