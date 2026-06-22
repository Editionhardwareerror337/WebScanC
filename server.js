require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { router } = require('./routes/scan');
const { webhookRouter } = require('./routes/webhook');
const { router: monitoringRouter } = require('./routes/monitoring');
const { router: checkoutRouter } = require('./routes/checkout');
const { router: pdfRouter } = require('./routes/pdf');
const { initDB } = require('./services/db');
const { startCron } = require('./services/cron');

const app = express();
const PORT = process.env.PORT || 3000;

// ── PROTECCION CONTRA CRASHES ───────────────────────────────────────────────
// Sin esto, un error no controlado en cualquier parte del codigo tira
// todo el servidor abajo y Railway tarda en reiniciarlo (downtime real).
process.on('uncaughtException', (err) => {
  console.error('❌ uncaughtException (el proceso sigue vivo):', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('❌ unhandledRejection (el proceso sigue vivo):', reason);
});

// Necesario en Railway/Heroku/cualquier proxy inverso, para que
// express-rate-limit identifique correctamente la IP real del usuario
app.set('trust proxy', 1);

// El webhook de Stripe necesita el body RAW (sin parsear) para verificar
// la firma criptografica. Por eso va ANTES de express.json().
app.use('/stripe', webhookRouter);

app.use(helmet({
  contentSecurityPolicy: false, // el frontend usa estilos/scripts propios sin CDN externo problemático
  crossOriginEmbedderPolicy: false,
}));
app.use(cors());
app.use(express.json({ limit: '50kb' }));

// Rate limit global de seguridad (aparte de los especificos por ruta)
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

app.use('/api', router);
app.use('/api', monitoringRouter);
app.use('/api', checkoutRouter);
app.use('/api', pdfRouter);

// Rutas principales
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'landing.html')));
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: '1h',
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    }
  },
}));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Manejador de errores global de Express — siempre el ultimo middleware
app.use((err, req, res, next) => {
  console.error('❌ Error no manejado en request:', err);
  if (!res.headersSent) {
    res.status(500).json({ error: true, message: 'Error interno del servidor.' });
  }
});

async function start() {
  const dbReady = await initDB();

  if (dbReady) {
    startCron();
  } else {
    console.log('⚠️  Cron de monitorización NO iniciado (requiere DATABASE_URL)');
  }

  const server = app.listen(PORT, () => {
    console.log(`\n✅ WebScan corriendo en http://localhost:${PORT}\n`);
    console.log(dbReady ? '✅ Base de datos conectada' : '⚠️  Sin base de datos — añade DATABASE_URL en Railway');
    if (!process.env.STRIPE_SECRET_KEY) console.log('⚠️  Sin STRIPE_SECRET_KEY — pagos automáticos desactivados');
    if (!process.env.STRIPE_WEBHOOK_SECRET) console.log('⚠️  Sin STRIPE_WEBHOOK_SECRET — webhook sin verificar firma');
    if (!process.env.MAIL_USER) console.log('⚠️  Sin MAIL_USER — emails en modo consola (no se envían de verdad)');
    if (!process.env.VT_API_KEY) console.log('⚠️  Sin VT_API_KEY — comprobaciones de VirusTotal desactivadas');
    console.log('');
  });

  // Timeouts del servidor HTTP — evita conexiones colgadas indefinidamente
  server.headersTimeout = 65000;
  server.requestTimeout = 60000;
  server.keepAliveTimeout = 61000;

  // Apagado ordenado: si Railway manda SIGTERM (despliegue nuevo, reinicio),
  // terminamos las peticiones en curso antes de cerrar.
  process.on('SIGTERM', () => {
    console.log('SIGTERM recibido, cerrando servidor de forma ordenada...');
    server.close(() => {
      console.log('Servidor cerrado.');
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10000);
  });
}

start();
