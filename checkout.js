// routes/checkout.js
// Crea sesiones de Stripe Checkout para los planes Pro y Agencia.
// Sustituye a los Payment Links estáticos (buy.stripe.com/...) por sesiones
// generadas dinámicamente: permite añadir cupones, trials, metadata, o
// lógica de upsell más adelante sin tocar el frontend.
const express = require('express');
const rateLimit = require('express-rate-limit');
const router = express.Router();

const PLAN_PRICE_ENV = {
  pro: 'STRIPE_PRICE_PRO',
  agency: 'STRIPE_PRICE_AGENCY',
};

// Mismo límite que /activate: evita que alguien spamee creación de sesiones
const checkoutLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: true, message: 'Demasiadas solicitudes. Espera unos minutos.' },
});

router.post('/checkout', checkoutLimiter, async (req, res) => {
  if (!process.env.STRIPE_SECRET_KEY) {
    return res.status(503).json({ error: true, message: 'Pagos no disponibles en este momento.' });
  }

  const { plan, email } = req.body || {};
  if (!plan || !PLAN_PRICE_ENV[plan]) {
    return res.status(400).json({ error: true, message: 'Plan no válido. Usa "pro" o "agency".' });
  }

  const priceId = process.env[PLAN_PRICE_ENV[plan]];
  if (!priceId) {
    console.error(`❌ Falta la variable de entorno ${PLAN_PRICE_ENV[plan]}`);
    return res.status(503).json({ error: true, message: 'Este plan no está disponible ahora mismo.' });
  }

  // Email opcional: si el usuario lo da, precargamos el checkout y vinculamos
  // el evento de Stripe a ese email aunque cambie de idea en el formulario.
  if (email && (typeof email !== 'string' || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))) {
    return res.status(400).json({ error: true, message: 'Email no válido.' });
  }

  const origin = req.headers.origin || `https://${req.headers.host}`;

  try {
    const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${origin}/gracias.html?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${origin}/#pricing`,
      customer_email: email || undefined,
      allow_promotion_codes: true,
      billing_address_collection: 'auto',
      metadata: { plan },
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error('❌ Error creando sesión de Checkout:', err.message);
    res.status(500).json({ error: true, message: 'No se pudo iniciar el pago. Inténtalo de nuevo.' });
  }
});

module.exports = { router };
