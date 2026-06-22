// routes/webhook.js
// Recibe eventos de Stripe y gestiona suscripciones automaticamente
const express = require('express');
const router = express.Router();
const { createLicense, deactivateLicense, isEventProcessed, markEventProcessed } = require('../services/licenses');
const { sendLicenseEmail } = require('../services/mailer');

const PLAN_MAP = {
  [process.env.STRIPE_PRICE_PRO]: 'pro',
  [process.env.STRIPE_PRICE_AGENCY]: 'agency',
};

// Este endpoint recibe los webhooks de Stripe.
// IMPORTANTE: necesita el body RAW (sin parsear) para verificar la firma - ver server.js
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;

  if (webhookSecret && process.env.STRIPE_SECRET_KEY) {
    try {
      const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } catch (err) {
      console.error('Webhook signature invalida:', err.message);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }
  } else {
    try {
      event = JSON.parse(req.body.toString());
    } catch {
      return res.status(400).send('Invalid JSON');
    }
  }

  // Responder a Stripe inmediatamente. El procesamiento continua despues.
  res.json({ received: true });

  try {
    if (event.id) {
      const already = await isEventProcessed(event.id);
      if (already) {
        console.log(`Evento ya procesado, ignorando: ${event.id}`);
        return;
      }
    }

    console.log(`Stripe event: ${event.type} (${event.id || 'sin id'})`);

    switch (event.type) {
      case 'checkout.session.completed': {
        const session = event.data.object;
        const email = session.customer_details?.email || session.customer_email;
        const customerId = session.customer;
        const subscriptionId = session.subscription;

        if (!email) {
          console.warn('checkout.session.completed sin email, ignorado');
          break;
        }

        let plan = 'pro';
        if (subscriptionId && process.env.STRIPE_SECRET_KEY) {
          try {
            const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
            const sub = await stripe.subscriptions.retrieve(subscriptionId);
            const priceId = sub.items.data[0]?.price?.id;
            plan = PLAN_MAP[priceId] || 'pro';
          } catch (e) {
            console.warn('No se pudo obtener el plan exacto de Stripe, usando pro por defecto:', e.message);
          }
        }

        const code = await createLicense({ email, plan, stripeCustomerId: customerId, stripeSubscriptionId: subscriptionId });
        if (code) {
          await sendLicenseEmail({ to: email, plan, code });
          console.log(`Nueva suscripcion: ${email} -> ${plan} -> ${code}`);
        } else {
          console.error(`No se pudo crear licencia para ${email} (falta DATABASE_URL?)`);
        }
        break;
      }

      case 'invoice.paid': {
        const invoice = event.data.object;
        console.log(`Renovacion pagada: ${invoice.customer_email || invoice.customer}`);
        break;
      }

      case 'invoice.payment_failed': {
        const invoice = event.data.object;
        console.warn(`Pago fallido: ${invoice.customer_email || invoice.customer}`);
        break;
      }

      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        const deactivated = await deactivateLicense({ stripeSubscriptionId: subscription.id });
        console.log(`Suscripcion cancelada: ${subscription.id} -> codigos desactivados: ${deactivated?.join(', ') || 'ninguno'}`);
        break;
      }

      default:
        break;
    }

    if (event.id) await markEventProcessed(event.id, event.type);
  } catch (err) {
    console.error('Error procesando webhook (despues de responder a Stripe):', err);
  }
});

module.exports = { webhookRouter: router };
