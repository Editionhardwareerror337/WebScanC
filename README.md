# WebScan — Checklist de publicación segura

## ⚠️ Antes de publicar, verifica esto

### 1. Variables de entorno en Railway

Ve a tu proyecto en Railway → Variables → añade:

```
VT_API_KEY=tu_key_de_virustotal
DATABASE_URL=(Railway la genera sola si añades un servicio Postgres)
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_PRO=price_...
STRIPE_PRICE_AGENCY=price_...
MAIL_USER=molinocatenad@gmail.com
MAIL_PASS=contraseña_de_aplicación_de_16_caracteres
```

### 2. Añadir PostgreSQL en Railway (OBLIGATORIO para guardar licencias)

1. En tu proyecto de Railway, pulsa **"+ New"**
2. Selecciona **"Database" → "Add PostgreSQL"**
3. Railway crea automáticamente la variable `DATABASE_URL` y la conecta a tu servicio
4. Reinicia el servicio (Railway lo hace solo al detectar la nueva variable)
5. En los logs deberías ver: `✅ Base de datos lista (tablas verificadas)`

Sin esto, los códigos de licencia generados por Stripe **se perderían** si Railway reinicia el contenedor.

### 3. Configurar el Webhook de Stripe

1. Stripe Dashboard → Developers → Webhooks → **Add endpoint**
2. URL: `https://TU-DOMINIO-RAILWAY.up.railway.app/stripe/webhook`
3. Eventos a escuchar:
   - `checkout.session.completed`
   - `customer.subscription.deleted`
   - `invoice.payment_failed`
4. Copia el **Signing secret** → pégalo en `STRIPE_WEBHOOK_SECRET`

### 4. Email (Gmail)

1. Activa verificación en 2 pasos en tu cuenta de Gmail
2. Ve a https://myaccount.google.com/apppasswords
3. Genera una contraseña de aplicación
4. Pégala en `MAIL_PASS` (sin espacios o con espacios, ambos funcionan)

### 5. VirusTotal

1. Regístrate gratis en virustotal.com
2. Perfil → API Key → copia
3. Pégala en `VT_API_KEY`

---

## ✅ Qué está verificado y probado

- [x] El servidor no crashea ante errores no controlados (`uncaughtException`/`unhandledRejection` capturados)
- [x] Apagado ordenado ante reinicios de Railway (`SIGTERM`)
- [x] Timeouts configurados (45s por scan, 60s por request HTTP)
- [x] SSRF bloqueado: IPs privadas, localhost, `file://`, `javascript:`, dominios `.local`/`.internal`
- [x] Rate limiting: global (300/15min), específico para `/api/scan`, específico para `/api/activate` (anti fuerza-bruta)
- [x] Dominios inexistentes devuelven error claro (HTTP 400), nunca un score falso
- [x] Sin modo "demostración" con datos simulados — todo lo que se muestra es resultado real del análisis
- [x] Licencias persistidas en PostgreSQL (sobreviven a reinicios del servidor)
- [x] Webhook de Stripe con verificación de firma criptográfica
- [x] Webhook protegido contra eventos duplicados (idempotencia)
- [x] Emails con manejo de errores (si falla el envío, no rompe el flujo de pago)
- [x] `trust proxy` configurado para Railway/proxies inversos
- [x] Exportar PDF corregido (usaba `document.write` + `noopener`, incompatible con Safari)
- [x] Copiar al portapapeles con fallback robusto (Safari/contextos no seguros)
- [x] Formulario de contacto conectado de verdad (antes decía "enviado" sin enviar nada)
- [x] **Monitorización automática real**: cron diario que revisa los dominios que tocan, compara con el escaneo anterior y envía alertas por email si el score cambia ≥5 puntos o aparece un fallo crítico nuevo

## 📡 Cómo funciona la monitorización automática

1. El cliente activa su licencia Pro/Agencia y analiza un dominio
2. En el panel de resultados, activa el switch "Monitorización automática" y elige frecuencia (Pro: semanal/mensual · Agencia: diaria/semanal/mensual)
3. Un cron job (`services/cron.js`) corre todos los días a las 4:00 AM
4. Revisa qué dominios tocan según su frecuencia individual
5. Vuelve a analizarlos con el mismo motor real (`scanner.js`)
6. Compara el score nuevo con el anterior guardado en `scan_history`
7. Si cambia ≥5 puntos o hay un fallo crítico nuevo → email de alerta automático
8. Si no hay cambios significativos → solo se registra en el historial, sin spam de emails

**Límites por plan:** Pro hasta 10 dominios, Agencia ilimitados (aplicado en `services/monitoring.js`).

## 🧪 Cómo probar que todo funciona tras desplegar

```bash
# 1. Health check
curl https://TU-DOMINIO.up.railway.app/api/health

# 2. Scan real
curl -X POST https://TU-DOMINIO.up.railway.app/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://tudominio.com"}'

# 3. Activar código demo (siempre disponible, no consume base de datos)
curl -X POST https://TU-DOMINIO.up.railway.app/api/activate \
  -H "Content-Type: application/json" \
  -d '{"code":"WEBSCAN-DEMO-PRO"}'
```

## 📧 Soporte

molinocatenad@gmail.com
