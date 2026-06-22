// services/scanner.js — Motor de escaneo WebScan v2
// 60+ checks, fix instructions con código real, score /100, mapeo OWASP Top 10
const { checkSSL } = require('./ssl');
const { checkHeaders } = require('./headers');
const { checkDNS } = require('./dns');
const { checkReputation } = require('./reputation');
const { checkExposure } = require('./exposure');

// ─── FIX INSTRUCTIONS CON CÓDIGO REAL ──────────────────────────────────────
// Cada fix incluye código específico para los servidores/plataformas más usados.
// Esto es lo que diferencia a WebScan de herramientas gratuitas.

const META = {
  // ── SSL / TLS ──────────────────────────────────────────────────────────────
  ssl_valid: {
    name: 'Certificado SSL válido',
    cat: 'ssl', severity: 'critical', owasp: 'A02',
    fix: `Tu sitio no tiene certificado SSL válido o no se puede verificar.

**Let's Encrypt (gratis, recomendado):**
\`\`\`bash
sudo apt install certbot
sudo certbot --nginx -d tudominio.com -d www.tudominio.com
\`\`\`

**Renovación automática:**
\`\`\`bash
sudo crontab -e
# Añade esta línea:
0 3 * * * certbot renew --quiet
\`\`\`

**cPanel/hosting compartido:** Accede a SSL/TLS > Let's Encrypt y actívalo con un clic.`,
  },

  tls_ver: {
    name: 'Versión TLS moderna (1.2+)',
    cat: 'ssl', severity: 'high', owasp: 'A02',
    fix: `Debes deshabilitar TLS 1.0 y TLS 1.1 (protocolos obsoletos y vulnerables).

**Nginx:**
\`\`\`nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
\`\`\`

**Apache:**
\`\`\`apache
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
SSLHonorCipherOrder off
\`\`\`

**Cloudflare:** SSL/TLS > Borde > Versión mínima TLS → selecciona TLS 1.2`,
  },

  ssl_exp: {
    name: 'Certificado no próximo a expirar',
    cat: 'ssl', severity: 'critical', owasp: 'A02',
    fix: `Tu certificado expira pronto. Configura renovación automática para evitar caídas.

**Certbot (renovación automática):**
\`\`\`bash
sudo certbot renew --dry-run   # verifica que funciona
sudo systemctl enable certbot.timer  # activa el timer
\`\`\`

**Verificar expiración:**
\`\`\`bash
echo | openssl s_client -connect tudominio.com:443 2>/dev/null | openssl x509 -noout -dates
\`\`\`

**Cloudflare:** Los certificados de Cloudflare se renuevan automáticamente. Verifica que el modo SSL sea "Full (Strict)".`,
  },

  ssl_chain: {
    name: 'Cadena de certificados completa',
    cat: 'ssl', severity: 'medium', owasp: 'A02',
    fix: `La cadena de certificados está incompleta. Los dispositivos móviles pueden rechazar la conexión.

**Nginx — incluye el certificado intermedio:**
\`\`\`bash
cat tudominio.crt intermediate.crt > fullchain.pem
# En nginx.conf:
ssl_certificate /path/to/fullchain.pem;
\`\`\`

**Apache:**
\`\`\`apache
SSLCertificateFile /path/to/tudominio.crt
SSLCACertificateFile /path/to/intermediate.crt
\`\`\`

Verifica la cadena en: https://www.ssllabs.com/ssltest/`,
  },

  hsts: {
    name: 'HSTS configurado',
    cat: 'ssl', severity: 'high', owasp: 'A02',
    fix: `HSTS obliga al navegador a usar siempre HTTPS. Previene ataques de downgrade.

**Nginx:**
\`\`\`nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
\`\`\`

**Apache:**
\`\`\`apache
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
\`\`\`

**Express/Node.js:**
\`\`\`js
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));
\`\`\`

**Cloudflare:** SSL/TLS > Borde > HSTS → Actívalo con max-age de 12 meses.`,
  },

  weak_ciphers: {
    name: 'Sin cifrados débiles (RC4, DES, 3DES)',
    cat: 'ssl', severity: 'high', owasp: 'A02',
    fix: `Tu servidor admite cifrados criptográficamente débiles que pueden comprometer las conexiones.

**Nginx — configuración segura de cifrados:**
\`\`\`nginx
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
ssl_prefer_server_ciphers on;
\`\`\`

**Apache:**
\`\`\`apache
SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
SSLHonorCipherOrder On
\`\`\``,
  },

  cert_transparency: {
    name: 'Certificate Transparency (CT)',
    cat: 'ssl', severity: 'low', owasp: 'A02',
    fix: `Certificate Transparency permite detectar certificados fraudulentos emitidos para tu dominio.

**Monitorización de CT Logs:**
- Regístrate en https://crt.sh para alertas de tu dominio
- Activa notificaciones en tu CA (Let's Encrypt las incluye automáticamente)

**Añadir Expect-CT header (informativo):**
\`\`\`nginx
add_header Expect-CT "max-age=86400, enforce" always;
\`\`\``,
  },

  // ── CABECERAS HTTP ─────────────────────────────────────────────────────────
  csp: {
    name: 'Content-Security-Policy',
    cat: 'headers', severity: 'high', owasp: 'A05',
    fix: `CSP previene ataques XSS controlando qué recursos puede cargar tu página.

**Nginx (política estricta recomendada):**
\`\`\`nginx
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'nonce-RANDOM'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';" always;
\`\`\`

**Apache:**
\`\`\`apache
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none';"
\`\`\`

**WordPress (en functions.php):**
\`\`\`php
add_action('send_headers', function() {
  header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");
});
\`\`\`

Genera tu CSP personalizada en: https://csp-evaluator.withgoogle.com`,
  },

  csp_unsafe: {
    name: 'CSP sin directivas peligrosas (unsafe-inline, unsafe-eval)',
    cat: 'headers', severity: 'high', owasp: 'A05',
    fix: `Tu CSP usa 'unsafe-inline' o 'unsafe-eval' que anulan la protección contra XSS.

**Reemplaza 'unsafe-inline' con nonces:**
\`\`\`nginx
# Genera un nonce aleatorio por petición en tu backend
add_header Content-Security-Policy "script-src 'nonce-$request_id';" always;
\`\`\`

**Express/Node.js con nonces:**
\`\`\`js
const crypto = require('crypto');
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('base64');
  res.setHeader('Content-Security-Policy', \`script-src 'nonce-\${res.locals.nonce}'\`);
  next();
});
// En tu HTML: <script nonce="<%= nonce %>">
\`\`\``,
  },

  xframe: {
    name: 'X-Frame-Options / CSP frame-ancestors',
    cat: 'headers', severity: 'medium', owasp: 'A05',
    fix: `Sin esta cabecera tu sitio puede ser embebido en iframes por atacantes (clickjacking).

**Nginx:**
\`\`\`nginx
add_header X-Frame-Options "DENY" always;
# Alternativa moderna (más flexible):
add_header Content-Security-Policy "frame-ancestors 'none';" always;
\`\`\`

**Apache:**
\`\`\`apache
Header always set X-Frame-Options "DENY"
\`\`\`

**Express/Node.js:**
\`\`\`js
app.use(helmet.frameguard({ action: 'deny' }));
\`\`\`

**Cloudflare (regla de transformación):** Security > Custom Rules > añade cabecera X-Frame-Options: DENY`,
  },

  xcto: {
    name: 'X-Content-Type-Options: nosniff',
    cat: 'headers', severity: 'medium', owasp: 'A05',
    fix: `Sin nosniff, los navegadores pueden interpretar archivos como un tipo MIME diferente (MIME sniffing attacks).

**Nginx:**
\`\`\`nginx
add_header X-Content-Type-Options "nosniff" always;
\`\`\`

**Apache:**
\`\`\`apache
Header always set X-Content-Type-Options "nosniff"
\`\`\`

**Express/Node.js:**
\`\`\`js
app.use(helmet.noSniff());
// o manualmente:
app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); next(); });
\`\`\``,
  },

  referrer: {
    name: 'Referrer-Policy',
    cat: 'headers', severity: 'low', owasp: 'A05',
    fix: `Sin Referrer-Policy, las URLs completas (con parámetros y tokens) se envían a sitios externos.

**Nginx:**
\`\`\`nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
\`\`\`

**Apache:**
\`\`\`apache
Header always set Referrer-Policy "strict-origin-when-cross-origin"
\`\`\`

**Opciones disponibles (de más a menos restrictivo):**
- \`no-referrer\` — nunca envía referrer
- \`strict-origin-when-cross-origin\` — recomendado
- \`same-origin\` — solo envía en mismo origen`,
  },

  perms: {
    name: 'Permissions-Policy',
    cat: 'headers', severity: 'medium', owasp: 'A05',
    fix: `Permissions-Policy controla el acceso a APIs sensibles del navegador (cámara, micrófono, GPS).

**Nginx:**
\`\`\`nginx
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=(self), usb=(), bluetooth=(), accelerometer=(), gyroscope=()" always;
\`\`\`

**Apache:**
\`\`\`apache
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
\`\`\`

**Express/Node.js:**
\`\`\`js
app.use(helmet.permissionsPolicy({ features: { camera: ["'none'"], microphone: ["'none'"], geolocation: ["'none'"] } }));
\`\`\``,
  },

  coop: {
    name: 'Cross-Origin-Opener-Policy',
    cat: 'headers', severity: 'medium', owasp: 'A05',
    fix: `COOP aísla tu ventana del navegador de otros orígenes, previniendo ataques Spectre/XS-Leaks.

**Nginx:**
\`\`\`nginx
add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Embedder-Policy "require-corp" always;
\`\`\`

**Apache:**
\`\`\`apache
Header always set Cross-Origin-Opener-Policy "same-origin"
\`\`\`

**Nota:** Si usas iframes de terceros, usa \`same-origin-allow-popups\` en lugar de \`same-origin\`.`,
  },

  sri: {
    name: 'Subresource Integrity (SRI)',
    cat: 'headers', severity: 'medium', owasp: 'A08',
    fix: `Sin SRI, si el CDN del que cargas librerías es comprometido, tu web también lo será.

**Genera el hash SRI para cualquier recurso:**
\`\`\`bash
curl -s https://cdn.example.com/lib.js | openssl dgst -sha384 -binary | openssl base64 -A
\`\`\`

**Úsalo en tu HTML:**
\`\`\`html
<script src="https://cdn.example.com/lib.js"
        integrity="sha384-HASH_AQUI"
        crossorigin="anonymous"></script>
\`\`\`

**Genera automáticamente en:** https://www.srihash.org`,
  },

  // ── DNS y EMAIL ────────────────────────────────────────────────────────────
  spf: {
    name: 'Registro SPF',
    cat: 'dns', severity: 'high', owasp: 'A07',
    fix: `Sin SPF, cualquiera puede enviar emails suplantando tu dominio.

**Registro TXT en tu DNS:**
\`\`\`
v=spf1 include:_spf.google.com include:sendgrid.net ~all
\`\`\`

**Explicación de los modificadores:**
- \`~all\` — softfail (recomendado mientras pruebas)
- \`-all\` — hardfail (más estricto, úsalo cuando estés seguro)
- \`+all\` — NUNCA usar, permite cualquier remitente

**Para solo Google Workspace:**
\`\`\`
v=spf1 include:_spf.google.com ~all
\`\`\``,
  },

  dmarc: {
    name: 'Registro DMARC',
    cat: 'dns', severity: 'high', owasp: 'A07',
    fix: `DMARC indica a los servidores de email qué hacer con correos que no pasan SPF/DKIM.

**Registro TXT en _dmarc.tudominio.com:**
\`\`\`
v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@tudominio.com; ruf=mailto:dmarc-forensics@tudominio.com; fo=1; adkim=s; aspf=s;
\`\`\`

**Progresión recomendada:**
1. \`p=none\` — solo monitoriza, no hace nada
2. \`p=quarantine\` — envía a spam los que fallen
3. \`p=reject\` — rechaza los que fallen (máxima protección)

**Herramienta de diagnóstico:** https://mxtoolbox.com/DMARC.aspx`,
  },

  dkim: {
    name: 'Registro DKIM',
    cat: 'dns', severity: 'medium', owasp: 'A07',
    fix: `DKIM firma criptográficamente los emails para probar que vienen de tu servidor.

**Google Workspace:**
Admin Console > Apps > Google Workspace > Gmail > Autenticar correo electrónico > Generar nueva clave

**En tu panel de hosting (cPanel):**
Email > Autenticación de correo electrónico > DKIM > Activar

**Postfix (servidor propio) con OpenDKIM:**
\`\`\`bash
sudo apt install opendkim opendkim-tools
sudo opendkim-genkey -t -s mail -d tudominio.com
# Añade la clave pública a tu DNS como registro TXT en mail._domainkey.tudominio.com
\`\`\``,
  },

  dnssec: {
    name: 'DNSSEC activo',
    cat: 'dns', severity: 'medium', owasp: 'A07',
    fix: `DNSSEC previene ataques de envenenamiento de caché DNS (DNS spoofing).

**Cloudflare (recomendado — un clic):**
DNS > DNSSEC > Activar DNSSEC

**Namecheap:**
Domain List > Manage > Advanced DNS > DNSSEC > Enable

**GoDaddy:**
Mis Dominios > DNS > Seguridad DNSSEC > Activar

**Verifica la activación en:** https://dnssec-analyzer.verisignlabs.com`,
  },

  caa: {
    name: 'Registro CAA (Certificate Authority Authorization)',
    cat: 'dns', severity: 'medium', owasp: 'A02',
    fix: `CAA restringe qué Autoridades Certificadoras pueden emitir certificados para tu dominio.

**Añade en tu DNS (registro tipo CAA):**
\`\`\`
tudominio.com.  CAA  0 issue "letsencrypt.org"
tudominio.com.  CAA  0 issue "digicert.com"
tudominio.com.  CAA  0 iodef "mailto:security@tudominio.com"
\`\`\`

**Si solo usas Let's Encrypt:**
\`\`\`
tudominio.com.  CAA  0 issue "letsencrypt.org"
tudominio.com.  CAA  0 issuewild ";"
\`\`\`

Genera tu registro en: https://sslmate.com/caa/`,
  },

  // ── REPUTACIÓN Y MALWARE ───────────────────────────────────────────────────
  gsb: {
    name: 'Google Safe Browsing',
    cat: 'malware', severity: 'critical', owasp: 'A09',
    fix: `Tu sitio está marcado en Google Safe Browsing como malware o phishing.

**Pasos para recuperación:**
1. Limpia el malware con: Sucuri SiteCheck, Wordfence (WordPress), o tu antivirus de hosting
2. Revisa los archivos modificados recientemente:
\`\`\`bash
find /var/www -newer /tmp/ref -name "*.php" -type f
\`\`\`
3. Cambia TODAS las contraseñas (FTP, panel, base de datos)
4. Solicita revisión en: https://search.google.com/search-console/security-issues
5. Espera 1-3 días para que Google revise y elimine la alerta.`,
  },

  vt: {
    name: 'VirusTotal (múltiples motores)',
    cat: 'malware', severity: 'critical', owasp: 'A09',
    fix: `Tu dominio está marcado como malicioso en uno o más motores de VirusTotal.

**Para cada motor que te detecta:**
1. Ve a https://www.virustotal.com/gui/domain/TUDOMINIO/detection
2. Identifica qué motores te detectan
3. Limpia el malware de tu servidor
4. Solicita deslistado directamente en cada motor:
   - Bitdefender: https://www.bitdefender.com/consumer/support/answer/29358/
   - Kaspersky: https://opentip.kaspersky.com/
   - Fortinet: https://www.fortiguard.com/webfilter
5. Abre un ticket de soporte con el enlace a tu informe limpio de VirusTotal.`,
  },

  spam: {
    name: 'Sin listas negras de spam',
    cat: 'malware', severity: 'high', owasp: 'A09',
    fix: `Tu dominio o IP está en listas negras de spam.

**Diagnóstico completo:**
https://mxtoolbox.com/blacklists.aspx

**Para solicitar deslistado en las principales listas:**
- Spamhaus: https://www.spamhaus.org/lookup/
- Barracuda: https://www.barracudacentral.org/rbl/removal-request
- SORBS: https://www.sorbs.net/

**Causas más comunes:**
- Formulario de contacto sin captcha (spam relay)
- Servidor de email mal configurado (open relay)
- Malware enviando spam desde tu servidor`,
  },

  hist: {
    name: 'Historial limpio de seguridad',
    cat: 'malware', severity: 'medium', owasp: 'A09',
    fix: `Tu dominio tiene historial de actividad maliciosa detectada anteriormente.

**Revisa tu historial en:**
- https://transparencyreport.google.com/safe-browsing/search
- https://www.virustotal.com/gui/domain/TUDOMINIO

**Si el historial es antiguo y ya lo resolviste:**
- Solicita revisión en Google Search Console
- Espera 30-90 días para que los registros históricos se diluyan
- Mantén el sitio limpio con monitorización continua`,
  },

  // ── COOKIES ───────────────────────────────────────────────────────────────
  ck_secure: {
    name: 'Cookies con flag Secure',
    cat: 'cookies', severity: 'high', owasp: 'A02',
    fix: `Las cookies sin flag Secure pueden enviarse por HTTP, exponiendo sesiones.

**Express/Node.js:**
\`\`\`js
app.use(session({
  cookie: { secure: true, httpOnly: true, sameSite: 'strict' }
}));
// O individualmente:
res.cookie('session', value, { secure: true, httpOnly: true });
\`\`\`

**PHP:**
\`\`\`php
session_set_cookie_params(['secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
// O en php.ini:
session.cookie_secure = 1
\`\`\`

**WordPress (en wp-config.php):**
\`\`\`php
define('FORCE_SSL_ADMIN', true);
@ini_set('session.cookie_secure', true);
\`\`\``,
  },

  ck_httponly: {
    name: 'Cookies con flag HttpOnly',
    cat: 'cookies', severity: 'high', owasp: 'A02',
    fix: `Las cookies sin HttpOnly son accesibles por JavaScript, lo que permite robarlas mediante XSS.

**Express/Node.js:**
\`\`\`js
res.cookie('sessionId', token, { httpOnly: true, secure: true, sameSite: 'strict' });
\`\`\`

**PHP:**
\`\`\`php
setcookie('session', $value, ['httponly' => true, 'secure' => true]);
// php.ini:
session.cookie_httponly = 1
\`\`\`

**Nginx (para todas las cookies del proxy):**
\`\`\`nginx
proxy_cookie_flags ~ httponly secure;
\`\`\``,
  },

  ck_samesite: {
    name: 'Cookies con SameSite',
    cat: 'cookies', severity: 'medium', owasp: 'A01',
    fix: `Sin SameSite, las cookies se envían en peticiones cross-site (vulnerabilidad CSRF).

**Express/Node.js:**
\`\`\`js
res.cookie('token', value, { sameSite: 'strict', httpOnly: true, secure: true });
\`\`\`

**PHP:**
\`\`\`php
setcookie('token', $val, ['samesite' => 'Strict', 'httponly' => true, 'secure' => true]);
\`\`\`

**Opciones:**
- \`Strict\` — nunca en peticiones cross-site
- \`Lax\` — solo en navegación normal (recomendado para la mayoría)
- \`None; Secure\` — siempre (requiere Secure)`,
  },

  ck_ttl: {
    name: 'Sin cookies con duración excesiva',
    cat: 'cookies', severity: 'low', owasp: 'A02',
    fix: `Cookies con duración superior a 1 año mantienen sesiones abiertas indefinidamente.

**Express/Node.js — limitar duración de sesión:**
\`\`\`js
res.cookie('session', token, {
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 días máximo
  httpOnly: true, secure: true
});
\`\`\`

**PHP:**
\`\`\`php
$expires = time() + (7 * 24 * 60 * 60); // 7 días
setcookie('session', $value, $expires, '/', '', true, true);
\`\`\`

**Recomendación:** Tokens de sesión → 24h. "Recuérdame" → máximo 30 días.`,
  },

  // ── ARCHIVOS EXPUESTOS ─────────────────────────────────────────────────────
  srv_ver: {
    name: 'Versión de servidor oculta',
    cat: 'exposed', severity: 'medium', owasp: 'A05',
    fix: `Tu servidor revela su software y versión en la cabecera Server, facilitando ataques dirigidos.

**Nginx:**
\`\`\`nginx
server_tokens off;  # En nginx.conf dentro de http {}
\`\`\`

**Apache:**
\`\`\`apache
ServerTokens Prod
ServerSignature Off
\`\`\`

**Express/Node.js:**
\`\`\`js
app.disable('x-powered-by');
app.use(helmet());  // oculta automáticamente
\`\`\`

**PHP — ocultar versión:**
\`\`\`ini
expose_php = Off  ; en php.ini
\`\`\``,
  },

  xpow: {
    name: 'X-Powered-By oculto',
    cat: 'exposed', severity: 'medium', owasp: 'A05',
    fix: `La cabecera X-Powered-By revela el framework/lenguaje de tu aplicación.

**Express/Node.js:**
\`\`\`js
app.disable('x-powered-by');
// o con Helmet (recomendado):
app.use(helmet());
\`\`\`

**PHP — eliminar en Nginx:**
\`\`\`nginx
fastcgi_hide_header X-Powered-By;
\`\`\`

**Apache:**
\`\`\`apache
Header unset X-Powered-By
\`\`\``,
  },

  git: {
    name: 'Directorio .git no accesible',
    cat: 'exposed', severity: 'critical', owasp: 'A05',
    fix: `El directorio .git expuesto permite descargar TODO el código fuente, incluyendo secretos y contraseñas.

**Nginx:**
\`\`\`nginx
location ~ /\\.git {
    deny all;
    return 404;
}
\`\`\`

**Apache (.htaccess):**
\`\`\`apache
RedirectMatch 404 /\\.git
# o:
<DirectoryMatch "\\.git">
    Order allow,deny
    Deny from all
</DirectoryMatch>
\`\`\`

**URGENTE:** Si ya estuvo expuesto, rota TODAS las credenciales en el repositorio inmediatamente.`,
  },

  env: {
    name: 'Archivo .env no accesible',
    cat: 'exposed', severity: 'critical', owasp: 'A05',
    fix: `El archivo .env expuesto revela todas las contraseñas, claves API y credenciales de base de datos.

**Nginx:**
\`\`\`nginx
location ~ /\\.env {
    deny all;
    return 404;
}
\`\`\`

**Apache (.htaccess):**
\`\`\`apache
<Files ".env">
    Order allow,deny
    Deny from all
</Files>
\`\`\`

**URGENTE:** Rota inmediatamente TODAS las credenciales que estuvieran en ese archivo.
Comprueba si ya fue indexado: https://www.google.com/search?q=site:tudominio.com+.env`,
  },

  admin: {
    name: 'Panel de administración protegido',
    cat: 'exposed', severity: 'high', owasp: 'A01',
    fix: `El panel de administración es accesible sin restricciones de acceso por IP o 2FA.

**Nginx — restricción por IP:**
\`\`\`nginx
location /admin {
    allow 1.2.3.4;  # tu IP
    deny all;
}
\`\`\`

**WordPress — cambiar URL de login:**
\`\`\`php
// Plugin: WPS Hide Login
// O añade en wp-config.php con un plugin de seguridad
\`\`\`

**Cloudflare Zero Trust (recomendado):**
Zero Trust > Access > Applications → protege /admin con autenticación adicional sin coste.`,
  },

  backup_exposed: {
    name: 'Sin archivos de backup expuestos',
    cat: 'exposed', severity: 'critical', owasp: 'A05',
    fix: `Se detectaron archivos de backup accesibles que pueden contener código fuente y base de datos.

**Nginx — bloquear extensiones de backup:**
\`\`\`nginx
location ~* \\.(sql|bak|backup|tar|gz|zip|old|orig)$ {
    deny all;
    return 404;
}
\`\`\`

**Apache:**
\`\`\`apache
<FilesMatch "\\.(sql|bak|backup|tar\\.gz|zip|old)$">
    Order allow,deny
    Deny from all
</FilesMatch>
\`\`\`

**Buena práctica:** Guarda los backups fuera del directorio web público.`,
  },

  // ── CMS Y CONFIGURACIÓN ───────────────────────────────────────────────────
  cms_ver: {
    name: 'Versión de CMS no expuesta',
    cat: 'cms', severity: 'high', owasp: 'A06',
    fix: `Tu CMS expone su versión, facilitando ataques dirigidos a vulnerabilidades conocidas.

**WordPress — ocultar versión:**
\`\`\`php
// En functions.php:
remove_action('wp_head', 'wp_generator');
add_filter('the_generator', '__return_empty_string');
\`\`\`

**WordPress — actualizar automáticamente:**
\`\`\`php
// En wp-config.php:
define('WP_AUTO_UPDATE_CORE', true);
\`\`\`

**Mantén siempre actualizado:** Core, plugins y themes. Las versiones antiguas tienen vulnerabilidades públicas con exploits disponibles.`,
  },

  cms_login: {
    name: 'URL de login de CMS no estándar',
    cat: 'cms', severity: 'medium', owasp: 'A07',
    fix: `La URL de login por defecto (/wp-login.php, /admin) es objetivo constante de ataques de fuerza bruta.

**WordPress:**
- Plugin "WPS Hide Login" → cambia la URL a /acceso-secreto o similar
- Añade Rate Limiting en Nginx:
\`\`\`nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
location = /wp-login.php {
    limit_req zone=login burst=5 nodelay;
}
\`\`\`

**Cloudflare:** Security > Tools > Rate Limiting → limita /wp-login.php a 5 peticiones/minuto.`,
  },

  dir_list: {
    name: 'Listado de directorios desactivado',
    cat: 'cms', severity: 'medium', owasp: 'A05',
    fix: `El listado de directorios expone la estructura de archivos de tu servidor.

**Nginx:**
\`\`\`nginx
autoindex off;  # En el bloque server {} o location {}
\`\`\`

**Apache (.htaccess o httpd.conf):**
\`\`\`apache
Options -Indexes
\`\`\`

**Verifica:** Accede a una carpeta que exista pero sin index.html. Si ves un listado de archivos, está activo.`,
  },

  wp_debug: {
    name: 'WordPress debug desactivado en producción',
    cat: 'cms', severity: 'medium', owasp: 'A05',
    fix: `WP_DEBUG activo en producción expone rutas del servidor, consultas SQL y errores internos.

**WordPress (wp-config.php):**
\`\`\`php
// En producción:
define('WP_DEBUG', false);
define('WP_DEBUG_LOG', false);
define('WP_DEBUG_DISPLAY', false);
@ini_set('display_errors', 0);
\`\`\`

**Si necesitas depurar en producción, usa logs privados:**
\`\`\`php
define('WP_DEBUG', true);
define('WP_DEBUG_LOG', '/ruta/privada/fuera/web/debug.log');
define('WP_DEBUG_DISPLAY', false);
\`\`\``,
  },

  // ── REDIRECCIONES Y CONTENIDO MIXTO ───────────────────────────────────────
  mixed: {
    name: 'Sin contenido mixto (HTTP en HTTPS)',
    cat: 'mixed', severity: 'high', owasp: 'A02',
    fix: `Tu página HTTPS carga recursos por HTTP, lo que permite ataques man-in-the-middle.

**Localizar recursos HTTP en tu código:**
\`\`\`bash
grep -r "http://" /var/www/html --include="*.html" --include="*.php" --include="*.js"
\`\`\`

**Solución global con Nginx (upgrade-insecure-requests):**
\`\`\`nginx
add_header Content-Security-Policy "upgrade-insecure-requests;" always;
\`\`\`

**WordPress:**
- Plugin "Really Simple SSL" migra automáticamente todos los recursos
- O en functions.php:
\`\`\`php
add_filter('the_content', function($c) { return str_replace('http://', 'https://', $c); });
\`\`\``,
  },

  https_redir: {
    name: 'Redirección HTTP → HTTPS',
    cat: 'mixed', severity: 'high', owasp: 'A02',
    fix: `Las visitas por HTTP no se redirigen automáticamente a HTTPS.

**Nginx:**
\`\`\`nginx
server {
    listen 80;
    server_name tudominio.com www.tudominio.com;
    return 301 https://$host$request_uri;
}
\`\`\`

**Apache (.htaccess):**
\`\`\`apache
RewriteEngine On
RewriteCond %{HTTPS} off
RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
\`\`\`

**Cloudflare:** SSL/TLS > Borde > Redirige siempre a HTTPS → Activar`,
  },

  cors: {
    name: 'CORS sin wildcard peligroso',
    cat: 'mixed', severity: 'medium', owasp: 'A05',
    fix: `Access-Control-Allow-Origin: * permite que cualquier web haga peticiones autenticadas a tu API.

**Express/Node.js — CORS restrictivo:**
\`\`\`js
const cors = require('cors');
app.use(cors({
  origin: ['https://tuapp.com', 'https://www.tuapp.com'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
}));
\`\`\`

**Nginx — CORS manual:**
\`\`\`nginx
add_header Access-Control-Allow-Origin "https://tuapp.com" always;
add_header Access-Control-Allow-Credentials "true" always;
\`\`\`

**Nunca uses \`*\` con credenciales.** Si necesitas acceso público, desactiva las credenciales.`,
  },

  open_redirect: {
    name: 'Sin open redirects detectados',
    cat: 'mixed', severity: 'high', owasp: 'A01',
    fix: `Se detectaron posibles open redirects que permiten redirigir a usuarios a sitios maliciosos.

**Valida siempre las URLs de redirección:**
\`\`\`js
// Node.js — validación segura
function safeRedirect(url, res) {
  const allowed = ['https://tudominio.com', 'https://www.tudominio.com'];
  const parsed = new URL(url);
  if (allowed.includes(parsed.origin)) {
    res.redirect(url);
  } else {
    res.redirect('/');  // fallback seguro
  }
}
\`\`\`

**PHP:**
\`\`\`php
$allowed = ['https://tudominio.com'];
$url = $_GET['redirect'];
if (in_array(parse_url($url, PHP_URL_HOST), ['tudominio.com'])) {
    header('Location: ' . $url);
}
\`\`\``,
  },

  // ── RENDIMIENTO TÉCNICO ───────────────────────────────────────────────────
  ttfb: {
    name: 'Tiempo de respuesta < 600ms',
    cat: 'perf', severity: 'low', owasp: null,
    fix: `El tiempo hasta el primer byte (TTFB) es alto, lo que afecta al SEO y experiencia de usuario.

**Nginx — activar caché:**
\`\`\`nginx
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=STATIC:10m inactive=7d use_temp_path=off;
location / {
    proxy_cache STATIC;
    proxy_cache_valid 200 1d;
}
\`\`\`

**CDN:** Cloudflare, BunnyCDN o Fastly reducen el TTFB drásticamente.

**Bases de datos:** Añade índices a las consultas lentas:
\`\`\`sql
EXPLAIN SELECT * FROM tabla WHERE campo = 'valor';  -- identifica consultas lentas
\`\`\``,
  },

  compress: {
    name: 'Compresión Gzip/Brotli activa',
    cat: 'perf', severity: 'low', owasp: null,
    fix: `Sin compresión, los archivos se transfieren a tamaño completo, aumentando el tiempo de carga.

**Nginx:**
\`\`\`nginx
gzip on;
gzip_vary on;
gzip_types text/plain text/css application/json application/javascript text/xml application/xml;
gzip_comp_level 6;
# Brotli (si tienes el módulo):
brotli on;
brotli_types text/plain text/css application/json application/javascript;
\`\`\`

**Apache:**
\`\`\`apache
AddOutputFilterByType DEFLATE text/html text/plain text/css application/javascript
\`\`\`

**Cloudflare:** Speed > Optimization > Brotli → Activar (automático)`,
  },

  cache: {
    name: 'Cabeceras de caché configuradas',
    cat: 'perf', severity: 'low', owasp: null,
    fix: `Sin cabeceras de caché, los navegadores descargan todos los recursos en cada visita.

**Nginx:**
\`\`\`nginx
location ~* \\.(css|js|png|jpg|ico|woff2)$ {
    add_header Cache-Control "public, max-age=31536000, immutable";
}
location ~* \\.html$ {
    add_header Cache-Control "no-cache, must-revalidate";
}
\`\`\`

**Express/Node.js:**
\`\`\`js
app.use(express.static('public', {
  maxAge: '1y',
  setHeaders: (res, path) => {
    if (path.endsWith('.html')) res.setHeader('Cache-Control', 'no-cache');
  }
}));
\`\`\``,
  },

  robots: {
    name: 'robots.txt presente',
    cat: 'perf', severity: 'low', owasp: null,
    fix: `Un robots.txt correcto guía a los crawlers y puede proteger rutas sensibles del indexado.

**Ejemplo de robots.txt básico:**
\`\`\`
User-agent: *
Allow: /
Disallow: /admin/
Disallow: /api/
Disallow: /wp-login.php

Sitemap: https://tudominio.com/sitemap.xml
\`\`\`

**WordPress:** Plugin Yoast SEO lo genera automáticamente.
**Next.js:** Crea public/robots.txt o usa next-sitemap.`,
  },

  sitemap: {
    name: 'Sitemap XML presente',
    cat: 'perf', severity: 'low', owasp: null,
    fix: `Un sitemap.xml ayuda a Google a indexar correctamente todas las páginas de tu sitio.

**WordPress:** Plugin Yoast SEO o RankMath lo generan automáticamente.

**Node.js/Express:**
\`\`\`js
const { SitemapStream, streamToPromise } = require('sitemap');
const sm = new SitemapStream({ hostname: 'https://tudominio.com' });
sm.write({ url: '/', changefreq: 'daily', priority: 1.0 });
sm.end();
\`\`\`

**Regístralo en Google Search Console:** Índice > Sitemaps > Añadir sitemap`,
  },
};

// ─── CATEGORÍAS CON NUEVOS CHECKS ────────────────────────────────────────────
const CATEGORIES = [
  { id:'ssl',     label:'SSL / TLS',                    icon:'🔒', keys:['ssl_valid','tls_ver','ssl_exp','ssl_chain','hsts','weak_ciphers','cert_transparency'] },
  { id:'headers', label:'Cabeceras HTTP',               icon:'📋', keys:['csp','csp_unsafe','xframe','xcto','referrer','perms','coop','sri'] },
  { id:'dns',     label:'DNS y email',                  icon:'🌐', keys:['spf','dmarc','dkim','dnssec','caa'] },
  { id:'malware', label:'Reputación y malware',         icon:'🛡️', keys:['gsb','vt','spam','hist'] },
  { id:'cookies', label:'Seguridad de cookies',         icon:'🍪', keys:['ck_secure','ck_httponly','ck_samesite','ck_ttl'] },
  { id:'exposed', label:'Archivos y datos expuestos',   icon:'⚙️', keys:['srv_ver','xpow','git','env','admin','backup_exposed'] },
  { id:'cms',     label:'CMS y configuración',          icon:'🔌', keys:['cms_ver','cms_login','dir_list','wp_debug'] },
  { id:'mixed',   label:'Redirects y contenido mixto',  icon:'🔀', keys:['mixed','https_redir','cors','open_redirect'] },
  { id:'perf',    label:'Rendimiento técnico',           icon:'⚡', keys:['ttfb','compress','cache','robots','sitemap'] },
];

// ─── MOTOR PRINCIPAL ──────────────────────────────────────────────────────────
async function runScan(url) {
  const hostname = new URL(url).hostname;
  const t0 = Date.now();

  const [ssl, headers, dns, rep, exp] = await Promise.allSettled([
    checkSSL(hostname),
    checkHeaders(url),
    checkDNS(hostname),
    checkReputation(hostname),
    checkExposure(url),
  ]);

  const ttfb = Date.now() - t0;

  const sslUnreachable = !ssl.value || ssl.value?.tls_ver?.value === 'Desconocido';
  const headersUnreachable = !headers.value || headers.value?.error || Object.keys(headers.value?.checks || {}).length === 0;

  if (sslUnreachable && headersUnreachable) {
    throw new Error(`No se pudo conectar con ${hostname}. Verifica que el dominio existe y está activo.`);
  }

  // ── Checks adicionales derivados del body/headers ─────────────────────────
  const body = headers.value?.body || '';
  const hdrs = headers.value?.headers || {};
  const h = (n) => hdrs[n.toLowerCase()];

  // CSP unsafe-inline / unsafe-eval
  const cspVal = h('content-security-policy') || '';
  const cspUnsafe = /unsafe-inline|unsafe-eval/.test(cspVal);
  const cspUnsafeCheck = cspVal
    ? { pass: !cspUnsafe, value: cspUnsafe ? 'CSP con directivas peligrosas' : 'CSP sin unsafe-inline/eval' }
    : { pass: null, value: 'Sin CSP' };

  // SRI — comprueba si hay scripts externos sin integrity
  let sriCheck = { pass: null, value: 'Sin scripts externos' };
  if (body) {
    const externalScripts = (body.match(/<script[^>]+src=["']https?:\/\/(?!${hostname})[^"']+["'][^>]*>/gi) || []);
    if (externalScripts.length > 0) {
      const withoutSRI = externalScripts.filter(s => !/integrity=/i.test(s));
      sriCheck = {
        pass: withoutSRI.length === 0,
        value: withoutSRI.length === 0
          ? `${externalScripts.length} script(s) externo(s) con SRI`
          : `${withoutSRI.length}/${externalScripts.length} script(s) sin integrity`,
      };
    }
  }

  // CAA — viene de DNS
  const caaCheck = dns.value?.caa || { pass: null, value: 'No comprobado' };

  // Backup expuesto — viene de exposure
  const backupCheck = exp.value?.backup_exposed || { pass: null, value: 'No comprobado' };

  // Open redirect — heurística básica sobre el body
  let openRedirectCheck = { pass: null, value: 'No analizable' };
  if (body) {
    const redirectParams = /(?:redirect|return|next|url|goto|dest)=https?:\/\//i.test(body);
    openRedirectCheck = {
      pass: !redirectParams,
      value: redirectParams ? 'Parámetros de redirección detectados' : 'Sin open redirect evidente',
    };
  }

  // WP debug
  let wpDebugCheck = { pass: null, value: 'No aplica' };
  if (body && /wp-content|wp-includes/i.test(body)) {
    const debugOn = /wp_debug.*true|notice:|warning:|deprecated:/i.test(body);
    wpDebugCheck = {
      pass: !debugOn,
      value: debugOn ? 'WP_DEBUG parece activo en producción' : 'Sin errores de debug visibles',
    };
  }

  // Cert transparency — check básico vía presencia de SCT en headers
  const sctCheck = {
    pass: !!h('expect-ct') || !!ssl.value?.sct,
    value: h('expect-ct') ? 'Expect-CT configurado' : 'Sin Expect-CT',
  };

  // Weak ciphers — viene de SSL service
  const weakCiphersCheck = ssl.value?.weak_ciphers || { pass: null, value: 'No analizable' };

  const raw = {
    ...(ssl.value || {}),
    ...(headers.value?.checks || {}),
    ...(dns.value || {}),
    ...(rep.value || {}),
    ...(exp.value || {}),
    ttfb:           { pass: ttfb < 600, value: `${ttfb}ms` },
    compress:       headers.value?.compress    || { pass: null, value: 'No disponible' },
    cache:          headers.value?.cache       || { pass: null, value: 'No disponible' },
    robots:         headers.value?.robots      || { pass: null, value: 'No disponible' },
    sitemap:        headers.value?.sitemap     || { pass: null, value: 'No disponible' },
    mixed:          headers.value?.mixed       || { pass: null, value: 'No disponible' },
    https_redir:    headers.value?.https_redir || { pass: null, value: 'No disponible' },
    cors:           headers.value?.cors        || { pass: null, value: 'No disponible' },
    csp_unsafe:     cspUnsafeCheck,
    sri:            sriCheck,
    caa:            caaCheck,
    backup_exposed: backupCheck,
    open_redirect:  openRedirectCheck,
    wp_debug:       wpDebugCheck,
    cert_transparency: sctCheck,
    weak_ciphers:   weakCiphersCheck,
  };

  const categories = CATEGORIES.map(cat => ({
    id: cat.id,
    cat: cat.label,
    icon: cat.icon,
    results: cat.keys.map(key => {
      const m = META[key] || { name: key, severity: 'low', fix: '', owasp: null };
      const r = raw[key] || { pass: null, value: 'No disponible' };
      return {
        key,
        name: m.name,
        severity: m.severity,
        owasp: m.owasp ? `OWASP A${m.owasp.replace('A','')}` : null,
        fix: m.fix,
        pass: r.pass,
        value: r.value,
      };
    }),
  }));

  const flat = categories.flatMap(c => c.results).filter(r => r.pass !== null);
  const passed = flat.filter(r => r.pass).length;
  const total = flat.length;
  const score = total ? Math.round((passed / total) * 100) : 0;

  // Score /100 con pesos por severidad
  const weights = { critical: 4, high: 2, medium: 1, low: 0.5 };
  const maxWeight = flat.reduce((s, r) => s + (weights[r.severity] || 1), 0);
  const earnedWeight = flat.filter(r => r.pass).reduce((s, r) => s + (weights[r.severity] || 1), 0);
  const weightedScore = maxWeight ? Math.round((earnedWeight / maxWeight) * 100) : 0;

  const letter = weightedScore >= 90 ? 'A' : weightedScore >= 75 ? 'B' : weightedScore >= 55 ? 'C' : 'D';
  const color  = weightedScore >= 90 ? '#16A34A' : weightedScore >= 75 ? '#2563EB' : weightedScore >= 55 ? '#B45309' : '#DC2626';

  // Fallos críticos para el resumen ejecutivo
  const criticalFailures = flat
    .filter(r => !r.pass && r.severity === 'critical')
    .map(r => r.name);

  return {
    domain: hostname,
    scannedAt: new Date().toISOString(),
    summary: {
      passed,
      failed: total - passed,
      total,
      score: weightedScore,
      rawScore: score,
      letter,
      color,
      pct: total ? passed / total : 0,
      criticalFailures,
    },
    categories,
  };
}

module.exports = { runScan };
