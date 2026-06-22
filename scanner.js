const { checkSSL } = require('./ssl');
const { checkHeaders } = require('./headers');
const { checkDNS } = require('./dns');
const { checkReputation } = require('./reputation');
const { checkExposure } = require('./exposure');

const META = {
  ssl_valid:   { name:'Certificado SSL válido',              cat:'ssl',     severity:'critical', fix:"Obtén un certificado gratuito con Let's Encrypt. En la mayoría de hostings está en un clic." },
  tls_ver:     { name:'Versión TLS moderna (1.2+)',          cat:'ssl',     severity:'high',     fix:'Deshabilita TLS 1.0/1.1. En Nginx: ssl_protocols TLSv1.2 TLSv1.3;' },
  ssl_exp:     { name:'Certificado no próximo a expirar',    cat:'ssl',     severity:'critical', fix:"Activa renovación automática con Certbot o en tu panel de hosting." },
  ssl_chain:   { name:'Cadena de certificados completa',     cat:'ssl',     severity:'medium',   fix:'Incluye los certificados intermedios. Verifica con ssllabs.com.' },
  hsts:        { name:'HSTS configurado',                    cat:'ssl',     severity:'high',     fix:'Añade cabecera: Strict-Transport-Security: max-age=31536000; includeSubDomains' },
  csp:         { name:'Content-Security-Policy',             cat:'headers', severity:'high',     fix:"Añade cabecera CSP. Empieza con: Content-Security-Policy: default-src 'self'" },
  xframe:      { name:'X-Frame-Options',                     cat:'headers', severity:'medium',   fix:'Añade: X-Frame-Options: DENY' },
  xcto:        { name:'X-Content-Type-Options',              cat:'headers', severity:'medium',   fix:'Añade: X-Content-Type-Options: nosniff' },
  referrer:    { name:'Referrer-Policy',                     cat:'headers', severity:'low',      fix:'Añade: Referrer-Policy: strict-origin-when-cross-origin' },
  perms:       { name:'Permissions-Policy',                  cat:'headers', severity:'medium',   fix:'Añade: Permissions-Policy: camera=(), microphone=(), geolocation=()' },
  coop:        { name:'Cross-Origin-Opener-Policy',          cat:'headers', severity:'medium',   fix:'Añade: Cross-Origin-Opener-Policy: same-origin' },
  spf:         { name:'Registro SPF',                        cat:'dns',     severity:'high',     fix:'Crea registro TXT en DNS: v=spf1 include:_spf.google.com ~all' },
  dmarc:       { name:'Registro DMARC',                      cat:'dns',     severity:'high',     fix:'Crea registro TXT en _dmarc.tudominio: v=DMARC1; p=quarantine' },
  dkim:        { name:'Registro DKIM',                       cat:'dns',     severity:'medium',   fix:'Activa DKIM en tu proveedor de email y publica el registro DNS.' },
  dnssec:      { name:'DNSSEC activo',                       cat:'dns',     severity:'medium',   fix:'Activa DNSSEC en el panel de tu registrador de dominio.' },
  gsb:         { name:'Google Safe Browsing',                cat:'malware', severity:'critical', fix:'Solicita revisión en Google Search Console > Seguridad.' },
  vt:          { name:'VirusTotal (múltiples motores)',       cat:'malware', severity:'critical', fix:'Limpia el malware y solicita revisión en cada motor que detecte.' },
  spam:        { name:'Sin listas negras de spam',           cat:'malware', severity:'high',     fix:'Usa MXToolbox Blacklist Check y solicita deslistado.' },
  hist:        { name:'Historial limpio',                    cat:'malware', severity:'medium',   fix:'Revisa el historial en VirusTotal y Google Transparency Report.' },
  ck_secure:   { name:'Cookies con flag Secure',             cat:'cookies', severity:'high',     fix:'Añade el atributo Secure a todas las cookies.' },
  ck_httponly: { name:'Cookies con flag HttpOnly',           cat:'cookies', severity:'high',     fix:'Añade HttpOnly a las cookies de sesión.' },
  ck_samesite: { name:'Cookies con SameSite',                cat:'cookies', severity:'medium',   fix:'Añade SameSite=Strict o Lax a las cookies sensibles.' },
  ck_ttl:      { name:'Sin cookies con duración excesiva',   cat:'cookies', severity:'low',      fix:'Limita la duración de las cookies de sesión.' },
  srv_ver:     { name:'Versión de servidor oculta',          cat:'exposed', severity:'medium',   fix:'En Nginx: server_tokens off; En Apache: ServerTokens Prod;' },
  xpow:        { name:'X-Powered-By oculto',                cat:'exposed', severity:'medium',   fix:"En PHP: expose_php = Off; En Express: app.disable('x-powered-by');" },
  git:         { name:'Directorio .git no accesible',        cat:'exposed', severity:'critical', fix:'En Nginx: location /.git { deny all; return 404; }' },
  env:         { name:'Archivo .env no accesible',           cat:'exposed', severity:'critical', fix:'En Apache añade a .htaccess: <Files ".env"> deny from all </Files>' },
  admin:       { name:'Panel de admin protegido',            cat:'exposed', severity:'high',     fix:'Protege /wp-admin o /admin con IP whitelist o 2FA.' },
  cms_ver:     { name:'CMS detectado',                       cat:'cms',     severity:'high',     fix:'Mantén tu CMS siempre actualizado a la última versión.' },
  cms_login:   { name:'Login de CMS no expuesto',            cat:'cms',     severity:'medium',   fix:'Cambia la URL de login por defecto (/wp-login.php).' },
  dir_list:    { name:'Listado de directorios desactivado',  cat:'cms',     severity:'medium',   fix:'En Nginx: autoindex off; En Apache: Options -Indexes;' },
  mixed:       { name:'Sin contenido mixto (HTTP en HTTPS)', cat:'mixed',   severity:'high',     fix:'Cambia todos los recursos HTTP a HTTPS en tu código.' },
  https_redir: { name:'Redirección HTTP → HTTPS',            cat:'mixed',   severity:'high',     fix:'Configura redirección 301 de HTTP a HTTPS en tu servidor.' },
  cors:        { name:'CORS sin wildcard peligroso',         cat:'mixed',   severity:'medium',   fix:"No uses Access-Control-Allow-Origin: * en APIs autenticadas." },
  ttfb:        { name:'Tiempo de respuesta < 600ms',         cat:'perf',    severity:'low',      fix:'Usa un CDN y activa la caché del servidor.' },
  compress:    { name:'Compresión Gzip/Brotli activa',       cat:'perf',    severity:'low',      fix:'En Nginx: gzip on; brotli on;' },
  cache:       { name:'Cabeceras de caché configuradas',     cat:'perf',    severity:'low',      fix:'Añade Cache-Control a los recursos estáticos.' },
  robots:      { name:'robots.txt presente',                 cat:'perf',    severity:'low',      fix:'Crea /robots.txt con User-agent: * Disallow:' },
  sitemap:     { name:'Sitemap XML presente',                cat:'perf',    severity:'low',      fix:'Genera un sitemap.xml y regístralo en Search Console.' },
};

const CATEGORIES = [
  { id:'ssl',     label:'SSL / TLS',                   icon:'🔒', keys:['ssl_valid','tls_ver','ssl_exp','ssl_chain','hsts'] },
  { id:'headers', label:'Cabeceras HTTP',              icon:'📋', keys:['csp','xframe','xcto','referrer','perms','coop'] },
  { id:'dns',     label:'DNS y email',                 icon:'🌐', keys:['spf','dmarc','dkim','dnssec'] },
  { id:'malware', label:'Reputación y malware',        icon:'🛡️', keys:['gsb','vt','spam','hist'] },
  { id:'cookies', label:'Seguridad de cookies',        icon:'🍪', keys:['ck_secure','ck_httponly','ck_samesite','ck_ttl'] },
  { id:'exposed', label:'Archivos expuestos',          icon:'⚙️', keys:['srv_ver','xpow','git','env','admin'] },
  { id:'cms',     label:'CMS y configuración',         icon:'🔌', keys:['cms_ver','cms_login','dir_list'] },
  { id:'mixed',   label:'Redirects y contenido mixto', icon:'🔀', keys:['mixed','https_redir','cors'] },
  { id:'perf',    label:'Rendimiento técnico',         icon:'⚡', keys:['ttfb','compress','cache','robots','sitemap'] },
];

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

  // Si el certificado SSL no se pudo leer EN ABSOLUTO (tls_ver sigue "Desconocido")
  // Y la peticion HTTP de cabeceras tambien fallo (sin checks devueltos),
  // el dominio casi seguro no existe o no esta accesible. Avisamos claro.
  const sslUnreachable = !ssl.value || ssl.value?.tls_ver?.value === 'Desconocido';
  const headersUnreachable = !headers.value || headers.value?.error || Object.keys(headers.value?.checks || {}).length === 0;

  if (sslUnreachable && headersUnreachable) {
    throw new Error(`No se pudo conectar con ${hostname}. Verifica que el dominio existe y está activo.`);
  }

  const raw = {
    ...(ssl.value || {}),
    ...(headers.value?.checks || {}),
    ...(dns.value || {}),
    ...(rep.value || {}),
    ...(exp.value || {}),
    ttfb: { pass: ttfb < 600, value: `${ttfb}ms` },
    compress: headers.value?.compress || { pass: null, value: 'No disponible' },
    cache:    headers.value?.cache    || { pass: null, value: 'No disponible' },
    robots:   headers.value?.robots   || { pass: null, value: 'No disponible' },
    sitemap:  headers.value?.sitemap  || { pass: null, value: 'No disponible' },
    mixed:    headers.value?.mixed    || { pass: null, value: 'No disponible' },
    https_redir: headers.value?.https_redir || { pass: null, value: 'No disponible' },
    cors:     headers.value?.cors     || { pass: null, value: 'No disponible' },
  };

  const categories = CATEGORIES.map(cat => ({
    id: cat.id,
    cat: cat.label,
    icon: cat.icon,
    results: cat.keys.map(key => {
      const m = META[key] || { name: key, severity: 'low', fix: '' };
      const r = raw[key] || { pass: null, value: 'No disponible' };
      return { key, name: m.name, desc: '', severity: m.severity, fix: m.fix, pass: r.pass, value: r.value };
    }),
  }));

  const flat = categories.flatMap(c => c.results).filter(r => r.pass !== null);
  const passed = flat.filter(r => r.pass).length;
  const pct = flat.length ? passed / flat.length : 0;
  const score = Math.round(pct * 100);
  const letter = pct >= .90 ? 'A' : pct >= .75 ? 'B' : pct >= .55 ? 'C' : 'D';
  const color  = pct >= .90 ? '#16A34A' : pct >= .75 ? '#2563EB' : pct >= .55 ? '#B45309' : '#DC2626';

  return {
    domain: hostname,
    scannedAt: new Date().toISOString(),
    summary: { passed, failed: flat.length - passed, total: flat.length, score, letter, color, pct },
    categories,
  };
}

module.exports = { runScan };
