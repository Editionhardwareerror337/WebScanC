const fetch = require('node-fetch');

const UA = 'Mozilla/5.0 (compatible; WebScanBot/1.0)';
const TIMEOUT = 9000;

async function fetchT(url, opts = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal, redirect: 'manual', headers: { 'User-Agent': UA, ...opts.headers } });
  } finally { clearTimeout(t); }
}

async function checkHeaders(url) {
  const checks = {};
  let res, finalUrl = url, body = '', headers = {}, cookies = [];

  try {
    res = await fetchT(url);
    headers = Object.fromEntries(res.headers.entries());
    cookies = (res.headers.raw && res.headers.raw()['set-cookie']) || [];

    let n = 0, current = url;
    while ([301,302,307,308].includes(res.status) && n < 5) {
      const loc = res.headers.get('location');
      if (!loc) break;
      current = new URL(loc, current).href;
      n++;
      res = await fetchT(current);
      headers = Object.fromEntries(res.headers.entries());
      const more = (res.headers.raw && res.headers.raw()['set-cookie']) || [];
      cookies = cookies.concat(more);
    }
    finalUrl = current;
    body = await res.text().catch(() => '');
    if (body.length > 400000) body = body.slice(0, 400000);
  } catch (err) {
    return { checks: {}, compress: null, cache: null, robots: null, sitemap: null, mixed: null, https_redir: null, cors: null, error: err.message };
  }

  const h = (n) => headers[n.toLowerCase()];

  checks.csp     = { pass: !!h('content-security-policy'), value: h('content-security-policy') ? 'Presente' : 'Ausente' };
  checks.xframe  = { pass: !!h('x-frame-options'), value: h('x-frame-options') || 'Ausente' };
  checks.xcto    = { pass: h('x-content-type-options') === 'nosniff', value: h('x-content-type-options') || 'Ausente' };
  checks.referrer= { pass: !!h('referrer-policy'), value: h('referrer-policy') || 'Ausente' };
  checks.perms   = { pass: !!h('permissions-policy'), value: h('permissions-policy') ? 'Presente' : 'Ausente' };
  checks.coop    = { pass: !!h('cross-origin-opener-policy'), value: h('cross-origin-opener-policy') || 'Ausente' };
  checks.hsts    = { pass: !!h('strict-transport-security'), value: h('strict-transport-security') || 'Ausente' };

  const srv = h('server') || '';
  checks.srv_ver = { pass: !srv || !/[\d]/.test(srv), value: srv || 'Oculto' };
  const xpb = h('x-powered-by') || '';
  checks.xpow = { pass: !xpb, value: xpb || 'Oculto' };

  // Cookies
  const arr = Array.isArray(cookies) ? cookies : [];
  if (arr.length === 0) {
    checks.ck_secure = { pass: true, value: 'Sin cookies' };
    checks.ck_httponly = { pass: true, value: 'Sin cookies' };
    checks.ck_samesite = { pass: true, value: 'Sin cookies' };
    checks.ck_ttl = { pass: true, value: 'Sin cookies' };
  } else {
    const noSecure = arr.filter(c => !/;\s*secure/i.test(c)).length;
    const noHttpOnly = arr.filter(c => !/;\s*httponly/i.test(c)).length;
    const noSameSite = arr.filter(c => !/;\s*samesite/i.test(c)).length;
    const longLived = arr.filter(c => { const m = c.match(/max-age=(\d+)/i); return m && parseInt(m[1]) > 31536000; }).length;
    checks.ck_secure   = { pass: noSecure === 0, value: noSecure === 0 ? 'Todas con Secure' : `${noSecure} sin Secure` };
    checks.ck_httponly = { pass: noHttpOnly === 0, value: noHttpOnly === 0 ? 'Todas con HttpOnly' : `${noHttpOnly} sin HttpOnly` };
    checks.ck_samesite = { pass: noSameSite === 0, value: noSameSite === 0 ? 'SameSite configurado' : `${noSameSite} sin SameSite` };
    checks.ck_ttl      = { pass: longLived === 0, value: longLived === 0 ? 'Duración razonable' : `${longLived} cookie(s) > 1 año` };
  }

  // CORS
  const acao = h('access-control-allow-origin');
  const cors = { pass: acao !== '*', value: acao ? `ACAO: ${acao}` : 'No expuesto en esta ruta' };

  // Cache / compression
  const cache = { pass: !!h('cache-control'), value: h('cache-control') || 'Sin Cache-Control' };
  const enc = h('content-encoding') || '';
  const compress = { pass: /br|gzip/.test(enc), value: enc || 'Sin compresión' };

  // Mixed content
  let mixed = { pass: true, value: 'No aplica' };
  if (finalUrl.startsWith('https://') && body) {
    const matches = body.match(/(?:src|href)=["']http:\/\/[^"']+["']/gi) || [];
    mixed = { pass: matches.length === 0, value: matches.length === 0 ? 'Sin recursos HTTP' : `${matches.length} recurso(s) HTTP` };
  }

  // HTTP -> HTTPS redirect
  let https_redir = { pass: null, value: 'No disponible' };
  if (url.startsWith('https://')) {
    try {
      const httpUrl = url.replace('https://', 'http://');
      const r = await fetchT(httpUrl);
      if ([301,302,307,308].includes(r.status)) {
        const loc = r.headers.get('location') || '';
        https_redir = { pass: loc.startsWith('https://') || loc.startsWith('/'), value: loc.startsWith('https://') || loc.startsWith('/') ? 'Redirige a HTTPS' : 'Redirige sin HTTPS' };
      } else {
        https_redir = { pass: false, value: `HTTP responde ${r.status} sin redirigir` };
      }
    } catch {
      https_redir = { pass: true, value: 'HTTP no responde (asumido OK)' };
    }
  }

  // robots / sitemap
  let robots = { pass: false, value: 'No encontrado' };
  let sitemap = { pass: false, value: 'No encontrado' };
  try {
    const r = await fetchT(new URL('/robots.txt', finalUrl).href);
    robots = { pass: r.status === 200, value: r.status === 200 ? '200 OK' : `${r.status}` };
  } catch {}
  try {
    const r = await fetchT(new URL('/sitemap.xml', finalUrl).href);
    sitemap = { pass: r.status === 200, value: r.status === 200 ? '200 OK' : 'No encontrado' };
  } catch {}

  return { checks, compress, cache, robots, sitemap, mixed, https_redir, cors, finalUrl, body, headers };
}

module.exports = { checkHeaders, fetchT };
