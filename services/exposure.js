const { fetchT } = require('./headers');

const ADMIN_PATHS = ['/wp-admin/', '/wp-login.php', '/administrator/', '/admin/'];
const LISTABLE = ['/uploads/', '/wp-content/uploads/', '/assets/'];

async function safe(url) {
  try {
    const r = await fetchT(url, { method: 'GET' });
    let text = '';
    try { text = await r.text(); if (text.length > 50000) text = text.slice(0, 50000); } catch {}
    return { status: r.status, text };
  } catch { return { status: 0, text: '' }; }
}

function detectCMS(html) {
  const h = (html || '').toLowerCase();
  if (h.includes('wp-content') || h.includes('wp-includes')) {
    const v = html.match(/<meta name="generator" content="WordPress\s*([\d.]+)?/i);
    return { cms: 'WordPress', version: v?.[1] || null };
  }
  if (h.includes('joomla')) return { cms: 'Joomla', version: null };
  if (h.includes('drupal.js') || h.includes('sites/default/files')) return { cms: 'Drupal', version: null };
  if (h.includes('shopify')) return { cms: 'Shopify', version: null };
  if (h.includes('wix.com')) return { cms: 'Wix', version: null };
  if (h.includes('squarespace')) return { cms: 'Squarespace', version: null };
  return { cms: null, version: null };
}

async function checkExposure(url) {
  const base = new URL(url);
  const origin = `${base.protocol}//${base.host}`;
  const out = {};

  // .git
  const git = await safe(`${origin}/.git/HEAD`);
  const gitExposed = git.status === 200 && /ref:|^[0-9a-f]{40}/i.test(git.text.trim());
  out.git = { pass: !gitExposed, value: gitExposed ? '/.git/HEAD accesible (CRÍTICO)' : 'No accesible' };

  // .env
  const env = await safe(`${origin}/.env`);
  const envExposed = env.status === 200 && /^[A-Z_]+=/m.test(env.text);
  out.env = { pass: !envExposed, value: envExposed ? '/.env accesible (CRÍTICO)' : 'No accesible' };

  // CMS - fetch homepage
  let html = '';
  try {
    const r = await fetchT(url);
    html = await r.text().catch(() => '');
  } catch {}

  const cmsInfo = detectCMS(html);
  if (cmsInfo.cms) {
    out.cms_ver = { pass: null, value: cmsInfo.version ? `${cmsInfo.cms} ${cmsInfo.version}` : `${cmsInfo.cms} detectado` };
    if (cmsInfo.cms === 'WordPress') {
      const login = await safe(`${origin}/wp-login.php`);
      out.cms_login = { pass: login.status !== 200, value: login.status === 200 ? '/wp-login.php accesible' : 'No expuesto' };
    } else {
      out.cms_login = { pass: true, value: 'No aplica' };
    }
  } else {
    out.cms_ver = { pass: true, value: 'Ningún CMS conocido detectado' };
    out.cms_login = { pass: true, value: 'No aplica' };
  }

  // Admin panels
  let adminFound = null;
  for (const p of ADMIN_PATHS) {
    const r = await safe(`${origin}${p}`);
    if (r.status === 200) { adminFound = p; break; }
  }
  out.admin = { pass: !adminFound, value: adminFound ? `${adminFound} accesible` : 'Sin paneles expuestos' };

  // Directory listing
  let listable = null;
  for (const d of LISTABLE) {
    const r = await safe(`${origin}${d}`);
    if (r.status === 200 && /index of/i.test(r.text)) { listable = d; break; }
  }
  out.dir_list = { pass: !listable, value: listable ? `${listable} con listado activo` : 'Desactivado' };

  return out;
}

module.exports = { checkExposure };
