const fetch = require('node-fetch');
const DOH = 'https://dns.google/resolve';

async function q(name, type) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 5000);
  try {
    const r = await fetch(`${DOH}?name=${encodeURIComponent(name)}&type=${type}`, { signal: ctrl.signal, headers: { Accept: 'application/dns-json' } });
    if (!r.ok) return null;
    return await r.json();
  } catch { return null; } finally { clearTimeout(t); }
}

function txt(answers) {
  return (answers || []).filter(a => a.type === 16).map(a => (a.data || '').replace(/^"|"$/g, '').replace(/\\"/g, '"'));
}

async function checkDNS(domain) {
  const out = {};

  const spfRes = await q(domain, 'TXT');
  const spf = txt(spfRes?.Answer).find(t => t.toLowerCase().startsWith('v=spf1'));
  out.spf = { pass: !!spf, value: spf ? spf.slice(0, 90) : 'Sin registro SPF' };

  const dmarcRes = await q(`_dmarc.${domain}`, 'TXT');
  const dmarc = txt(dmarcRes?.Answer).find(t => t.toLowerCase().startsWith('v=dmarc1'));
  if (dmarc) {
    const policy = (dmarc.match(/p=(\w+)/i)?.[1] || 'none').toLowerCase();
    out.dmarc = { pass: policy !== 'none', value: `${dmarc.slice(0, 60)}${policy === 'none' ? ' (política débil)' : ''}` };
  } else {
    out.dmarc = { pass: false, value: 'Sin registro DMARC' };
  }

  let dkimFound = null;
  for (const sel of ['default','google','selector1','selector2','k1','mail']) {
    const r = await q(`${sel}._domainkey.${domain}`, 'TXT');
    const found = txt(r?.Answer).find(t => /v=dkim1|p=/i.test(t));
    if (found) { dkimFound = sel; break; }
  }
  out.dkim = { pass: !!dkimFound, value: dkimFound ? `Selector "${dkimFound}" encontrado` : 'No detectado (selectores comunes)' };

  const dnskey = await q(domain, 'DNSKEY');
  const hasKey = (dnskey?.Answer || []).some(a => a.type === 48);
  out.dnssec = { pass: hasKey, value: hasKey ? 'DNSKEY presente' : 'No configurado' };

  return out;
}

module.exports = { checkDNS };
