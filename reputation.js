const fetch = require('node-fetch');

async function checkReputation(domain) {
  const key = process.env.VT_API_KEY;
  if (!key) {
    const na = { pass: null, value: 'No verificado (sin VT_API_KEY)' };
    return { gsb: na, vt: na, spam: na, hist: na };
  }

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 9000);
    const res = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, { headers: { 'x-apikey': key }, signal: ctrl.signal });
    clearTimeout(t);

    if (res.status === 404) {
      const ok = { pass: true, value: 'Sin registros en VirusTotal' };
      return { gsb: ok, vt: ok, spam: ok, hist: ok };
    }
    if (!res.ok) throw new Error(`VT ${res.status}`);

    const data = await res.json();
    const stats = data?.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a,b) => a+b, 0);

    const vt = { pass: malicious + suspicious === 0, value: `${malicious + suspicious}/${total} detecciones` };
    const cats = data?.data?.attributes?.categories || {};
    const flagged = Object.values(cats).some(c => /phishing|malware|malicious/i.test(c));
    const gsb = { pass: !flagged && malicious === 0, value: flagged ? 'Marcado como phishing/malware' : 'Sin alertas' };
    const rep = data?.data?.attributes?.reputation ?? 0;
    const spam = { pass: rep >= 0, value: rep >= 0 ? 'Sin listas negras' : `Reputación negativa (${rep})` };
    const hist = { pass: malicious === 0, value: malicious === 0 ? 'Sin incidentes' : `${malicious} motor(es) detectaron`};

    return { gsb, vt, spam, hist };
  } catch (e) {
    const err = { pass: null, value: 'Error consultando VirusTotal' };
    return { gsb: err, vt: err, spam: err, hist: err };
  }
}

module.exports = { checkReputation };
