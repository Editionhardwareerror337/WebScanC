const tls = require('tls');

function checkSSL(hostname, port = 443) {
  return new Promise((resolve) => {
    const out = {
      ssl_valid: { pass: false, value: 'No se pudo conectar' },
      tls_ver:   { pass: false, value: 'Desconocido' },
      ssl_exp:   { pass: false, value: 'Desconocido' },
      ssl_chain: { pass: false, value: 'Desconocido' },
    };

    const socket = tls.connect({ host: hostname, port, servername: hostname, timeout: 8000, rejectUnauthorized: false }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();

        out.ssl_valid = socket.authorized
          ? { pass: true, value: `Certificado válido · ${cert.issuer?.O || cert.issuer?.CN || 'CA confiable'}` }
          : { pass: false, value: `Certificado no confiable (${socket.authorizationError || 'desconocido'})` };

        const ok = ['TLSv1.2', 'TLSv1.3'].includes(protocol);
        out.tls_ver = { pass: ok, value: protocol || 'Desconocido' };

        if (cert.valid_to) {
          const days = Math.floor((new Date(cert.valid_to) - new Date()) / 86400000);
          out.ssl_exp = { pass: days > 14, value: days > 0 ? `Expira en ${days} días` : 'Certificado expirado' };
        }

        let chainLen = 0, c = cert, seen = new Set();
        while (c && c.fingerprint && !seen.has(c.fingerprint)) { seen.add(c.fingerprint); chainLen++; c = c.issuerCertificate; }
        out.ssl_chain = { pass: chainLen >= 2, value: `${chainLen} certificado(s)${chainLen >= 2 ? ' · Cadena completa' : ' · Cadena incompleta'}` };

        socket.end();
        resolve(out);
      } catch {
        socket.end();
        resolve(out);
      }
    });

    socket.on('error', () => resolve(out));
    socket.on('timeout', () => { socket.destroy(); resolve(out); });
  });
}

module.exports = { checkSSL };
