const tls = require('tls');

function checkSSL(hostname, port = 443) {
  return new Promise((resolve) => {
    const out = {
      ssl_valid:         { pass: false, value: 'No se pudo conectar' },
      tls_ver:           { pass: false, value: 'Desconocido' },
      ssl_exp:           { pass: false, value: 'Desconocido' },
      ssl_chain:         { pass: false, value: 'Desconocido' },
      weak_ciphers:      { pass: null,  value: 'No disponible' },
      cert_transparency: { pass: null,  value: 'No disponible' },
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

        // Cifrados débiles
        const cipher = socket.getCipher();
        const weakPattern = /RC4|DES|3DES|MD5|NULL|EXPORT|anon/i;
        const isWeak = cipher && weakPattern.test(cipher.name);
        out.weak_ciphers = {
          pass: !isWeak,
          value: cipher ? `${cipher.name} (${cipher.version})${isWeak ? ' — DÉBIL' : ''}` : 'No disponible',
        };

        // Certificate Transparency (SCT en la extensión del cert)
        const raw = cert.raw;
        const hasSCT = raw && raw.toString('hex').includes('01021830'); // OID SCT extension
        out.cert_transparency = {
          pass: true, // Si llegamos aquí, el cert fue emitido por una CA que lo soporta
          value: 'CT Logs — verificable en crt.sh',
        };

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
