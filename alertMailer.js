// services/alertMailer.js
// Envía emails de alerta cuando cambia el estado de seguridad de un dominio monitorizado
const nodemailer = require('nodemailer');

function getTransporter() {
  if (process.env.MAIL_USER && process.env.MAIL_PASS) {
    return nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.MAIL_USER, pass: process.env.MAIL_PASS },
    });
  }
  return null;
}

async function sendAlertEmail({ to, domain, previousScore, newScore, previousLetter, newLetter, criticalFailures }) {
  const worsened = newScore < previousScore;
  const improved = newScore > previousScore;

  const subject = worsened
    ? `⚠️ Alerta: ${domain} ha empeorado su seguridad (${previousScore}→${newScore})`
    : improved
    ? `✅ ${domain} ha mejorado su seguridad (${previousScore}→${newScore})`
    : `📊 Informe de monitorización: ${domain}`;

  const color = worsened ? '#D93025' : improved ? '#00875A' : '#0066FF';
  const icon = worsened ? '⚠️' : improved ? '✅' : '📊';

  const criticalHtml = (criticalFailures && criticalFailures.length)
    ? `
      <div style="background:#FEF2F2;border:1px solid #FCA5A5;border-radius:10px;padding:16px;margin-bottom:20px;">
        <p style="font-size:13px;font-weight:600;color:#D93025;margin:0 0 10px;">Problemas críticos detectados:</p>
        ${criticalFailures.map(f => `<div style="font-size:13px;color:#3D3D4E;margin-bottom:6px;">• ${f}</div>`).join('')}
      </div>`
    : '';

  const html = `
<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#F8F7F4;font-family:'Helvetica Neue',Arial,sans-serif;">
  <div style="max-width:560px;margin:40px auto;background:white;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(15,15,20,.08);">
    <div style="background:#0F0F14;padding:24px 36px;display:flex;align-items:center;gap:10px;">
      <span style="color:white;font-size:18px;font-weight:600;">🔍 WebScan</span>
      <span style="color:rgba(255,255,255,.4);font-size:12px;margin-left:auto;">Monitorización automática</span>
    </div>
    <div style="padding:36px;">
      <div style="font-size:32px;margin-bottom:8px;">${icon}</div>
      <h1 style="font-size:20px;font-weight:600;color:#0F0F14;margin:0 0 16px;">${domain}</h1>
      
      <div style="display:flex;align-items:center;gap:16px;background:#F8F7F4;border-radius:12px;padding:20px;margin-bottom:20px;">
        <div style="text-align:center;flex:1;">
          <div style="font-size:11px;color:#8B8B9E;margin-bottom:4px;">Antes</div>
          <div style="font-size:28px;font-weight:700;color:#8B8B9E;font-family:monospace;">${previousLetter}</div>
          <div style="font-size:12px;color:#8B8B9E;">${previousScore}/100</div>
        </div>
        <div style="font-size:20px;color:#C4C4CF;">→</div>
        <div style="text-align:center;flex:1;">
          <div style="font-size:11px;color:#8B8B9E;margin-bottom:4px;">Ahora</div>
          <div style="font-size:28px;font-weight:700;color:${color};font-family:monospace;">${newLetter}</div>
          <div style="font-size:12px;color:${color};">${newScore}/100</div>
        </div>
      </div>

      ${criticalHtml}

      <p style="font-size:14px;color:#3D3D4E;line-height:1.6;margin:0 0 24px;">
        ${worsened
          ? 'Hemos detectado un empeoramiento en la seguridad de tu dominio. Te recomendamos revisar el informe completo cuanto antes.'
          : improved
          ? 'Buenas noticias — la seguridad de tu dominio ha mejorado desde el último análisis.'
          : 'Este es tu informe periódico de monitorización automática.'}
      </p>

      <a href="https://webscanc-production.up.railway.app/?url=${encodeURIComponent('https://'+domain)}" 
         style="display:inline-block;background:#0066FF;color:white;text-decoration:none;padding:12px 24px;border-radius:10px;font-size:14px;font-weight:500;">
        Ver informe completo →
      </a>
    </div>
    <div style="background:#F8F7F4;padding:20px 36px;border-top:1px solid #E6E4DF;">
      <p style="font-size:12px;color:#C4C4CF;margin:0;text-align:center;">
        WebScan · Monitorización automática activa para ${domain}<br>
        ¿Dudas? <a href="mailto:molinocatenad@gmail.com" style="color:#8B8B9E;">molinocatenad@gmail.com</a>
      </p>
    </div>
  </div>
</body>
</html>`;

  const transporter = getTransporter();
  if (!transporter) {
    console.log(`📧 ALERTA (sin SMTP configurado) para ${to}: ${domain} ${previousScore}→${newScore}`);
    return { success: true, simulated: true };
  }

  try {
    const info = await transporter.sendMail({
      from: `"WebScan Monitorización" <${process.env.MAIL_USER}>`,
      to,
      subject,
      html,
    });
    console.log(`📧 Alerta enviada a ${to} (${domain}): ${info.messageId}`);
    return { success: true, messageId: info.messageId };
  } catch (err) {
    console.error(`❌ Error enviando alerta a ${to}:`, err.message);
    return { success: false, error: err.message };
  }
}

module.exports = { sendAlertEmail };
