// services/mailer.js
// Envía emails usando Gmail (o cualquier SMTP)
// Configura MAIL_USER y MAIL_PASS en .env
const nodemailer = require('nodemailer');

function getTransporter() {
  // Soporta Gmail y SMTP genérico
  if (process.env.MAIL_USER && process.env.MAIL_PASS) {
    return nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.MAIL_USER,  // tu@gmail.com
        pass: process.env.MAIL_PASS,  // contraseña de aplicación de Google
      },
    });
  }
  // Fallback: log en consola (para desarrollo sin email configurado)
  return null;
}

async function sendLicenseEmail({ to, plan, code }) {
  const planName = plan === 'agency' ? 'Agencia' : 'Pro';
  const planPrice = plan === 'agency' ? '100€/mes' : '50€/mes';
  const features = plan === 'agency'
    ? ['Análisis ilimitados', 'Informe PDF profesional', 'Panel SaaS completo', 'Monitorización diaria', 'Dominios ilimitados', 'Informes white-label', 'Acceso API completo', 'Soporte prioritario 24h']
    : ['Análisis ilimitados', 'Informe PDF profesional', 'Panel SaaS completo', 'Monitorización semanal', 'Hasta 10 dominios', 'Alertas por email'];

  const subject = `Tu código de activación WebScan ${planName} — ${code}`;
  
  const html = `
<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#F8F7F4;font-family:'Helvetica Neue',Arial,sans-serif;">
  <div style="max-width:560px;margin:40px auto;background:white;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(15,15,20,.08);">
    
    <!-- Header -->
    <div style="background:#0F0F14;padding:28px 36px;display:flex;align-items:center;gap:10px;">
      <div style="background:rgba(255,255,255,.1);width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;">
        <span style="color:white;font-size:16px;">🔍</span>
      </div>
      <span style="color:white;font-size:18px;font-weight:600;letter-spacing:-.02em;">WebScan</span>
    </div>
    
    <!-- Body -->
    <div style="padding:36px;">
      <h1 style="font-size:22px;font-weight:600;color:#0F0F14;margin:0 0 8px;letter-spacing:-.02em;">
        ¡Tu plan ${planName} está listo!
      </h1>
      <p style="font-size:15px;color:#3D3D4E;line-height:1.6;margin:0 0 28px;">
        Gracias por suscribirte a WebScan ${planName} (${planPrice}). 
        Tu código de activación personal es:
      </p>
      
      <!-- Code -->
      <div style="background:#F8F7F4;border:2px dashed #E6E4DF;border-radius:12px;padding:20px;text-align:center;margin-bottom:28px;">
        <div style="font-family:'Courier New',monospace;font-size:24px;font-weight:600;color:#0066FF;letter-spacing:.08em;">
          ${code}
        </div>
        <div style="font-size:12px;color:#8B8B9E;margin-top:8px;">Código de activación personal · No compartas este código</div>
      </div>
      
      <!-- Instructions -->
      <div style="margin-bottom:28px;">
        <p style="font-size:14px;font-weight:500;color:#0F0F14;margin:0 0 12px;">Cómo activarlo:</p>
        <div style="display:flex;flex-direction:column;gap:10px;">
          <div style="display:flex;gap:12px;align-items:flex-start;">
            <div style="background:#0066FF;color:white;width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600;flex-shrink:0;margin-top:1px;">1</div>
            <div style="font-size:14px;color:#3D3D4E;">Ve a <a href="https://webscanc-production.up.railway.app" style="color:#0066FF;text-decoration:none;font-weight:500;">webscanc-production.up.railway.app</a></div>
          </div>
          <div style="display:flex;gap:12px;align-items:flex-start;">
            <div style="background:#0066FF;color:white;width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600;flex-shrink:0;margin-top:1px;">2</div>
            <div style="font-size:14px;color:#3D3D4E;">Analiza cualquier web y pulsa el botón de PDF u otra función Pro</div>
          </div>
          <div style="display:flex;gap:12px;align-items:flex-start;">
            <div style="background:#0066FF;color:white;width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600;flex-shrink:0;margin-top:1px;">3</div>
            <div style="font-size:14px;color:#3D3D4E;">En el modal que aparece, pulsa <strong>"¿Tienes un código?"</strong> e introduce el código de arriba</div>
          </div>
        </div>
      </div>
      
      <!-- Features -->
      <div style="background:#F8F7F4;border-radius:10px;padding:18px;margin-bottom:28px;">
        <p style="font-size:13px;font-weight:500;color:#0F0F14;margin:0 0 10px;">Tu plan ${planName} incluye:</p>
        ${features.map(f => `
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
          <span style="color:#00875A;font-size:14px;">✓</span>
          <span style="font-size:13px;color:#3D3D4E;">${f}</span>
        </div>`).join('')}
      </div>
      
      <p style="font-size:13px;color:#8B8B9E;line-height:1.6;margin:0;">
        ¿Alguna duda? Escríbenos a 
        <a href="mailto:molinocatenad@gmail.com" style="color:#0066FF;text-decoration:none;">molinocatenad@gmail.com</a> 
        y te respondemos en menos de 24 horas.
      </p>
    </div>
    
    <!-- Footer -->
    <div style="background:#F8F7F4;padding:20px 36px;border-top:1px solid #E6E4DF;">
      <p style="font-size:12px;color:#C4C4CF;margin:0;text-align:center;">
        WebScan · Auditoría de seguridad web profesional<br>
        Has recibido este email porque compraste una suscripción WebScan.
      </p>
    </div>
  </div>
</body>
</html>`;

  const text = `
WebScan ${planName} — Código de activación

Tu código: ${code}

Cómo activarlo:
1. Ve a webscanc-production.up.railway.app
2. Analiza cualquier web y pulsa PDF u otra función Pro
3. Pulsa "¿Tienes un código?" e introduce: ${code}

¿Dudas? molinocatenad@gmail.com
`;

  const transporter = getTransporter();
  
  if (!transporter) {
    // Sin email configurado — solo log en consola
    console.log('📧 EMAIL (sin SMTP configurado):');
    console.log(`   Para: ${to}`);
    console.log(`   Asunto: ${subject}`);
    console.log(`   Código: ${code}`);
    console.log(`   Plan: ${planName}`);
    return { success: true, simulated: true };
  }

  try {
    const info = await transporter.sendMail({
      from: `"WebScan" <${process.env.MAIL_USER}>`,
      to,
      subject,
      text,
      html,
    });
    console.log(`📧 Email enviado a ${to}: ${info.messageId}`);
    return { success: true, messageId: info.messageId };
  } catch (err) {
    console.error(`❌ Error enviando email a ${to}:`, err.message);
    return { success: false, error: err.message };
  }
}

module.exports = { sendLicenseEmail };
