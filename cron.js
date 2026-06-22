// services/cron.js
// Job programado: revisa los dominios monitorizados que tocan hoy,
// los analiza de nuevo, compara con el escaneo anterior y avisa si algo cambió.
const cron = require('node-cron');
const { runScan } = require('./scanner');
const {
  getDomainsDueForCheck,
  recordScanResult,
  getPreviousScore,
} = require('./monitoring');
const { sendAlertEmail } = require('./alertMailer');

// Umbral de cambio de score que dispara una alerta (evita spam por fluctuaciones de 1-2 puntos)
const ALERT_THRESHOLD = 5;

async function checkOneDomain(monitored) {
  const url = `https://${monitored.domain}`;
  console.log(`🔍 [Monitorización] Analizando ${monitored.domain} (plan ${monitored.plan})...`);

  let result;
  try {
    result = await runScan(url);
  } catch (err) {
    console.warn(`⚠️  [Monitorización] No se pudo analizar ${monitored.domain}: ${err.message}`);
    return;
  }

  const { score, letter, passed, failed } = result.summary;
  const criticalFailures = result.categories
    .flatMap(c => c.results)
    .filter(r => r.pass === false && r.severity === 'critical')
    .map(r => r.name);

  const previous = await getPreviousScore(monitored.id);

  await recordScanResult({
    monitoredDomainId: monitored.id,
    score,
    letter,
    passed,
    failed,
    criticalFailures,
  });

  if (!previous) {
    // Primer escaneo de este dominio, no hay nada que comparar todavía
    console.log(`✅ [Monitorización] Primer escaneo de ${monitored.domain}: ${score}/100 (${letter})`);
    return;
  }

  const diff = score - previous.score;
  const significantChange = Math.abs(diff) >= ALERT_THRESHOLD;
  const hasCritical = criticalFailures.length > 0;

  if (significantChange || hasCritical) {
    await sendAlertEmail({
      to: monitored.email,
      domain: monitored.domain,
      previousScore: previous.score,
      newScore: score,
      previousLetter: previous.letter,
      newLetter: letter,
      criticalFailures,
    });
    console.log(`📧 [Monitorización] Alerta enviada: ${monitored.domain} ${previous.score}→${score}`);
  } else {
    console.log(`✅ [Monitorización] Sin cambios significativos en ${monitored.domain}: ${previous.score}→${score}`);
  }
}

// Procesa todos los dominios pendientes, uno a uno (para no saturar VirusTotal/DNS)
async function runMonitoringCycle() {
  console.log('🕐 [Monitorización] Iniciando ciclo de comprobación...');
  const due = await getDomainsDueForCheck();

  if (due.length === 0) {
    console.log('✅ [Monitorización] No hay dominios pendientes de revisión.');
    return;
  }

  console.log(`📋 [Monitorización] ${due.length} dominio(s) pendiente(s) de revisión.`);

  for (const domain of due) {
    try {
      await checkOneDomain(domain);
    } catch (err) {
      console.error(`❌ [Monitorización] Error procesando ${domain.domain}:`, err.message);
    }
    // Pequeña pausa entre dominios para no saturar las APIs externas (VirusTotal, DNS)
    await new Promise(r => setTimeout(r, 3000));
  }

  console.log('✅ [Monitorización] Ciclo completado.');
}

// Inicia el cron — se ejecuta una vez al día a las 4:00 AM.
// Cada dominio individualmente decide si le toca o no según su frecuencia (daily/weekly/monthly),
// la función getDomainsDueForCheck ya filtra eso.
function startCron() {
  // Formato: minuto hora * * *  →  4:00 AM todos los días
  cron.schedule('0 4 * * *', () => {
    runMonitoringCycle().catch(err => console.error('❌ Error en ciclo de monitorización:', err));
  });
  console.log('⏰ Cron de monitorización programado (diario a las 4:00 AM)');
}

module.exports = { startCron, runMonitoringCycle };
