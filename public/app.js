
function sanitizeURL(input) {
  const s = String(input).trim().slice(0, 2048);
  if (!s) return null;
  try {
    const url = new URL(s.startsWith('http') ? s : 'https://' + s);
    if (!['http:','https:'].includes(url.protocol)) return null;
    const host = url.hostname;
    if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|0\.0\.0\.0|::1)/.test(host)) return null;
    if (/[<>"'`]/.test(s)) return null;
    return url.href;
  } catch { return null; }
}
function escapeHTML(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

// Convierte fix instructions (markdown reducido) a HTML seguro con bloques de código
function renderFix(text) {
  if (!text) return '';
  let html = escapeHTML(text);
  // Bloques de código ```...```
  html = html.replace(/```(\w*)\n?([\s\S]*?)```/g, (_, lang, code) =>
    `<pre class="fix-code"><code>${code.trim()}</code></pre>`
  );
  // Inline code `...`
  html = html.replace(/`([^`\n]+)`/g, '<code class="fix-inline">$1</code>');
  // **negrita**
  html = html.replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>');
  // Doble salto = nuevo párrafo
  html = html.replace(/\n\n/g, '</p><p>');
  // Salto simple = <br>
  html = html.replace(/\n/g, '<br>');
  return `<p>${html}</p>`;
}

const PLANS = {
  free:   {name:'Free',   maxScans:3,  pdf:false,monitoring:false,whitelabel:false,domains:1,  api:false,saas:false},
  pro:    {name:'Pro',    maxScans:Infinity,pdf:true, monitoring:true, whitelabel:false,domains:10, api:false,saas:true},
  agency: {name:'Agencia',maxScans:Infinity,pdf:true, monitoring:true, whitelabel:true, domains:Infinity,api:true, saas:true}
};
const VALID_CODES = {'WEBSCAN-PRO-2025':'pro','WEBSCAN-AGN-2025':'agency','WEBSCAN-DEMO-PRO':'pro','WEBSCAN-DEMO-AGN':'agency'};

function getState() {
  try {
    const raw = localStorage.getItem('ws_v2');
    const s = raw ? JSON.parse(raw) : {};
    const mk = `${new Date().getFullYear()}-${new Date().getMonth()}`;
    if (s.mk !== mk) { s.scans=[]; s.mk=mk; saveState(s); }
    return s;
  } catch { return {plan:'free',scans:[],mk:''} }
}
function saveState(s) { try { localStorage.setItem('ws_v2', JSON.stringify(s)); } catch {} }
function getCurrentPlan() { return getState().plan || 'free'; }
function getPlanInfo() { return PLANS[getCurrentPlan()]; }
function getScansUsed() { return (getState().scans||[]).length; }
function getScansLeft() { const p=getPlanInfo(); return p.maxScans===Infinity?Infinity:Math.max(0,p.maxScans-getScansUsed()); }
function recordScan() { const s=getState(); s.scans=[...(s.scans||[]),Date.now()]; saveState(s); }
function setPlan(plan, licenseCode) {
  const s=getState(); s.plan=plan; s.activated=Date.now();
  if (licenseCode) s.licenseCode = licenseCode;
  saveState(s);
  renderPlanUI();
  showToast(`Plan ${PLANS[plan].name} activado ✓`,'ok');
  // Si hay resultados de un analisis anterior en pantalla, re-renderizarlos con el nuevo plan
  if (scanData && scanData.results) {
    rerenderResults();
  }
}
function getLicenseCode(){ return getState().licenseCode || null; }

function rerenderResults(){
  if(!scanData || !scanData.results) return;
  const containerId = scanData.lastContainer || 'results';
  const container = document.getElementById(containerId);
  if(!container) return;
  renderResultsUI(container, scanData.domain, scanData.results, scanData.sc, false, false);
  showToast('Plan actualizado — resultados actualizados ✓', 'ok');
}

function renderPlanUI() {
  const plan=getCurrentPlan(), info=PLANS[plan];
  const badge=document.getElementById('plan-badge');
  if(badge){ badge.className=`plan-indicator ${plan}`; badge.innerHTML=`<span class="pi-dot"></span>${info.name}`; }
  renderScanCounter();
}
function renderScanCounter() {
  const plan=getCurrentPlan(), used=getScansUsed(), left=getScansLeft();
  ['scan-counter-hero','scan-counter-main'].forEach(id=>{
    const el=document.getElementById(id); if(!el) return;
    if(plan!=='free'){ el.innerHTML='<span style="font-family:var(--mono);font-size:12px;color:var(--ink3)">✓ Análisis ilimitados</span>'; return; }
    const cls=left===0?'exhausted':left===1?'warn':'';
    const dots=Array.from({length:3},(_,i)=>`<span class="sc-dot ${i<used?(left===0?'out':'used'):''}"></span>`).join('');
    el.className=`scan-counter ${cls}`;
    el.innerHTML=`<span class="sc-dots">${dots}</span><span>${left===0?'Límite mensual alcanzado':`${left} análisis restante${left!==1?'s':''} este mes`}</span>`;
  });
}

function openModal(type) {
  const cfg = {
    limit:      {icon:'limit',e:'🚫',title:'Límite mensual alcanzado',desc:'Has usado tus 3 análisis gratuitos del mes. Actualiza a Pro para análisis ilimitados, PDF y monitorización.'},
    pdf:        {icon:'lock',e:'📄',title:'Informe PDF — Plan Pro',desc:'Los informes PDF profesionales están disponibles desde el plan Pro. Listos para entregar al cliente en segundos.'},
    monitoring: {icon:'lock',e:'📡',title:'Monitorización — Plan Pro',desc:'Recibe alertas automáticas cuando cambie la seguridad de tu web. Panel SaaS incluido con historial y tendencias.'},
    saas:       {icon:'lock',e:'📊',title:'Panel SaaS — Plan Pro',desc:'Gestiona todos tus dominios desde un panel centralizado con historial, alertas y comparativas de evolución.'},
    whitelabel: {icon:'lock',e:'🏷️',title:'White-label — Plan Agencia',desc:'Informes con tu logo y colores. Tus clientes ven tu marca, no la nuestra. Dominios ilimitados y API incluidos.'},
    api:        {icon:'lock',e:'⚙️',title:'API — Plan Agencia',desc:'Integra WebScan en tus sistemas. Lanza análisis programáticamente y recibe resultados estructurados en JSON.'},
  };
  const c=cfg[type]||cfg.limit;
  document.getElementById('modal-icon').className=`modal-icon ${c.icon}`;
  document.getElementById('modal-icon').textContent=c.e;
  document.getElementById('modal-title').textContent=c.title;
  document.getElementById('modal-desc').textContent=c.desc;
  const isAgency=type==='whitelabel'||type==='api';
  const plans=isAgency
    ?[{key:'agency',icon:'🏢',name:'Agencia',desc:'Dominios ilimitados · White-label · API',price:'100€/mes',featured:true}]
    :[{key:'pro',icon:'⚡',name:'Pro',desc:'Ilimitados · PDF · Monitorización · SaaS',price:'50€/mes',featured:true},{key:'agency',icon:'🏢',name:'Agencia',desc:'Todo Pro + White-label + API',price:'100€/mes',featured:false}];
  document.getElementById('modal-plans').innerHTML=plans.map(p=>`
    <button class="modal-plan ${p.featured?'featured':''}" onclick="goToStripe('${escapeHTML(p.key)}')">
      <span class="modal-plan-icon">${p.icon}</span>
      <div style="flex:1"><div class="modal-plan-name">${escapeHTML(p.name)}</div><div class="modal-plan-desc">${escapeHTML(p.desc)}</div></div>
      <span class="modal-plan-price">${escapeHTML(p.price)}</span>
    </button>`).join('');
  document.getElementById('modal-overlay').classList.add('show');
  document.body.style.overflow='hidden';
}
function closeModal(){ document.getElementById('modal-overlay').classList.remove('show'); document.body.style.overflow=''; document.getElementById('code-section').style.display='none'; document.getElementById('activation-code').value=''; }
function goToStripe(plan){ const urls={pro:'https://buy.stripe.com/6oUaEX6WHdn76eL1AZ8so02',agency:'https://buy.stripe.com/6oUdR9ftd1EpdHddjH8so03'}; if(urls[plan]){closeModal();window.open(urls[plan],'_blank','noopener,noreferrer');} }
function showCodeInput(){ document.getElementById('code-section').style.display='block'; document.getElementById('activation-code').focus(); }
function activateCode(){
  const code = document.getElementById('activation-code').value.trim().toUpperCase();
  if (!code) return;

  const btn = document.querySelector('#code-section .code-submit');
  if (btn) { btn.disabled = true; btn.textContent = 'Verificando...'; }

  fetch('/api/activate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code })
  })
  .then(r => r.json())
  .then(data => {
    if (btn) { btn.disabled = false; btn.textContent = 'Activar'; }
    if (data.valid) {
      closeModal();
      setPlan(data.plan, code);
    } else {
      showToast(data.message || 'Código no válido', 'error');
      const input = document.getElementById('activation-code');
      if (input) { input.style.borderColor = 'var(--red)'; setTimeout(() => input.style.borderColor = '', 2000); }
    }
  })
  .catch(() => {
    if (btn) { btn.disabled = false; btn.textContent = 'Activar'; }
    showToast('Error de conexión. Inténtalo de nuevo.', 'error');
  });
}
let scanData=null;
const delay=ms=>new Promise(r=>setTimeout(r,ms));
let scanRateLimit={count:0,ts:0};

async function startScan(inputId,resultId) {
  const now=Date.now();
  if(now-scanRateLimit.ts<10000&&scanRateLimit.count>0){ showToast('Espera unos segundos antes de volver a analizar','error'); return; }

  const rawInput=document.getElementById(inputId)?.value?.trim();
  const url=sanitizeURL(rawInput);
  if(!url){ showToast('Introduce una URL válida (ej: https://tuempresa.com)','error'); document.getElementById(inputId)?.focus(); return; }

  if(getCurrentPlan()==='free'&&getScansLeft()<=0){ openModal('limit'); return; }

  scanRateLimit={count:scanRateLimit.count+1,ts:now};
  const btn=document.getElementById('scan-btn2');
  if(btn) btn.disabled=true;

  const domain=escapeHTML(new URL(url).hostname);
  const container=document.getElementById(resultId);
  container.innerHTML='';

  const term=document.createElement('div');
  term.className='terminal';
  term.setAttribute('role','log');
  term.setAttribute('aria-live','polite');
  container.appendChild(term);
  if(resultId==='results') container.scrollIntoView({behavior:'smooth',block:'start'});

  const steps=[
    ['>','tt',`Iniciando análisis de ${domain}...`],
    ['>','tt','Resolviendo DNS y conectando...'],
    ['>','tt','Verificando certificado SSL/TLS...'],
    ['>','tt','Analizando cabeceras de seguridad HTTP...'],
    ['>','tt','Consultando VirusTotal...'],
    ['>','tt','Verificando SPF · DMARC · DKIM · DNSSEC...'],
    ['>','tt','Inspeccionando cookies de seguridad...'],
    ['>','tt','Detectando CMS y versiones expuestas...'],
    ['>','tt','Buscando archivos sensibles (.env, .git)...'],
    ['>','tt','Analizando redirects y contenido mixto...'],
    ['>','tt','Midiendo TTFB y compresión...'],
  ];

  // Lanzar la peticion real al backend en paralelo a la animacion
  const apiPromise = fetch('/api/scan', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({url, license: getLicenseCode()})
  }).then(r=>r.json()).catch(e=>({error:true,message:e.message}));

  for(const[sym,cls,txt] of steps){
    await delay(160+Math.random()*140);
    const ln=document.createElement('div'); ln.className='tl';
    ln.innerHTML=`<span class="${escapeHTML(cls)}">${escapeHTML(sym)}</span><span class="tt">${escapeHTML(txt)}</span>`;
    term.appendChild(ln); term.scrollTop=term.scrollHeight;
  }
  const cur=document.createElement('div'); cur.className='tl';
  cur.innerHTML='<span class="tp">&gt;</span><span class="tcursor"></span>';
  term.appendChild(cur);

  // Esperar respuesta real del backend (con minimo de tiempo para que la animacion no parpadee)
  let apiResult;
  try {
    apiResult = await apiPromise;
  } catch(fetchErr) {
    apiResult = { error: true, message: fetchErr.message };
  }
  await delay(300);

  if(apiResult.error){
    term.innerHTML+=`<div class="tl"><span class="tf">ERROR</span><span class="tt">${escapeHTML(apiResult.message||'No se pudo completar el análisis')}</span></div>`;
    if(btn) btn.disabled=false;
    showToast(apiResult.message||'No se pudo conectar con el servidor. Inténtalo de nuevo en unos segundos.','error');
    return;
  }

  const okLine=document.createElement('div'); okLine.className='tl';
  okLine.innerHTML='<span class="tok">OK</span><span class="tt">Análisis completado. Generando informe...</span>';
  term.appendChild(okLine);
  await delay(250);

  recordScan(); renderScanCounter();

  const results = apiResult.categories;
  const sc = {
    passed: apiResult.summary.passed,
    failed: apiResult.summary.failed,
    total: apiResult.summary.total,
    pct: apiResult.summary.pct,
    letter: apiResult.summary.letter,
    color: apiResult.summary.color,
    score: apiResult.summary.score,
  };
  scanData={url,domain,results,sc,lastContainer:resultId};
  container.innerHTML='';
  await renderResultsUI(container, domain, results, sc, false, true);

  if(btn) btn.disabled=false;
  showToast(`Análisis completado · Score ${sc.letter} · ${sc.score}/100`,'ok');
  container.scrollIntoView({behavior:'smooth',block:'start'});
}

async function renderResultsUI(container, domain, results, sc, isDemo, animate){
  container.innerHTML='';
  const plan=getCurrentPlan(), info=getPlanInfo();

  const sum=document.createElement('div'); sum.className='results-summary';
  sum.innerHTML=`
    <div>
      <svg width="100" height="60" viewBox="0 0 100 60" role="img" aria-label="Puntuación ${sc.score} de 100">
        <path d="M 8 54 A 42 42 0 0 1 92 54" fill="none" stroke="var(--paper3)" stroke-width="6" stroke-linecap="round"/>
        <path d="M 8 54 A 42 42 0 0 1 92 54" fill="none" stroke="${escapeHTML(sc.color)}" stroke-width="6" stroke-linecap="round"
          stroke-dasharray="132" stroke-dashoffset="${132-132*sc.pct}" style="transition:stroke-dashoffset 1s ease"/>
        <text x="50" y="46" text-anchor="middle" font-family="DM Mono,monospace" font-size="20" font-weight="500" fill="var(--ink)">${sc.score}</text>
        <text x="50" y="58" text-anchor="middle" font-family="DM Mono,monospace" font-size="9" fill="var(--ink4)">/ 100</text>
      </svg>
    </div>
    <div class="rs-stats">
      <div><div class="rs-stat-val ok">${sc.passed}</div><div class="rs-stat-label">correctas</div></div>
      <div><div class="rs-stat-val fail">${sc.failed}</div><div class="rs-stat-label">problemas</div></div>
      <div><div class="rs-stat-val">${sc.total}</div><div class="rs-stat-label">total</div></div>
      <div><div class="rs-stat-val" style="color:${escapeHTML(sc.color)}">${escapeHTML(sc.letter)}</div><div class="rs-stat-label">puntuación</div></div>
    </div>`;
  container.appendChild(sum);

  if(isDemo){
    const dm=document.createElement('div'); dm.style.cssText='background:var(--amber-bg);border:1px solid var(--amber-border);border-radius:var(--radius-lg);padding:12px 16px;margin-bottom:16px;font-size:13px;color:var(--amber)';
    dm.textContent='⚠ Resultados de demostración (backend no disponible)';
    container.appendChild(dm);
  }

  if(info.monitoring){
    const isAg=plan==='agency';
    const mp=document.createElement('div'); mp.className='monitoring-panel'; mp.id='monitoring-panel-live';
    mp.innerHTML=`
      <div class="mp-header">
        <div class="mp-title">📡 Monitorización automática <span class="pro-badge ${isAg?'agency-badge':''}">${isAg?'AGENCIA':'PRO'}</span></div>
        <div class="mp-toggle" id="mp-toggle-wrap">
          <span id="mp-status-text">Comprobando…</span>
          <div class="toggle-sw off" id="mp-toggle-switch" role="switch" aria-checked="false" tabindex="0"></div>
        </div>
      </div>
      <div class="mp-schedules" id="mp-schedules">
        ${(isAg?['Diaria','Semanal','Mensual']:['Semanal','Mensual']).map((l,i)=>
          `<span class="mp-chip" data-freq="${l==='Diaria'?'daily':l==='Semanal'?'weekly':'monthly'}">${l}</span>`).join('')}
      </div>
      <div style="font-size:11px;color:var(--ink3);margin-top:10px;line-height:1.5;">
        Te avisaremos por email si el score de <strong>${escapeHTML(domain)}</strong> cambia ${'>'}5 puntos o aparece un problema crítico nuevo.
      </div>`;
    container.appendChild(mp);
    initMonitoringPanel(domain);
  }

  if(plan==='agency'){
    const fk='wsk_live_'+Math.random().toString(36).slice(2,10)+Math.random().toString(36).slice(2,10);
    const ap=document.createElement('div'); ap.className='agency-panel';
    ap.innerHTML=`
      <div class="ap-title">🏢 Panel Agencia <span class="pro-badge agency-badge">AGENCIA</span></div>
      <div class="ap-grid">
        <div class="ap-item"><div class="ap-item-title">Dominios gestionados</div><div class="ap-item-val">Ilimitados</div></div>
        <div class="ap-item"><div class="ap-item-title">Informes</div><div class="ap-item-val">White-label activo</div></div>
        <div class="ap-item" style="grid-column:1/-1">
          <div class="ap-item-title">Clave API</div>
          <div class="ap-api-key"><span>${escapeHTML(fk)}</span><button class="ap-copy" onclick="copyAPIKey('${escapeHTML(fk)}')">Copiar</button></div>
        </div>
      </div>`;
    container.appendChild(ap);
  }

  const expRow=document.createElement('div'); expRow.className='export-row';
  if(info.pdf){
    expRow.innerHTML+=`<button class="export-btn primary-export" onclick="exportPDF()">📄 Exportar PDF${plan==='agency'?' <span class="pro-badge agency-badge">WL</span>':''}</button>`;
  } else {
    expRow.innerHTML+=`<button class="export-btn" style="opacity:.5" onclick="openModal('pdf')" title="Plan Pro">📄 PDF 🔒</button>`;
  }
  expRow.innerHTML+=`<button class="export-btn" onclick="exportCSV()">📊 Exportar CSV</button>`;
  expRow.innerHTML+=`<button class="export-btn" onclick="copyShareLink()">🔗 Copiar enlace</button>`;
  container.appendChild(expRow);

  if(plan==='free'){
    const left=getScansLeft();
    const ub=document.createElement('div'); ub.className='upgrade-banner';
    ub.innerHTML=`
      <div class="ub-text">
        <div class="ub-title">${left===0?'Has agotado tus análisis del mes':`Te quedan ${left} análisis gratuito${left!==1?'s':''} este mes`}</div>
        <div class="ub-desc">Pro incluye ilimitados, PDF, monitorización y panel SaaS completo.</div>
      </div>
      <button class="ub-btn" onclick="openModal('limit')">Ver planes →</button>`;
    container.appendChild(ub);
  }

  const hdr=document.createElement('div');
  hdr.style.cssText='display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px;margin-top:8px';
  hdr.innerHTML=`
    <span style="font-family:var(--mono);font-size:13px;color:var(--ink3);display:flex;align-items:center;gap:6px">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
      ${domain}
    </span>
    <span style="font-family:var(--mono);font-size:11px;color:var(--ink4)">${new Date().toLocaleDateString('es-ES',{day:'2-digit',month:'short',year:'numeric'})}</span>`;
  container.appendChild(hdr);

  for(let i=0;i<results.length;i++){
    const cat=results[i];
    const catFailed=cat.results.filter(r=>r.pass===false).length;
    const catNA=cat.results.filter(r=>r.pass===null).length;
    const catPassed=cat.results.length-catFailed-catNA;
    const pillCls=catFailed===0?'ok':catFailed<=2?'warn':'fail';
    const pillTxt=catFailed===0?'OK':`${catFailed} problema${catFailed>1?'s':''}`;
    const sec=document.createElement('div');
    sec.className='result-section'+(i===0?' open':'');
    sec.innerHTML=`
      <div class="rs-header" onclick="toggleSec(this)" role="button" tabindex="0" aria-expanded="${i===0}">
        <span class="rs-icon">${cat.icon}</span>
        <span class="rs-title">${escapeHTML(cat.cat)}</span>
        <div class="rs-pills"><span class="rs-pill ${pillCls}">${pillTxt}</span><span class="rs-count">${catPassed}/${cat.results.length}</span></div>
        <span class="rs-chev">▼</span>
      </div>
      <div class="rs-body">
        ${cat.results.map((r,idx)=>{
          const icon = r.pass===null?'⚪':r.pass?'✅':'❌';
          const valCls = r.pass===null?'warn':r.pass?'ok':'fail';
          const sevCls = r.pass===null?'low':r.pass?'low':escapeHTML(r.severity||'medium');
          const sevTxt = r.pass===null?'INFO':r.pass?'OK':escapeHTML(r.severity||'medium').toUpperCase();
          return `
          <div class="check-row" style="animation-delay:${idx*30}ms">
            <span class="cr-icon">${icon}</span>
            <div class="cr-main">
              <div class="cr-name">
                ${escapeHTML(r.name)}
                <span class="cr-severity sev-${sevCls}">${sevTxt}</span>
                ${r.owasp ? `<span class="cr-owasp">${escapeHTML(r.owasp)}</span>` : ''}
              </div>
              <div class="cr-desc">${escapeHTML(r.desc)}</div>
              <div class="cr-val ${valCls}">${escapeHTML(r.value)}</div>
              ${r.pass===false&&r.fix?`<div class="cr-fix">💡 Cómo solucionarlo ▾</div><div class="cr-fix-detail">${renderFix(r.fix)}</div>`:''}
            </div>
          </div>`;}).join('')}
      </div>`;
    container.appendChild(sec);
    if(animate) await delay(40);
  }

  if(plan==='free'){
    const lw=document.createElement('div'); lw.style.marginTop='16px';
    lw.innerHTML=`
      <div style="font-family:var(--mono);font-size:10px;color:var(--ink3);letter-spacing:.08em;text-transform:uppercase;margin-bottom:10px">Funciones desbloqueables</div>
      <div class="locked-card"><span class="locked-icon">📄</span><div class="locked-text"><div class="locked-title">Informe PDF profesional <span class="pro-badge">PRO</span></div><div class="locked-desc">PDF listo para entregar al cliente con resultados, severidad y recomendaciones.</div></div><button class="locked-btn" onclick="openModal('pdf')">Desbloquear</button></div>
      <div class="locked-card"><span class="locked-icon">📡</span><div class="locked-text"><div class="locked-title">Monitorización automática <span class="pro-badge">PRO</span></div><div class="locked-desc">Alertas por email cuando cambie el estado de seguridad de tu dominio.</div></div><button class="locked-btn" onclick="openModal('monitoring')">Desbloquear</button></div>
      <div class="locked-card"><span class="locked-icon">📊</span><div class="locked-text"><div class="locked-title">Panel SaaS completo <span class="pro-badge">PRO</span></div><div class="locked-desc">Gestiona múltiples dominios, historial y tendencias desde un panel centralizado.</div></div><button class="locked-btn" onclick="openModal('saas')">Desbloquear</button></div>
      <div class="locked-card"><span class="locked-icon">🏷️</span><div class="locked-text"><div class="locked-title">White-label + API <span class="pro-badge agency-badge">AGENCIA</span></div><div class="locked-desc">Informes con tu marca. Integración API para automatizar auditorías.</div></div><button class="locked-btn" onclick="openModal('whitelabel')">Desbloquear</button></div>`;
    container.appendChild(lw);
  }
}

function toggleSec(hdr){
  const sec=hdr.parentElement, isOpen=sec.classList.contains('open');
  sec.classList.toggle('open',!isOpen);
  hdr.setAttribute('aria-expanded',!isOpen);
}
function toggleFix(el){
  const detail = el.nextElementSibling;
  if(!detail) return;
  const isOpen = detail.classList.contains('open');
  detail.classList.toggle('open', !isOpen);
  el.textContent = isOpen ? '💡 Cómo solucionarlo ▾' : '💡 Ocultar solución ▴';
}
function rndIP(){ return `${Math.floor(Math.random()*200+50)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`; }
function exportCSV(){
  if(!scanData) return;
  const rows=[['Dominio','Categoría','Comprobación','Estado','Severidad','Valor','Descripción','Solución']];
  scanData.results.forEach(cat=>cat.results.forEach(r=>{
    rows.push([scanData.domain,cat.cat,r.name,r.pass?'OK':'FALLO',r.pass?'':r.severity||'medium',r.value,r.desc,r.fix||'']);
  }));
  const csv=rows.map(r=>r.map(c=>`"${String(c).replace(/"/g,'""')}"`).join(',')).join('\r\n');
  const blob=new Blob(['\uFEFF'+csv],{type:'text/csv;charset=utf-8;'});
  const blobUrl=URL.createObjectURL(blob);
  const a=document.createElement('a'); a.href=blobUrl;
  a.download=`webscan-${scanData.domain}-${Date.now()}.csv`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(()=>URL.revokeObjectURL(blobUrl),5000);
  showToast('CSV descargado','ok');
}

function exportPDF(){
  if(!scanData) return;
  if(!getPlanInfo().pdf){ openModal('pdf'); return; }
  const {domain,sc,results}=scanData;
  const date=new Date().toLocaleDateString('es-ES',{day:'2-digit',month:'long',year:'numeric'});
  const wl=getCurrentPlan()==='agency';
  let cats='';
  results.forEach(cat=>{
    cats+=`<h2 style="font-size:13px;font-weight:600;color:#0f0f14;margin:24px 0 10px;padding-bottom:6px;border-bottom:2px solid #e6e4df;font-family:Arial">${cat.icon} ${cat.cat}</h2>`;
    cat.results.forEach(r=>{
      const sevColor={critical:'#D93025',high:'#B45309',medium:'#2563EB',low:'#6B7280'}[r.severity]||'#6B7280';
      cats+=`<div style="display:flex;gap:10px;padding:8px 0;border-bottom:1px solid #f0f0f0;align-items:flex-start;font-family:Arial">
        <span style="font-size:12px;flex-shrink:0;margin-top:2px">${r.pass?'OK':'X'}</span>
        <div style="flex:1">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
            <strong style="font-size:12px;color:#0f0f14">${r.name}</strong>
            ${!r.pass?`<span style="font-size:9px;font-weight:500;padding:1px 6px;border-radius:20px;background:${sevColor}22;color:${sevColor};border:1px solid ${sevColor}44">${(r.severity||'MEDIUM').toUpperCase()}</span>`:''}
          </div>
          <div style="font-size:11px;color:#8b8b9e;margin-bottom:2px">${r.desc}</div>
          <code style="font-size:10px;color:${r.pass?'#00875a':'#D93025'}">${r.value}</code>
          ${!r.pass&&r.fix?`<div style="font-size:10px;color:#3D3D4E;background:#f8f7f4;padding:6px 8px;border-radius:4px;margin-top:4px;border-left:2px solid #0066FF">Solución: ${r.fix}</div>`:''}
        </div>
      </div>`;
    });
  });
  const critical=results.flatMap(c=>c.results).filter(r=>!r.pass&&r.severity==='critical').length;
  const high=results.flatMap(c=>c.results).filter(r=>!r.pass&&r.severity==='high').length;
  const html=`<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>WebScan - ${domain}</title></head>
  <body style="margin:40px;font-family:Arial,sans-serif;color:#0f0f14;font-size:13px;max-width:800px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;padding-bottom:16px;border-bottom:2px solid #0f0f14">
      <div><h1 style="font-size:20px;font-weight:700;margin:0">${wl?'Informe de Seguridad Web':'WebScan'}</h1><div style="font-size:11px;color:#8b8b9e;margin-top:2px">${wl?'':'Auditoría de seguridad automatizada'}</div></div>
      <div style="text-align:right"><div style="font-size:11px;color:#8b8b9e">${date}</div><div style="font-size:11px;color:#8b8b9e">${domain}</div></div>
    </div>
    <div style="background:#f8f7f4;border-radius:8px;padding:16px 20px;margin:20px 0;display:flex;gap:24px;align-items:center;flex-wrap:wrap">
      <div style="text-align:center"><div style="font-size:40px;font-weight:700;color:${sc.color};font-family:monospace;line-height:1">${sc.letter}</div><div style="font-size:11px;color:#8b8b9e">Score ${sc.score}/100</div></div>
      <div style="flex:1;display:flex;gap:20px;flex-wrap:wrap">
        <div><div style="font-size:11px;color:#8b8b9e">Dominio</div><div style="font-weight:600">${domain}</div></div>
        <div><div style="font-size:11px;color:#8b8b9e">Correctas</div><div style="font-weight:600;color:#00875a">${sc.passed}</div></div>
        <div><div style="font-size:11px;color:#8b8b9e">Problemas</div><div style="font-weight:600;color:#D93025">${sc.failed}</div></div>
        <div><div style="font-size:11px;color:#8b8b9e">Críticos</div><div style="font-weight:600;color:#D93025">${critical}</div></div>
        <div><div style="font-size:11px;color:#8b8b9e">Altos</div><div style="font-weight:600;color:#B45309">${high}</div></div>
      </div>
    </div>
    ${cats}
    <div style="margin-top:40px;padding-top:16px;border-top:1px solid #e6e4df;font-size:11px;color:#c4c4cf;display:flex;justify-content:space-between">
      <span>${wl?'Informe generado con WebScan':'WebScan - webscan.app'}</span><span>${date}</span>
    </div>
    <script>window.onload=function(){setTimeout(function(){window.print();},300);};</script>
  </body></html>`;

  // Usamos un Blob URL en vez de document.write (deprecado y poco fiable en Safari).
  // Sin 'noopener' para mantener la referencia a la ventana y poder cerrarla despues.
  const blob = new Blob([html], { type: 'text/html' });
  const blobUrl = URL.createObjectURL(blob);
  const w = window.open(blobUrl, '_blank');

  if (!w) {
    // El navegador bloqueo el popup
    showToast('Tu navegador bloqueó la ventana. Permite popups para webscanc-production.up.railway.app', 'error');
    URL.revokeObjectURL(blobUrl);
    return;
  }

  // Liberar memoria del blob una vez cargado (con margen de tiempo para que imprima)
  setTimeout(() => URL.revokeObjectURL(blobUrl), 30000);
  showToast('Informe PDF generado — usa Cmd+P / Ctrl+P para guardarlo','ok');
}

function copyShareLink(){
  const url=scanData?scanData.url:'';
  const link=`${location.origin}${location.pathname}?url=${encodeURIComponent(url)}`;
  copyToClipboard(link, 'Enlace copiado');
}
function copyAPIKey(key){
  copyToClipboard(key, 'Clave API copiada');
}

// ── MONITORIZACIÓN EN VIVO (conectada al backend) ─────────────────────────
async function initMonitoringPanel(domain){
  const code = getLicenseCode();
  const switchEl = document.getElementById('mp-toggle-switch');
  const statusText = document.getElementById('mp-status-text');
  const schedules = document.getElementById('mp-schedules');
  if(!switchEl) return;

  if(!code){
    // Plan activado con codigo demo, sin licencia real persistida
    statusText.textContent = 'Modo demo';
    switchEl.style.opacity = '.4';
    switchEl.style.cursor = 'not-allowed';
    return;
  }

  let isMonitored = false;
  let currentFreq = 'weekly';

  try {
    const res = await fetch(`/api/monitoring/domains?licenseCode=${encodeURIComponent(code)}`);
    const data = await res.json();
    if(data.domains){
      const found = data.domains.find(d => d.domain === domain.toLowerCase());
      if(found){ isMonitored = true; currentFreq = found.frequency; }
    }
  } catch(e){
    statusText.textContent = 'Error de conexión';
    return;
  }

  function paintState(){
    switchEl.classList.toggle('on', isMonitored);
    switchEl.classList.toggle('off', !isMonitored);
    switchEl.setAttribute('aria-checked', isMonitored);
    statusText.textContent = isMonitored ? 'Activa' : 'Desactivada';
    schedules.querySelectorAll('.mp-chip').forEach(chip=>{
      chip.classList.toggle('active', chip.dataset.freq === currentFreq);
    });
  }
  paintState();

  switchEl.onclick = async () => {
    switchEl.style.pointerEvents='none';
    try {
      if(!isMonitored){
        const res = await fetch('/api/monitoring/domains', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ licenseCode: code, domain, frequency: currentFreq })
        });
        const data = await res.json();
        if(!res.ok || data.error){ showToast(data.message||'Error activando monitorización','error'); }
        else { isMonitored = true; showToast('Monitorización activada — recibirás alertas por email','ok'); }
      } else {
        const res = await fetch(`/api/monitoring/domains/${encodeURIComponent(domain)}`, {
          method:'DELETE', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ licenseCode: code })
        });
        if(res.ok){ isMonitored = false; showToast('Monitorización desactivada','ok'); }
        else { showToast('Error desactivando monitorización','error'); }
      }
    } catch(e){
      showToast('Error de conexión con el servidor','error');
    }
    switchEl.style.pointerEvents='auto';
    paintState();
  };

  schedules.querySelectorAll('.mp-chip').forEach(chip=>{
    chip.onclick = async () => {
      const newFreq = chip.dataset.freq;
      if(newFreq === currentFreq) return;
      currentFreq = newFreq;
      paintState();
      if(isMonitored){
        try {
          const res = await fetch('/api/monitoring/domains', {
            method:'POST', headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ licenseCode: code, domain, frequency: currentFreq })
          });
          if(res.ok) showToast(`Frecuencia actualizada: ${chip.textContent}`,'ok');
        } catch(e){}
      }
    };
  });
}
function copyToClipboard(text, successMsg){
  if(navigator.clipboard && window.isSecureContext){
    navigator.clipboard.writeText(text)
      .then(()=>showToast(successMsg,'ok'))
      .catch(()=>fallbackCopy(text, successMsg));
  } else {
    fallbackCopy(text, successMsg);
  }
}
function fallbackCopy(text, successMsg){
  try{
    const ta=document.createElement('textarea');
    ta.value=text;
    ta.style.position='fixed'; ta.style.opacity='0';
    document.body.appendChild(ta);
    ta.focus(); ta.select();
    const ok=document.execCommand('copy');
    document.body.removeChild(ta);
    if(ok) showToast(successMsg,'ok');
    else showToast('No se pudo copiar. Cópialo manualmente.','error');
  }catch(e){
    showToast('No se pudo copiar. Cópialo manualmente.','error');
  }
}
const PAGES = {
  privacy:{title:'Política de Privacidad',meta:'Última actualización: 1 de junio de 2025',html:`
    <div class="pm-hl">Cumple con el RGPD (UE 2016/679) y la LOPDGDD (LO 3/2018).</div>
    <h2>1. Responsable del tratamiento</h2><p><strong>WebScan</strong> — contacto: <a href="mailto:molinocatenad@gmail.com">molinocatenad@gmail.com</a></p>
    <h2>2. Datos que recogemos</h2><ul><li><strong>Datos de uso:</strong> URLs analizadas, resultados, timestamps.</li><li><strong>Datos técnicos:</strong> IP (anonimizada en 24h), navegador, SO.</li><li><strong>Facturación:</strong> email y datos de pago procesados por Stripe. WebScan no almacena tarjetas.</li></ul>
    <h2>3. Base jurídica</h2><ul><li>Ejecución de contrato (art. 6.1.b RGPD)</li><li>Interés legítimo (art. 6.1.f RGPD)</li><li>Consentimiento (art. 6.1.a RGPD) para comunicaciones</li><li>Obligación legal (art. 6.1.c RGPD) para facturación</li></ul>
    <h2>4. Conservación</h2><p>Datos de análisis: 12 meses tras cancelación. Facturación: 5 años. IPs: anonimizadas en 24h.</p>
    <h2>5. Destinatarios</h2><table><tr><th>Proveedor</th><th>Finalidad</th><th>País</th><th>Garantía</th></tr><tr><td>Stripe</td><td>Pagos</td><td>EE.UU.</td><td>SCCs UE</td></tr><tr><td>Vercel</td><td>Hosting</td><td>EE.UU.</td><td>SCCs + DPA</td></tr><tr><td>VirusTotal</td><td>Análisis</td><td>EE.UU.</td><td>SCCs + DPA</td></tr></table>
    <h2>6. Tus derechos</h2><p>Acceso, rectificación, supresión, oposición, limitación, portabilidad y retirada del consentimiento. Escribe a <a href="mailto:molinocatenad@gmail.com">molinocatenad@gmail.com</a>. Reclamaciones ante la <a href="https://www.aepd.es" target="_blank" rel="noopener">AEPD</a>.</p>
    <h2>7. Seguridad</h2><p>Cifrado TLS en tránsito, acceso restringido por roles, auditorías periódicas y cabeceras de seguridad HTTP según estándares OWASP.</p>`},
  terms:{title:'Términos de uso',meta:'Versión 1.0 · 1 de junio de 2025',html:`
    <h2>1. Objeto</h2><p>Los presentes términos regulan el acceso y uso del servicio WebScan. El uso implica aceptación plena.</p>
    <h2>2. Servicio</h2><p>WebScan realiza análisis externos automatizados no invasivos de dominios web: SSL, cabeceras HTTP, DNS, reputación, cookies, CMS y rendimiento.</p>
    <div class="pm-warn">WebScan solo puede usarse sobre dominios con autorización expresa del propietario. El uso no autorizado puede ser constitutivo de delito informático (art. 197 bis CP).</div>
    <h2>3. Planes y facturación</h2><ul><li><strong>Free:</strong> 3 análisis/mes, sin PDF ni monitorización.</li><li><strong>Pro (50€/mes):</strong> ilimitados, PDF, SaaS, monitorización semanal, 10 dominios.</li><li><strong>Agencia (100€/mes):</strong> todo lo de Pro + white-label, dominios ilimitados, API.</li></ul><p>Pagos vía Stripe. Renovación automática mensual. Cancelación en cualquier momento. Sin reembolsos parciales.</p>
    <h2>4. Uso aceptable</h2><p>Prohibido: analizar dominios sin autorización, ataques DoS, reventa sin acuerdo, elusión de límites técnicos, actividades ilegales.</p>
    <h2>5. Limitación de responsabilidad</h2><p>Los resultados son orientativos y no constituyen auditoría certificada. WebScan no garantiza la detección del 100% de vulnerabilidades.</p>
    <h2>6. Ley aplicable</h2><p>Legislación española. Juzgados y Tribunales de Madrid.</p>`},
  cookies:{title:'Política de Cookies',meta:'1 de junio de 2025',html:`
    <p>Conforme a la Directiva 2002/58/CE y la LOPDGDD.</p>
    <h2>Cookies utilizadas</h2>
    <table><tr><th>Cookie</th><th>Tipo</th><th>Finalidad</th><th>Duración</th></tr>
    <tr><td>ws_v2</td><td>Técnica (localStorage)</td><td>Plan activo y contador de análisis</td><td>Hasta borrado manual</td></tr>
    <tr><td>ws_cookies_accepted</td><td>Técnica (localStorage)</td><td>Recordar aceptación del banner</td><td>Hasta borrado manual</td></tr>
    <tr><td>_stripe_sid / _stripe_mid</td><td>Técnica (Stripe)</td><td>Seguridad en pagos</td><td>Sesión / 1 año</td></tr></table>
    <div class="pm-hl">WebScan <strong>no usa cookies publicitarias ni de seguimiento</strong>.</div>
    <h2>Gestión</h2><p>Puedes eliminar cookies desde la configuración de tu navegador (<a href="https://support.google.com/chrome/answer/95647" target="_blank" rel="noopener">Chrome</a>, <a href="https://support.mozilla.org/es/kb/habilitar-y-deshabilitar-cookies" target="_blank" rel="noopener">Firefox</a>, <a href="https://support.apple.com/es-es/guide/safari/sfri11471" target="_blank" rel="noopener">Safari</a>).</p>`},
  gdpr:{title:'Información RGPD',meta:'Reglamento UE 2016/679',html:`
    <div class="pm-hl">Tus derechos bajo el RGPD en relación con WebScan.</div>
    <h2>Responsable</h2><p>WebScan — DPO: <a href="mailto:molinocatenad@gmail.com">molinocatenad@gmail.com</a></p>
    <h2>Tus derechos</h2>
    <table><tr><th>Derecho</th><th>Descripción</th></tr>
    <tr><td>Acceso (art. 15)</td><td>Copia de tus datos tratados</td></tr>
    <tr><td>Rectificación (art. 16)</td><td>Corregir datos inexactos</td></tr>
    <tr><td>Supresión (art. 17)</td><td>Eliminar tus datos</td></tr>
    <tr><td>Limitación (art. 18)</td><td>Limitar el tratamiento</td></tr>
    <tr><td>Portabilidad (art. 20)</td><td>Datos en formato estructurado</td></tr>
    <tr><td>Oposición (art. 21)</td><td>Oponerte al tratamiento</td></tr></table>
    <p>Plazo de respuesta: <strong>30 días</strong>. Reclamaciones: <a href="https://www.aepd.es" target="_blank" rel="noopener">AEPD</a> · <a href="https://sedeagpd.gob.es" target="_blank" rel="noopener">sedeagpd.gob.es</a></p>`},
  about:{title:'Sobre nosotros',meta:'WebScan · Seguridad web accesible',html:`
    <p>WebScan nació de una pregunta sencilla: <em>¿por qué las herramientas de seguridad web profesionales son tan complejas y caras que solo las grandes empresas pueden permitírselas?</em></p>
    <h2>Misión</h2><p>Democratizar la auditoría de seguridad web. Cualquier negocio online merece saber si su web es segura, sin contratar un equipo de ciberseguridad.</p>
    <h2>Lo que hacemos diferente</h2><ul><li><strong>45 comprobaciones en menos de 20 segundos</strong> — incluyendo cookies, CMS, contenido mixto y severidad de cada problema.</li><li><strong>Soluciones incluidas</strong> — cada problema viene con su guía de solución paso a paso.</li><li><strong>SaaS completo</strong> — panel de gestión, historial, monitorización automática y alertas.</li><li><strong>Precio justo</strong> — desde 0€. Sin sorpresas.</li></ul>
    <h2>Contacto</h2><p><a href="mailto:molinocatenad@gmail.com">molinocatenad@gmail.com</a></p>`},
  contact:{title:'Contacto',meta:'Te respondemos en menos de 24 horas',html:`
    <p>Para soporte, facturación o colaboraciones. Respondemos en menos de 24h en días laborables.</p>
    <div class="pm-hl">Email: <strong><a href="mailto:molinocatenad@gmail.com">molinocatenad@gmail.com</a></strong></div>
    <h2>Envíanos un mensaje</h2>
    <form class="cf" onsubmit="submitContact(event)">
      <div class="cf-row">
        <div class="cf-field"><label class="cf-label" for="cf-name">Nombre *</label><input class="cf-input" id="cf-name" type="text" required autocomplete="name" maxlength="100"></div>
        <div class="cf-field"><label class="cf-label" for="cf-email">Email *</label><input class="cf-input" id="cf-email" type="email" required autocomplete="email" maxlength="200"></div>
      </div>
      <div class="cf-field"><label class="cf-label" for="cf-subject">Asunto *</label><input class="cf-input" id="cf-subject" type="text" required maxlength="200"></div>
      <div class="cf-field"><label class="cf-label" for="cf-msg">Mensaje *</label><textarea class="cf-textarea" id="cf-msg" required maxlength="2000"></textarea></div>
      <button class="cf-submit" type="submit">Enviar mensaje</button>
    </form>`},
  api:{title:'Documentación API',meta:'Plan Agencia · v1.0',html:`
    <div class="pm-warn">El acceso API requiere el Plan Agencia.</div>
    <h2>Autenticación</h2><pre style="background:var(--paper2);padding:12px;border-radius:8px;font-family:var(--mono);font-size:12px;overflow-x:auto;margin-bottom:16px">Authorization: Bearer wsk_live_xxxxxxxxxxxx</pre>
    <h2>POST /v1/scan</h2><pre style="background:var(--paper2);padding:12px;border-radius:8px;font-family:var(--mono);font-size:12px;overflow-x:auto;margin-bottom:16px">{"url":"https://ejemplo.com","notify_email":"tu@email.com"}</pre>
    <h2>GET /v1/scan/{id}</h2><pre style="background:var(--paper2);padding:12px;border-radius:8px;font-family:var(--mono);font-size:12px;overflow-x:auto;margin-bottom:16px">{"id":"scan_abc","domain":"ejemplo.com","score":87,"grade":"B","passed":38,"failed":7,"categories":{...}}</pre>
    <p>Contacto para acceso completo: <a href="mailto:molinocatenad@gmail.com">molinocatenad@gmail.com</a></p>`}
};

function openPage(key){
  const page=PAGES[key]; if(!page) return;
  document.getElementById('page-content').innerHTML=`<div class="pm"><h1>${page.title}</h1><div class="pm-meta">${page.meta}</div>${page.html}</div>`;
  document.getElementById('page-overlay').classList.add('show');
  document.getElementById('page-box').scrollTop=0;
  document.body.style.overflow='hidden';
}
function closePage(){ document.getElementById('page-overlay').classList.remove('show'); document.body.style.overflow=''; }
function submitContact(e){
  e.preventDefault();
  const name=document.getElementById('cf-name').value.trim();
  const email=document.getElementById('cf-email').value.trim();
  const subject=document.getElementById('cf-subject').value.trim();
  const msg=document.getElementById('cf-msg').value.trim();

  if(!name||!email||!subject||!msg){
    showToast('Completa todos los campos','error');
    return;
  }

  const body = `Nombre: ${name}\nEmail: ${email}\n\n${msg}`;
  const mailto = `mailto:molinocatenad@gmail.com?subject=${encodeURIComponent('[WebScan] '+subject)}&body=${encodeURIComponent(body)}`;

  // Abrimos el cliente de correo del usuario con todo precompletado
  window.location.href = mailto;
  showToast(`Abriendo tu cliente de email para enviar el mensaje, ${escapeHTML(name.split(' ')[0])}…`,'ok');
  closePage();
}
let toastTimer;
function showToast(msg,type){
  const t=document.getElementById('toast'), m=document.getElementById('toast-msg');
  clearTimeout(toastTimer);
  const icon=type==='ok'?'<polyline points="20 6 9 17 4 12" stroke-width="2.5" stroke-linecap="round" stroke="currentColor" fill="none"/>'
    :'<circle cx="12" cy="12" r="10" stroke-width="2" stroke="currentColor" fill="none"/><line x1="12" y1="8" x2="12" y2="12" stroke="currentColor" stroke-width="2"/><line x1="12" y1="16" x2="12.01" y2="16" stroke="currentColor" stroke-width="2"/>';
  t.querySelector('svg').innerHTML=icon;
  m.textContent=msg;
  requestAnimationFrame(()=>t.classList.add('show'));
  toastTimer=setTimeout(()=>t.classList.remove('show'),3500);
}

function acceptCookies(){
  try{ localStorage.setItem('ws_cookies_accepted','1'); }catch(e){}
  const banner = document.getElementById('cookie-banner');
  if(banner){ banner.style.transform='translateY(100%)'; banner.style.pointerEvents='none'; }
}
(function initBanner(){
  try{
    if(!localStorage.getItem('ws_cookies_accepted')){
      setTimeout(()=>{
        const b=document.getElementById('cookie-banner');
        if(b){ b.style.transform='translateY(0)'; b.style.pointerEvents='auto'; }
      },1400);
    }
  }catch(e){}
})();

document.addEventListener('click', e => {
  if(e.target.classList.contains('cr-fix')) toggleFix(e.target);
});

document.addEventListener('keydown',e=>{
  if(e.key==='Escape'){closeModal();closePage();}
  if((e.key==='Enter'||e.key===' ')&&e.target.classList.contains('rs-header')){e.preventDefault();toggleSec(e.target);}
});
['url-input','url-input2'].forEach(id=>{
  document.getElementById(id)?.addEventListener('keydown',e=>{
    if(e.key==='Enter') startScan(id,id==='url-input'?'results-hero':'results');
  });
});
document.getElementById('activation-code')?.addEventListener('keydown',e=>{
  if(e.key==='Enter'){ e.preventDefault(); activateCode(); }
});

window.addEventListener('load',()=>{
  const ring=document.getElementById('hero-ring');
  if(ring) setTimeout(()=>{ring.style.transition='stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1)';ring.style.strokeDashoffset=String(176*(1-0.91));},400);
  const chart=document.getElementById('mini-chart');
  if(chart){const scores=[62,65,68,64,71,75,73,78,76,82,79,84,81,86,88,87,89,88,91,90,92,89,93,91,94,92,95,93,94,96];
    scores.forEach((v,i)=>{const b=document.createElement('div');b.className='chart-bar'+(i===scores.length-1?' active':'');b.style.height=(v/100*36)+'px';chart.appendChild(b);});
  }
  const params=new URLSearchParams(location.search);
  if(params.get('url')){const el=document.getElementById('url-input2');if(el){el.value=params.get('url');setTimeout(()=>startScan('url-input2','results'),800);}}
  renderPlanUI();
});
