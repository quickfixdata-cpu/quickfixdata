(function(){
  // Lightweight interactive demo for the pipeline
  const STAGES = [
    {id:'upload', label:'CSV Upload', duration:900, info:'File accepted: 3 rows, 5 columns.'},
    {id:'ai', label:'AI Processing', duration:1400, info:'Detecting columns, types, and anomalies.'},
    {id:'validate', label:'Validation', duration:1100, info:'Found formatting issues in dates and amounts.'},
    {id:'clean', label:'Cleaning', duration:1200, info:'Trimmed whitespace, fixed cases and formats.'},
    {id:'dups', label:'Duplicate Detection', duration:900, info:'2 duplicate rows found and collapsed.'},
    {id:'summary', label:'Summarize', duration:800, info:'Ready — 2 invoices, 1 reminder suggested.'},
    {id:'export', label:'Export', duration:700, info:'Download ready: CSV, XLSX, or JSON.'}
  ];

  const el = {
    steps: null, fill: null, stage: null, percent: null,
    insight: null, rows: null, errors: null, dups: null,
    before: null, after: null, handle: null, startBtn: null, resetBtn: null
  };

  function $(id){ return document.getElementById(id); }

  function buildSteps(){
    const container = $('pipelineSteps');
    container.innerHTML = '';
    STAGES.forEach((s, idx)=>{
      const div = document.createElement('div');
      div.className = 'pipeline-step';
      div.id = `step-${s.id}`;
      div.innerHTML = `<div class="step-bullet" aria-hidden="true"></div><div><strong>${s.label}</strong><div style="font-size:0.86rem;color:var(--text-secondary);">${s.info}</div></div>`;
      container.appendChild(div);
    });
  }

  function updateCounters(rows, fixes, dups){
    el.rows.textContent = rows;
    el.errors.textContent = fixes;
    el.dups.textContent = dups;
  }

  function animatePipeline(){
    let total = STAGES.reduce((acc,s)=>acc+s.duration,0);
    let elapsed = 0;
    let cumulative=0;
    STAGES.forEach((s, idx)=> cumulative+=s.duration);

    const runStage = (i) => {
      if(i>=STAGES.length) return finish();
      const s = STAGES[i];
      // activate
      const node = $('step-'+s.id);
      node.classList.add('active');
      el.stage.textContent = s.label;
      const start = performance.now();
      const duration = s.duration;
      const stepTick = (t)=>{
        const p = Math.min(1, (t-start)/duration);
        const percent = Math.round(((elapsed + (p*duration)) / total) * 100);
        el.fill.style.width = percent + '%';
        el.percent.textContent = percent + '%';
        if(p < 1){ requestAnimationFrame(stepTick); } else {
          // stage done
          elapsed += duration;
          // update counters / insights at certain stages
          if(s.id==='upload'){ updateCounters(103,0,0); el.insight.textContent = 'Scanning file: 103 rows, sample data looks unstructured.'; }
          if(s.id==='ai'){ updateCounters(103,12,0); el.insight.textContent = 'AI detected name,email,amount,due,paid — amounts inconsistent; dates ambiguous.'; }
          if(s.id==='validate'){ updateCounters(103,8,0); el.insight.textContent = 'Validation: 8 fixes to amounts/dates suggested.'; }
          if(s.id==='clean'){ updateCounters(103,8,2); el.insight.textContent = 'Cleaning applied: trimmed, normalized currency and dates.'; renderAfterSample(); }
          if(s.id==='dups'){ updateCounters(101,8,2); el.insight.textContent = 'Duplicates detected: 2 similar rows collapsed into one.'; renderAfterSample(); }
          if(s.id==='summary'){ el.insight.textContent = 'Summary: 2 invoices ready, 1 reminder draft. Preview generated.'; }
          if(s.id==='export'){ el.insight.textContent = 'Export available: CSV & Excel.'; }
          // proceed next
          setTimeout(()=>{ node.classList.remove('active'); runStage(i+1); }, 250);
        }
      };
      requestAnimationFrame(stepTick);
    };
    runStage(0);
  }

  function finish(){
    el.stage.textContent = 'Complete';
    el.percent.textContent = '100%';
    el.fill.style.width = '100%';
  }

  function renderAfterSample(){
    const before = $('beforeSample').textContent;
    // naive cleaning simulation
    const lines = before.split('\n').slice(1).map(l=>l.trim()).filter(Boolean);
    const table = [];
    lines.forEach((ln)=>{
      const cols = ln.split(',').map(c=>c.trim());
      // normalize
      const name = cols[0].replace(/\b(.)/g, (m)=>m.toUpperCase());
      const email = cols[1].toLowerCase();
      const amt = Number(cols[2].replace(/[^0-9.]/g,'')).toFixed(2);
      const due = cols[3].replace(/(\d{2})\/(\d{2})\/(\d{4})/,'$3-$2-$1');
      const paid = (/y(es)?/i.test(cols[4]||'') ? 'Yes' : 'No');
      table.push([name,email,amt,due,paid].join(','));
    });
    // remove duplicate rows by email+amount
    const seen = new Set();
    const dedup = table.filter(r=>{ const key=r.split(',')[1]+'|'+r.split(',')[2]; if(seen.has(key)) return false; seen.add(key); return true; });
    $('afterSample').textContent = 'Name,Email,Amount,Due Date,Paid\n' + dedup.join('\n');
  }

  function initSlider(){
    const ba = document.querySelector('.before-after-slider');
    const before = $('baBefore');
    const after = $('baAfter');
    const handle = $('baHandle');
    let percent = 50;
    function setPos(p){
      percent = Math.max(3, Math.min(97, p));
      before.style.width = `calc(${percent}% - 14px)`;
      after.style.marginLeft = `calc(${percent}% - 14px)`;
      handle.style.left = percent + '%';
      handle.setAttribute('aria-valuenow', Math.round(percent));
    }
    setPos(percent);
    let dragging = false;
    handle.addEventListener('pointerdown', (e)=>{ dragging=true; handle.setPointerCapture(e.pointerId); });
    window.addEventListener('pointerup', (e)=>{ if(dragging){ dragging=false; handle.releasePointerCapture(e.pointerId); } });
    window.addEventListener('pointermove', (e)=>{ if(!dragging) return; const rect = ba.getBoundingClientRect(); const p = ((e.clientX - rect.left)/rect.width)*100; setPos(p); });
    // keyboard
    handle.addEventListener('keydown', (ev)=>{
      if(ev.key==='ArrowLeft'){ setPos(percent-3); ev.preventDefault(); }
      if(ev.key==='ArrowRight'){ setPos(percent+3); ev.preventDefault(); }
    });
  }

  function attachControls(){
    el.startBtn.addEventListener('click', ()=>{ el.startBtn.disabled=true; el.resetBtn.disabled=false; animatePipeline(); });
    el.resetBtn.addEventListener('click', ()=>{ el.startBtn.disabled=false; el.resetBtn.disabled=true; el.fill.style.width='0%'; el.percent.textContent='0%'; el.stage.textContent='Waiting'; updateCounters('—','—','—'); $('afterSample').textContent=''; el.insight.textContent='Demo reset — press Start to run again.'; });
  }

  // lazy init when section visible
  function lazyInit(){
    const demo = document.getElementById('interactiveDemo');
    if(!demo) return;
    el.steps = $('pipelineSteps'); el.fill = $('progressFill'); el.stage = $('progressStage'); el.percent = $('progressPercent');
    el.insight = $('insightBody'); el.rows = $('countRows'); el.errors = $('countErrors'); el.dups = $('countDups');
    el.before = $('beforeSample'); el.after = $('afterSample'); el.handle = $('baHandle'); el.startBtn = $('demoStart'); el.resetBtn = $('demoReset');

    buildSteps(); updateCounters('—','—','—'); initSlider(); attachControls();
    // give some initial text
    el.insight.textContent = 'Ready to demonstrate: this staged demo simulates a real processing pipeline.';
  }

  // Intersection observer
  const target = document.getElementById('interactiveDemo');
  if(target && 'IntersectionObserver' in window){
    const obs = new IntersectionObserver((entries, o)=>{
      entries.forEach(en=>{
        if(en.isIntersecting){ lazyInit(); o.unobserve(target); }
      });
    }, {threshold:0.2});
    obs.observe(target);
  } else { document.addEventListener('DOMContentLoaded', lazyInit); }
})();
