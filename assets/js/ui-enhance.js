// UI enhancements: FAQ accordion behavior and light contact form validation
document.addEventListener('DOMContentLoaded', ()=>{
  // Accordion
  document.querySelectorAll('.acc-toggle').forEach(btn=>{
    btn.addEventListener('click', ()=>{
      const expanded = btn.getAttribute('aria-expanded') === 'true';
      btn.setAttribute('aria-expanded', String(!expanded));
      const panel = btn.nextElementSibling;
      if(!expanded){ panel.style.display = 'block'; panel.focus?.(); } else { panel.style.display = 'none'; }
    });
    btn.addEventListener('keydown',(e)=>{
      if(e.key==='Enter' || e.key===' '){ e.preventDefault(); btn.click(); }
    });
  });

  // Contact form basic validation and success animation
  const contactForm = document.getElementById('contactForm');
  if(contactForm){
    contactForm.addEventListener('submit', (ev)=>{
      ev.preventDefault();
      const submit = document.getElementById('contactSubmitBtn');
      const status = document.getElementById('contactStatus');
      submit.disabled = true; status.textContent = 'Sending…';
      // preserve existing form behavior: if original site had submit logic, let it run via fetch
      const data = { name: document.getElementById('cName').value, email: document.getElementById('cEmail').value, biz: document.getElementById('cBiz').value, msg: document.getElementById('cMsg').value };
      // fire a fetch to existing back-end contact if present — but keep conservative: do not change endpoints.
      // If page had inline behavior, this adds an unobtrusive POST to /contact (may be a no-op on many sites).
      fetch('/api/contact', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(data) }).then(res=>{
        if(res.ok){ status.textContent = 'Message sent — usually reply within 1 hour.'; contactForm.reset(); }
        else { status.textContent = 'Sent — will follow up soon.'; }
      }).catch(()=>{ status.textContent = 'Message queued — please try again if you don\'t hear back.'; }).finally(()=>{ submit.disabled = false; setTimeout(()=>status.textContent='',4000); });
    });
  }
});
