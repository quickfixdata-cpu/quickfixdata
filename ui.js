// Minimal UI bootstrap for premium visual touches
// - Headline reveal
// - Cursor follower
// - Interactive demo stage runner (non-invasive)
(function(){
  function ready(fn){ if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', fn); else fn(); }

  ready(() => {
    // Headline reveal: split main h1 into spans for stagger
    const h1 = document.querySelector('.hero h1');
    if (h1){
      const text = h1.textContent.trim();
      h1.classList.add('headline-gradient','headline-glow');
      const words = text.split(/\s+/).slice(0,8);
      h1.innerHTML = '<span class="reveal-words">'+ words.map(w=>`<span>${w}</span>`).join(' ')+ (text.split(/\s+/).slice(8).length? ' ' + text.split(/\s+/).slice(8).join(' ') : '') + '</span>';
      // animate after short delay
      setTimeout(()=>{ const rw = h1.querySelector('.reveal-words'); if (rw) rw.classList.add('animate'); }, 420);
    }

    // Cursor follower (desktop only)
    if (!window.matchMedia('(pointer: coarse)').matches && !window.matchMedia('(prefers-reduced-motion: reduce)').matches){
      const follower = document.createElement('div'); follower.className = 'cursor-follower'; follower.innerHTML = '<div class="dot"></div>';
      document.body.appendChild(follower);
      const dot = follower.querySelector('.dot');
      let mouseX = window.innerWidth/2, mouseY = window.innerHeight/2, posX = mouseX, posY = mouseY;
      window.addEventListener('mousemove', (e)=>{ mouseX = e.clientX; mouseY = e.clientY; follower.style.display = 'block'; });
      function loop(){ posX += (mouseX - posX) * 0.08; posY += (mouseY - posY) * 0.08; follower.style.transform = `translate(${posX}px, ${posY}px)`; requestAnimationFrame(loop); }
      requestAnimationFrame(loop);
    }

    // Non-invasive interactive demo: if there's a .demo-run element, animate stage changes
    const demo = document.querySelector('.demo-run');
    if (demo){
      const stages = demo.querySelectorAll('[data-stage]');
      let idx = 0;
      function nextStage(){ stages.forEach((s,i)=> s.style.opacity = i===idx?1:0.18 ); idx = (idx+1) % stages.length; }
      // initial
      stages.forEach((s,i)=> s.style.transition = 'opacity .5s var(--motion-ease)');
      setInterval(nextStage, 2400);
    }
  });
})();
