document.addEventListener('DOMContentLoaded', () => {
  const headline = document.querySelector('.hero-copy h1');
  if (headline) {
    const text = headline.textContent.trim();
    const words = text.split(' ');
    headline.textContent = '';
    words.forEach((word, index) => {
      const span = document.createElement('span');
      span.textContent = `${word} `;
      span.style.opacity = '0';
      span.style.display = 'inline-block';
      span.style.transform = 'translateY(18px)';
      span.style.transition = `opacity var(--motion-medium) var(--ease) ${index * 60}ms, transform var(--motion-medium) var(--ease) ${index * 60}ms`;
      headline.appendChild(span);
      requestAnimationFrame(() => {
        span.style.opacity = '1';
        span.style.transform = 'translateY(0)';
      });
    });
  }

  const cursorLight = document.createElement('div');
  cursorLight.className = 'cursor-light';
  document.body.appendChild(cursorLight);

  if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    cursorLight.style.display = 'none';
  }

  document.addEventListener('mousemove', (event) => {
    cursorLight.style.transform = `translate3d(${event.clientX}px, ${event.clientY}px, 0)`;
  });
});
