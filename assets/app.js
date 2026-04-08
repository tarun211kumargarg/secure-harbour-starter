function setActiveNav() {
  const path = window.location.pathname.replace(/\/$/, '') || '/';
  document.querySelectorAll('[data-nav]').forEach((link) => {
    const target = link.getAttribute('href');
    if ((target === '/' && path === '/') || (target !== '/' && path === target)) {
      link.classList.add('active');
    }
  });
}

function setYear() {
  document.querySelectorAll('[data-year]').forEach((node) => {
    node.textContent = new Date().getFullYear();
  });
}

function applyServicePrefill() {
  const serviceField = document.querySelector('[data-service-select]');
  if (!serviceField) return;
  const service = new URLSearchParams(window.location.search).get('service');
  if (!service) return;
  serviceField.value = service;
}

setActiveNav();
setYear();
applyServicePrefill();
