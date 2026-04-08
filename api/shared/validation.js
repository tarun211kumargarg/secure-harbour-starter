const ALLOWED_STATUSES = ['New', 'In Progress', 'Closed'];
const ALLOWED_SERVICES = [
  'AI Security',
  'Penetration Testing',
  'Red Teaming',
  'Vulnerability Assessment',
  'Security Consulting'
];

function normalizeString(value, maxLength = 2500) {
  return String(value || '').trim().replace(/\s+/g, ' ').slice(0, maxLength);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function sanitizePayload(payload) {
  return {
    name: normalizeString(payload.name, 120),
    company: normalizeString(payload.company, 120),
    email: normalizeString(payload.email, 180).toLowerCase(),
    phone: normalizeString(payload.phone, 30),
    serviceInterestedIn: normalizeString(payload.serviceInterestedIn, 80),
    message: normalizeString(payload.message, 2500),
    website: normalizeString(payload.website, 120)
  };
}

module.exports = {
  ALLOWED_STATUSES,
  ALLOWED_SERVICES,
  normalizeString,
  isValidEmail,
  sanitizePayload
};
