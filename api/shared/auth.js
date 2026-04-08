function getHeader(req, name) {
  if (!req || !req.headers) return undefined;
  if (typeof req.headers.get === 'function') return req.headers.get(name);
  return req.headers[name] || req.headers[name.toLowerCase()];
}

function getClientPrincipal(req) {
  const header = getHeader(req, 'x-ms-client-principal');
  if (!header) return null;

  try {
    const decoded = Buffer.from(header, 'base64').toString('utf8');
    return JSON.parse(decoded);
  } catch (error) {
    return null;
  }
}

function getUserRoles(principal) {
  if (!principal) return [];
  if (Array.isArray(principal.userRoles)) return principal.userRoles;
  if (Array.isArray(principal.roles)) return principal.roles;
  return [];
}

function requireOwner(req) {
  const principal = getClientPrincipal(req);
  const roles = getUserRoles(principal);
  const isOwner = roles.includes('owner');

  if (!isOwner) {
    return {
      response: {
        status: 403,
        body: { error: 'Owner access is required.' }
      }
    };
  }

  return { principal };
}

module.exports = {
  getClientPrincipal,
  getUserRoles,
  requireOwner
};
