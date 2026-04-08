const { getContainer } = require('../shared/cosmos');
const { requireOwner } = require('../shared/auth');
const { ALLOWED_STATUSES, normalizeString } = require('../shared/validation');

module.exports = async function (context, req) {
  const auth = requireOwner(req);
  if (auth.response) return auth.response;
  const principal = auth.principal;

  try {
    const id = normalizeString(req.body && req.body.id, 80);
    const status = normalizeString(req.body && req.body.status, 40);
    const ownerNotes = normalizeString(req.body && req.body.ownerNotes, 2500);

    if (!id) {
      return {
        status: 400,
        body: { error: 'Query id is required.' }
      };
    }

    if (!ALLOWED_STATUSES.includes(status)) {
      return {
        status: 400,
        body: { error: 'Invalid status.' }
      };
    }

    const container = getContainer();
    const { resource } = await container.item(id, id).read();

    if (!resource) {
      return {
        status: 404,
        body: { error: 'Query not found.' }
      };
    }

    resource.status = status;
    resource.ownerNotes = ownerNotes;
    resource.updatedAt = new Date().toISOString();
    resource.updatedBy = principal.userDetails || principal.identityProvider || 'owner';

    await container.items.upsert(resource);

    return {
      status: 200,
      body: { success: true, item: resource }
    };
  } catch (error) {
    context.log.error(error);
    return {
      status: 500,
      body: { error: 'Unable to update the query.' }
    };
  }
};
