const { getContainer } = require('../shared/cosmos');
const { requireOwner } = require('../shared/auth');
const { ALLOWED_SERVICES, ALLOWED_STATUSES, normalizeString } = require('../shared/validation');

module.exports = async function (context, req) {
  const auth = requireOwner(req);
  if (auth.response) return auth.response;
  const principal = auth.principal;

  try {
    const search = normalizeString((req.query && req.query.search) || '', 120).toLowerCase();
    const status = normalizeString((req.query && req.query.status) || '', 40);
    const service = normalizeString((req.query && req.query.service) || '', 80);

    if (status && !ALLOWED_STATUSES.includes(status)) {
      return {
        status: 400,
        body: { error: 'Invalid status filter.' }
      };
    }

    if (service && !ALLOWED_SERVICES.includes(service)) {
      return {
        status: 400,
        body: { error: 'Invalid service filter.' }
      };
    }

    const container = getContainer();
    const querySpec = {
      query: `
        SELECT * FROM c
        WHERE (@status = '' OR c.status = @status)
          AND (@service = '' OR c.serviceInterestedIn = @service)
          AND (
            @search = ''
            OR CONTAINS(LOWER(c.name), @search)
            OR CONTAINS(LOWER(c.company), @search)
            OR CONTAINS(LOWER(c.email), @search)
            OR CONTAINS(LOWER(c.message), @search)
            OR (IS_DEFINED(c.repo.fullName) AND CONTAINS(LOWER(c.repo.fullName), @search))
            OR (IS_DEFINED(c.repo.url) AND CONTAINS(LOWER(c.repo.url), @search))
            OR (IS_DEFINED(c.scanSummary.riskLevel) AND CONTAINS(LOWER(c.scanSummary.riskLevel), @search))
          )
        ORDER BY c.createdAt DESC
      `,
      parameters: [
        { name: '@status', value: status },
        { name: '@service', value: service },
        { name: '@search', value: search }
      ]
    };

    const { resources } = await container.items.query(querySpec).fetchAll();
    return {
      status: 200,
      body: resources
    };
  } catch (error) {
    context.log.error(error);
    return {
      status: 500,
      body: { error: 'Unable to load queries.' }
    };
  }
};
