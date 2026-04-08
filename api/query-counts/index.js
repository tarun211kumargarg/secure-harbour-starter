const { getContainer } = require('../shared/cosmos');
const { requireOwner } = require('../shared/auth');

async function getCount(container, status) {
  const query = status
    ? {
        query: 'SELECT VALUE COUNT(1) FROM c WHERE c.status = @status',
        parameters: [{ name: '@status', value: status }]
      }
    : 'SELECT VALUE COUNT(1) FROM c';

  const { resources } = await container.items.query(query).fetchAll();
  return resources[0] || 0;
}

module.exports = async function (context, req) {
  const auth = requireOwner(req);
  if (auth.response) return auth.response;
  const principal = auth.principal;

  try {
    const container = getContainer();
    const [total, fresh, inProgress, closed] = await Promise.all([
      getCount(container),
      getCount(container, 'New'),
      getCount(container, 'In Progress'),
      getCount(container, 'Closed')
    ]);

    return {
      status: 200,
      body: {
        total,
        New: fresh,
        InProgress: inProgress,
        Closed: closed
      }
    };
  } catch (error) {
    context.log.error(error);
    return {
      status: 500,
      body: { error: 'Unable to load query counts.' }
    };
  }
};
