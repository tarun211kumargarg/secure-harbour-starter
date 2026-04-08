const { CosmosClient } = require('@azure/cosmos');

let containerInstance;

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required setting: ${name}`);
  }
  return value;
}

function getContainer() {
  if (containerInstance) {
    return containerInstance;
  }

  const endpoint = requireEnv('COSMOS_ENDPOINT');
  const key = requireEnv('COSMOS_KEY');
  const databaseId = requireEnv('COSMOS_DATABASE_NAME');
  const containerId = requireEnv('COSMOS_CONTAINER_NAME');

  const client = new CosmosClient({ endpoint, key });
  const database = client.database(databaseId);
  containerInstance = database.container(containerId);
  return containerInstance;
}

module.exports = {
  getContainer
};
