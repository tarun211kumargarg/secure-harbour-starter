const { getGitHubModelsModel } = require('../shared/githubModels');

module.exports = async function () {
  return {
    status: 200,
    body: {
      ok: true,
      repoScanApi: true,
      hasGitHubModelsToken: Boolean(process.env.GITHUB_MODELS_TOKEN || process.env.GITHUB_TOKEN || process.env.SCAN_GITHUB_TOKEN),
      configuredTokenName: process.env.GITHUB_MODELS_TOKEN
        ? 'GITHUB_MODELS_TOKEN'
        : process.env.GITHUB_TOKEN
          ? 'GITHUB_TOKEN'
          : process.env.SCAN_GITHUB_TOKEN
            ? 'SCAN_GITHUB_TOKEN'
            : null,
      model: getGitHubModelsModel(),
      hasFetch: typeof fetch === 'function',
      nodeVersion: process.version,
      timestamp: new Date().toISOString()
    }
  };
};
