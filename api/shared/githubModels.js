const GITHUB_MODELS_ENDPOINT = process.env.GITHUB_MODELS_ENDPOINT || 'https://models.github.ai/inference/chat/completions';
const DEFAULT_GITHUB_MODELS_MODEL = 'microsoft/phi-4-mini-instruct';

class GitHubModelsError extends Error {
  constructor(message, statusCode = 502, upstreamStatus = null) {
    super(message);
    this.name = 'GitHubModelsError';
    this.statusCode = statusCode;
    this.upstreamStatus = upstreamStatus;
  }
}

function normalizeNumber(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : fallback;
}

function getGitHubModelsToken({ required = true } = {}) {
  const token = String(
    process.env.GITHUB_MODELS_TOKEN ||
    process.env.GITHUB_TOKEN ||
    process.env.SCAN_GITHUB_TOKEN ||
    ''
  ).trim();

  if (!token && required) {
    throw new GitHubModelsError(
      'AI scanner is not configured. Add GITHUB_MODELS_TOKEN or GITHUB_TOKEN to the Azure Static Web App application settings. The token must have GitHub Models access with the models:read scope.',
      503
    );
  }

  return token;
}

function hasGitHubModelsToken() {
  return Boolean(getGitHubModelsToken({ required: false }));
}

function getGitHubModelsModel() {
  return String(
    process.env.GITHUB_MODELS_MODEL ||
    process.env.AI_SCAN_MODEL ||
    DEFAULT_GITHUB_MODELS_MODEL
  ).trim();
}

function errorStatusForGitHubModels(status) {
  if (status === 401 || status === 403) return 503;
  if (status === 408 || status === 409 || status === 422 || status === 429) return status;
  return status >= 500 ? 502 : 500;
}

function buildRequestBody({ messages, model, temperature, maxTokens, responseFormat }) {
  const body = {
    model: model || getGitHubModelsModel(),
    messages,
    temperature: typeof temperature === 'number' ? temperature : 0.2,
    max_tokens: normalizeNumber(maxTokens, 1000)
  };

  if (responseFormat) {
    body.response_format = responseFormat;
  }

  return body;
}

async function requestGitHubModels(body) {
  const token = getGitHubModelsToken();
  const response = await fetch(GITHUB_MODELS_ENDPOINT, {
    method: 'POST',
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      'X-GitHub-Api-Version': '2022-11-28'
    },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    const detail = text ? ` ${text.slice(0, 220)}` : '';
    throw new GitHubModelsError(
      `GitHub Models request failed with status ${response.status}.${detail}`.trim(),
      errorStatusForGitHubModels(response.status),
      response.status
    );
  }

  return response.json();
}

async function createGitHubModelsChatCompletion(options) {
  const body = buildRequestBody(options);

  try {
    return await requestGitHubModels(body);
  } catch (error) {
    // Some catalog models may not support JSON mode even though the endpoint supports it.
    // Retry once without response_format and still require the caller to parse/validate JSON.
    if (body.response_format && error instanceof GitHubModelsError && error.upstreamStatus === 422) {
      const retryBody = { ...body };
      delete retryBody.response_format;
      return requestGitHubModels(retryBody);
    }
    throw error;
  }
}

function extractMessageContent(result) {
  return result && result.choices && result.choices[0] && result.choices[0].message
    ? String(result.choices[0].message.content || '').trim()
    : '';
}

module.exports = {
  GitHubModelsError,
  createGitHubModelsChatCompletion,
  extractMessageContent,
  getGitHubModelsModel,
  getGitHubModelsToken,
  hasGitHubModelsToken
};
