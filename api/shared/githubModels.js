const https = require('https');

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
      'AI scanner is not configured. Add GITHUB_MODELS_TOKEN to Azure Static Web App Environment variables for Production. The token must have GitHub Models access with Models: Read.',
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
  return status >= 500 ? 502 : 502;
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

function redactUpstreamText(text) {
  return String(text || '')
    .replace(/gh[pousr]_[0-9A-Za-z_]{20,}/g, 'gh*_****************')
    .replace(/Bearer\s+[A-Za-z0-9._-]+/gi, 'Bearer [REDACTED]')
    .slice(0, 500);
}

async function postJson(url, headers, body) {
  if (typeof fetch === 'function') {
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body)
    });
    const text = await response.text();
    return { ok: response.ok, status: response.status, text };
  }

  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const payload = JSON.stringify(body);
    const request = https.request({
      hostname: parsed.hostname,
      path: `${parsed.pathname}${parsed.search}`,
      method: 'POST',
      headers: {
        ...headers,
        'Content-Length': Buffer.byteLength(payload)
      },
      timeout: 30000
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({ ok: response.statusCode >= 200 && response.statusCode < 300, status: response.statusCode, text });
      });
    });

    request.on('timeout', () => {
      request.destroy(new Error('GitHub Models request timed out.'));
    });
    request.on('error', reject);
    request.write(payload);
    request.end();
  });
}

async function requestGitHubModels(body) {
  const token = getGitHubModelsToken();
  const result = await postJson(GITHUB_MODELS_ENDPOINT, {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${token}`,
    'Content-Type': 'application/json',
    'X-GitHub-Api-Version': '2022-11-28'
  }, body);

  if (!result.ok) {
    const detail = result.text ? ` ${redactUpstreamText(result.text)}` : '';
    throw new GitHubModelsError(
      `GitHub Models request failed with status ${result.status}.${detail}`.trim(),
      errorStatusForGitHubModels(result.status),
      result.status
    );
  }

  try {
    return JSON.parse(result.text || '{}');
  } catch (error) {
    throw new GitHubModelsError('GitHub Models returned a non-JSON response.', 502, result.status);
  }
}

async function createGitHubModelsChatCompletion(options) {
  const body = buildRequestBody(options);

  try {
    return await requestGitHubModels(body);
  } catch (error) {
    // Some models reject JSON mode. Retry once without response_format.
    if (body.response_format && error instanceof GitHubModelsError && [400, 404, 422].includes(error.upstreamStatus)) {
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
