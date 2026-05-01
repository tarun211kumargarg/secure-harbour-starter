const DEFAULT_MAX_FILES = Number(process.env.SCAN_MAX_FILES || 40);
const DEFAULT_MAX_FILE_BYTES = Number(process.env.SCAN_MAX_FILE_BYTES || 120000);
const DEFAULT_MAX_TOTAL_CHARS = Number(process.env.SCAN_MAX_TOTAL_CHARS || 160000);

class PublicScanError extends Error {
  constructor(message, statusCode = 400) {
    super(message);
    this.name = 'PublicScanError';
    this.statusCode = statusCode;
  }
}

const TEXT_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.json', '.html', '.htm', '.css', '.scss', '.vue',
  '.py', '.java', '.kt', '.kts', '.go', '.rb', '.php', '.cs', '.cpp', '.c', '.h', '.hpp', '.rs',
  '.swift', '.scala', '.sh', '.bash', '.zsh', '.ps1', '.yml', '.yaml', '.toml', '.xml', '.properties',
  '.gradle', '.sql', '.env', '.ini', '.conf', '.config', '.tf', '.dockerfile'
]);

const PRIORITY_FILENAMES = new Set([
  'package.json', 'requirements.txt', 'pom.xml', 'build.gradle', 'build.gradle.kts', 'go.mod', 'go.sum',
  'gemfile', 'composer.json', 'pyproject.toml', 'pipfile', 'dockerfile', 'docker-compose.yml',
  'docker-compose.yaml', '.env', '.env.example', 'application.yml', 'application.yaml', 'settings.py'
]);

const SKIPPED_PATH_SEGMENTS = new Set([
  '.git', '.github', 'node_modules', 'vendor', 'dist', 'build', 'coverage', '.next', '.nuxt', '.vercel',
  '.cache', '__pycache__', '.terraform', 'target', 'bin', 'obj', '.idea', '.vscode', 'public', 'static'
]);

const SKIPPED_FILENAMES = new Set([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'composer.lock', 'gemfile.lock', 'poetry.lock',
  'go.sum', 'cargo.lock'
]);

function normalizeNumber(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : fallback;
}

function parseGitHubRepoUrl(repoUrl) {
  let parsed;
  try {
    parsed = new URL(String(repoUrl || '').trim());
  } catch (error) {
    throw new PublicScanError('Enter a valid public GitHub repository URL, for example https://github.com/owner/repo.');
  }

  if (parsed.protocol !== 'https:' || !['github.com', 'www.github.com'].includes(parsed.hostname.toLowerCase())) {
    throw new PublicScanError('Only public GitHub repository URLs are supported for this demo.');
  }

  const parts = parsed.pathname.split('/').filter(Boolean);
  if (parts.length < 2) {
    throw new PublicScanError('The GitHub URL must include both the owner and repository name.');
  }

  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/i, '');
  const safeName = /^[A-Za-z0-9_.-]+$/;

  if (!safeName.test(owner) || !safeName.test(repo)) {
    throw new PublicScanError('The repository owner or name contains unsupported characters.');
  }

  return {
    owner,
    repo,
    fullName: `${owner}/${repo}`,
    normalizedUrl: `https://github.com/${owner}/${repo}`
  };
}

function githubHeaders() {
  const headers = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'secure-harbour-source-scan-demo'
  };

  const token = process.env.SCAN_GITHUB_TOKEN || process.env.GITHUB_TOKEN || process.env.GITHUB_MODELS_TOKEN;
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  return headers;
}

async function fetchGitHubJson(url) {
  const response = await fetch(url, { headers: githubHeaders() });

  if (response.status === 404) {
    throw new PublicScanError('The repository was not found or is not publicly accessible.', 404);
  }

  if (response.status === 403 && response.headers.get('x-ratelimit-remaining') === '0') {
    throw new PublicScanError('GitHub API rate limit reached. Configure SCAN_GITHUB_TOKEN, GITHUB_TOKEN, or GITHUB_MODELS_TOKEN and try again later.', 429);
  }

  if (!response.ok) {
    const text = await response.text().catch(() => '');
    throw new PublicScanError(`GitHub returned ${response.status}. ${text.slice(0, 160)}`.trim(), 502);
  }

  return response.json();
}

function extname(path) {
  const lower = path.toLowerCase();
  if (lower.endsWith('dockerfile')) return '.dockerfile';
  const index = lower.lastIndexOf('.');
  return index >= 0 ? lower.slice(index) : '';
}

function basename(path) {
  return path.split('/').pop().toLowerCase();
}

function hasSkippedSegment(path) {
  return path.split('/').some((segment) => SKIPPED_PATH_SEGMENTS.has(segment.toLowerCase()));
}

function isCandidateFile(entry, maxFileBytes) {
  if (!entry || entry.type !== 'blob' || !entry.path) return false;
  const name = basename(entry.path);
  if (SKIPPED_FILENAMES.has(name)) return false;
  if (hasSkippedSegment(entry.path)) return false;
  if (entry.size && entry.size > maxFileBytes) return false;
  return TEXT_EXTENSIONS.has(extname(entry.path)) || PRIORITY_FILENAMES.has(name);
}

function priorityScore(entry) {
  const path = entry.path.toLowerCase();
  const name = basename(path);
  let score = 0;
  if (PRIORITY_FILENAMES.has(name)) score -= 100;
  if (/\b(src|app|server|api|routes|controllers|auth|security|config)\b/.test(path)) score -= 40;
  if (/\b(test|tests|spec|docs|examples|fixtures)\b/.test(path)) score += 35;
  if (entry.size) score += Math.min(entry.size / 10000, 20);
  return score;
}

function isProbablyText(buffer) {
  if (!buffer || !buffer.length) return true;
  const sample = buffer.subarray(0, Math.min(buffer.length, 4096));
  let suspicious = 0;
  for (const byte of sample) {
    if (byte === 0) return false;
    if (byte < 7 || (byte > 14 && byte < 32)) suspicious += 1;
  }
  return suspicious / sample.length < 0.02;
}

async function fetchBlobText(owner, repo, sha, maxFileBytes) {
  const url = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/blobs/${encodeURIComponent(sha)}`;
  const blob = await fetchGitHubJson(url);

  if (blob.size && blob.size > maxFileBytes) {
    return null;
  }

  if (blob.encoding !== 'base64' || !blob.content) {
    return null;
  }

  const buffer = Buffer.from(blob.content.replace(/\n/g, ''), 'base64');
  if (buffer.length > maxFileBytes || !isProbablyText(buffer)) {
    return null;
  }

  return buffer.toString('utf8');
}

async function collectRepositoryFiles(repoUrl, options = {}) {
  const maxFiles = normalizeNumber(options.maxFiles || process.env.SCAN_MAX_FILES, DEFAULT_MAX_FILES);
  const maxFileBytes = normalizeNumber(options.maxFileBytes || process.env.SCAN_MAX_FILE_BYTES, DEFAULT_MAX_FILE_BYTES);
  const maxTotalChars = normalizeNumber(options.maxTotalChars || process.env.SCAN_MAX_TOTAL_CHARS, DEFAULT_MAX_TOTAL_CHARS);
  const parsed = parseGitHubRepoUrl(repoUrl);

  const repoApiUrl = `https://api.github.com/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}`;
  const repository = await fetchGitHubJson(repoApiUrl);

  if (repository.private) {
    throw new PublicScanError('Only public repositories are supported for this demo.', 400);
  }

  const defaultBranch = repository.default_branch || 'main';
  const treeUrl = `https://api.github.com/repos/${encodeURIComponent(parsed.owner)}/${encodeURIComponent(parsed.repo)}/git/trees/${encodeURIComponent(defaultBranch)}?recursive=1`;
  const tree = await fetchGitHubJson(treeUrl);

  if (!Array.isArray(tree.tree)) {
    throw new PublicScanError('Unable to read the repository file tree from GitHub.', 502);
  }

  const candidates = tree.tree
    .filter((entry) => isCandidateFile(entry, maxFileBytes))
    .sort((a, b) => priorityScore(a) - priorityScore(b) || a.path.localeCompare(b.path));

  const selected = candidates.slice(0, maxFiles);
  const files = [];
  let totalChars = 0;

  for (const entry of selected) {
    if (totalChars >= maxTotalChars) break;

    const content = await fetchBlobText(parsed.owner, parsed.repo, entry.sha, maxFileBytes).catch(() => null);
    if (!content) continue;

    const remaining = Math.max(0, maxTotalChars - totalChars);
    const trimmed = content.slice(0, remaining);
    totalChars += trimmed.length;

    files.push({
      path: entry.path,
      size: entry.size || Buffer.byteLength(trimmed),
      sha: entry.sha,
      content: trimmed
    });
  }

  if (!files.length) {
    throw new PublicScanError('No supported source files were found within the demo scan limits.', 422);
  }

  return {
    repository: {
      owner: parsed.owner,
      name: parsed.repo,
      fullName: parsed.fullName,
      url: parsed.normalizedUrl,
      description: repository.description || '',
      defaultBranch,
      language: repository.language || '',
      stars: repository.stargazers_count || 0,
      forks: repository.forks_count || 0,
      pushedAt: repository.pushed_at || null
    },
    limits: {
      maxFiles,
      maxFileBytes,
      maxTotalChars
    },
    tree: {
      truncated: Boolean(tree.truncated),
      totalEntries: tree.tree.length,
      candidateFiles: candidates.length,
      selectedFiles: selected.length,
      analyzedFiles: files.length,
      skippedCandidateFiles: Math.max(0, candidates.length - selected.length)
    },
    files
  };
}

module.exports = {
  PublicScanError,
  collectRepositoryFiles,
  parseGitHubRepoUrl
};
