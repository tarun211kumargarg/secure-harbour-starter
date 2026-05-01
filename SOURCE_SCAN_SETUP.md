# Live AI Repository Source Scan Demo

This update adds a public **AI Repo Scan** page to the Secure Harbour Azure Static Web App. A visitor pastes a public GitHub repository URL, the Azure Functions backend fetches a bounded set of source files, sends source excerpts and deterministic rule signals to GitHub Models, and returns the report directly to the browser.

## What was added

- Public page: `/repo-scan`
- Public API: `/api/repo-scan`
- Backend AI SAST module: `api/shared/aiCodeScanner.js`
- Public GitHub source collection through the GitHub API
- Deterministic OWASP rule signals used as guardrails for the AI scan
- Live result rendering for summary, severity, evidence, remediation plan, and findings

## Safety boundaries

The website demo is intentionally non-invasive:

- Only public GitHub repository URLs are accepted.
- The backend reads source text through the GitHub API.
- The backend does not clone, build, run, or execute submitted code.
- File count, file size, total characters, AI prompt size, and finding count are capped.
- Repository contents are treated as untrusted data in the AI prompt to reduce prompt-injection risk.
- Findings are indicators for review, not proof of exploitability.

## Required Azure settings for the live website

Configure a GitHub token in Azure Static Web Apps application settings. No OpenAI API key is used.

```text
GITHUB_MODELS_TOKEN
```

You can also set `GITHUB_TOKEN` instead of `GITHUB_MODELS_TOKEN`. The token must have access to GitHub Models with the `models: read` scope.

Optional model setting:

```text
GITHUB_MODELS_MODEL   # defaults to microsoft/phi-4-mini-instruct through GitHub Models
```

For better GitHub source-fetching limits, optionally configure:

```text
SCAN_GITHUB_TOKEN
```

The repo scan no longer requires name, email, or Cosmos DB. The result is returned immediately to the browser.

## Optional scan limits

Tune these settings for the public demo:

```text
SCAN_MAX_FILES          # default 40, source files fetched from GitHub
SCAN_MAX_FILE_BYTES     # default 120000
SCAN_MAX_TOTAL_CHARS    # default 160000
SCAN_MAX_FINDINGS       # default 80, backend rule signals
AI_SCAN_MAX_FILES       # default 24, source excerpts sent to AI
AI_SCAN_MAX_CHARS       # default 60000
AI_SCAN_MAX_FINDINGS    # default 20
AI_SCAN_MAX_TOKENS      # default 2200
```

## Deployment

The existing Azure Static Web Apps workflow deploys:

```text
app_location: site
api_location: api
```

After pushing to `main`, the live page should be available at:

```text
/repo-scan
```

On your current site, that resolves to:

```text
https://kind-island-0768a5f00.1.azurestaticapps.net/repo-scan
```

## Production hardening ideas

Before using this as a paid or high-volume scanning service, add:

- Per-IP rate limiting and abuse controls
- Queue-based processing for larger repositories
- Result persistence with expiry and user consent language
- Dependency scanning with OSV, GitHub Advisory Database, or equivalent
- Language-aware static analysis and data-flow rules
- Dedicated secret scanning with entropy checks and verification
- Manual validation for high-impact findings
- Monitoring for AI/API failures and GitHub rate-limit exhaustion
