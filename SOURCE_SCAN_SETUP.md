# GitHub-Token-Only Repository Source Scan Demo

This update adds a public **AI Repo Scan** page to the Secure Harbour Azure Static Web App. Visitors can submit a public GitHub repository URL and receive a lightweight OWASP Top 10 source-code scan summary. The request and scan result are stored in the existing Cosmos-backed owner dashboard.

This version does **not** require OpenAI, ChatGPT, GitHub Models, or any other paid AI/API token. The only recommended token is a GitHub token for GitHub API rate limits.

## What was added

- Public page: `/repo-scan`
- Public API: `/api/submit-repo-scan`
- Owner dashboard support for repository scan records
- Deterministic OWASP Top 10 source-code rule engine
- Local OWASP triage and remediation summary
- Manual GitHub Actions workflow: **Public Repository OWASP Source Scan**

## Safety boundaries

The website demo is intentionally non-invasive:

- Only public GitHub repository URLs are accepted.
- The backend reads source text through the GitHub API.
- The backend does not clone, build, run, or execute submitted code.
- File count, file size, total characters, and finding count are capped.
- Findings are indicators for review, not proof of exploitability.
- No external model API is called during scanning or summarization.

This makes the feature suitable for a public website showcase while still demonstrating a Checkmarx-style secure code scanning workflow.

## Required Azure settings

The feature reuses the existing Cosmos DB configuration:

```text
COSMOS_ENDPOINT
COSMOS_KEY
COSMOS_DATABASE_NAME
COSMOS_CONTAINER_NAME
```

The public repo scan records are stored in the same container with:

```text
recordType = "repoScan"
serviceInterestedIn = "AI Code Security Scan"
sourcePage = "repo-scan"
```

## GitHub token setting

For better GitHub API limits, configure one of:

```text
SCAN_GITHUB_TOKEN
GITHUB_TOKEN
```

A fine-grained GitHub token with read-only access to public repositories is enough. The token is used server-side for GitHub API requests and is not stored in Cosmos scan records.

No paid model-token settings are used by this version.

## Scan limits

Scan limits can be tuned with:

```text
SCAN_MAX_FILES          # default 40
SCAN_MAX_FILE_BYTES     # default 120000
SCAN_MAX_TOTAL_CHARS    # default 160000
SCAN_MAX_FINDINGS       # default 80
```

## Deployment

The existing Azure Static Web Apps workflow already deploys:

```text
app_location: site
api_location: api
```

After this code is pushed to `main`, the new page should be available at:

```text
/repo-scan
```

The route is added in `site/staticwebapp.config.json`.

## GitHub Actions scan workflow

A manual workflow is included:

```text
.github/workflows/source-code-scan.yml
```

Run **Public Repository OWASP Source Scan** from the Actions tab and provide a public GitHub repository URL. The workflow uses the built-in GitHub Actions token, so you do not need to create a paid API token.

The workflow writes:

```text
agents/source-scan-results.json
agents/source-scan-report.md
```

## Production hardening ideas

Before using this as a high-volume scanning service, add:

- Per-IP and per-email rate limiting
- Queue-based processing for larger repositories
- Dedicated scan-result container with TTL
- Secret scanning with verified entropy checks
- Dependency scanning with OSV, GitHub Advisory Database, or equivalent
- Language-aware static analysis and data-flow rules
- User consent and acceptable-use language
- Abuse monitoring and alerting
