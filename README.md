# Secure Harbour

This repo is split into three safe zones:

- `site/` - public Azure Static Web App
- `api/` - Azure Functions backend
- `agents/` + `agent-fixtures/` - private local-only and workflow agent demos

## Azure deployment

Set the repository secret `AZURE_STATIC_WEB_APPS_API_TOKEN` and deploy with the included `azure-static-webapp.yml` workflow if that is the workflow name in your repo, or the existing Azure Static Web Apps workflow currently configured for this project.

The Azure Static Web Apps workflow deploys:

- app location: `site`
- API location: `api`
- output location: empty string, because the site is static HTML/CSS/JS

## Public live AI repository scan demo

The website includes `/repo-scan`, a public demo page where a visitor can paste a public GitHub repository URL and receive an immediate OWASP Top 10 source-code scan report in the browser.

The live scan flow is intentionally safe for a public demo:

- accepts public GitHub repositories only
- reads selected source files through the GitHub API
- does not clone, build, run, or execute submitted code
- uses backend deterministic OWASP rule signals as guardrails
- sends bounded, redacted source excerpts to GitHub Models from the backend
- returns AI-generated findings, severity, evidence, and remediation guidance directly to the page
- keeps the GitHub token server-side in Azure Functions
- does not require an OpenAI API key

Required Azure setting for the live AI scan:

```text
GITHUB_MODELS_TOKEN
```

You can also use `GITHUB_TOKEN` instead of `GITHUB_MODELS_TOKEN`. The token must be able to call GitHub Models with `models: read`.

Optional model and GitHub API settings:

```text
GITHUB_MODELS_MODEL   # defaults to microsoft/phi-4-mini-instruct through GitHub Models
SCAN_GITHUB_TOKEN     # optional separate token for higher GitHub source-fetching limits
```

See `SOURCE_SCAN_SETUP.md` for configuration and deployment details.

## Manual source scan workflow

Run the manual workflow **Public Repository OWASP Source Scan** from GitHub Actions and provide a public GitHub repository URL.

The workflow writes:

- `agents/source-scan-results.json`
- `agents/source-scan-report.md`

## XSS agent demo

Run the manual workflow **XSS Two Agent Pipeline** from GitHub Actions.

The workflow serves `agent-fixtures/xss-lab.html` on a temporary local server inside the GitHub runner, so the demo vulnerability is never exposed on the public site.

- testing agent: LLM-guided Playwright loop
- patching agent: patches the local fixture after approval
- final report: combines evidence and patch summary

The patching job pauses on the `patch-approval` environment.
