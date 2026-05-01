# Secure Harbour

This repo is split into three safe zones:

- `site/` - public Azure Static Web App
- `api/` - Azure Functions backend
- `agents/` + `agent-fixtures/` - private local-only and workflow agent demos

## Azure deployment

Set the repository secret `AZURE_STATIC_WEB_APPS_API_TOKEN` and deploy with the included `azure-static-webapp.yml` workflow.

The Azure Static Web Apps workflow deploys:

- app location: `site`
- API location: `api`
- output location: empty string, because the site is static HTML/CSS/JS

## Public repository scan demo

The website includes `/repo-scan`, a public demo page where a visitor can submit a public GitHub repository URL for an OWASP Top 10 source-code scan.

The scan flow is intentionally safe for a public demo:

- accepts public GitHub repositories only
- reads source files through the GitHub API
- does not clone, build, run, or execute submitted code
- caps file count, file size, total characters, and findings
- applies deterministic OWASP source rules
- generates a local OWASP triage and remediation summary
- requires no paid AI/API token; only `SCAN_GITHUB_TOKEN` is recommended for GitHub API rate limits
- stores scan requests and summaries in the existing owner dashboard

See `SOURCE_SCAN_SETUP.md` for configuration and deployment details.

## Manual source scan workflow

Run the manual workflow **Public Repository OWASP Source Scan** from GitHub Actions and provide a public GitHub repository URL.

The workflow uses the built-in GitHub Actions token through `github.token`; no paid API token is required.

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
