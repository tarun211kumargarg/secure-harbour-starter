# Secure Harbour

This repo is split into three safe zones:

- `site/` - public Azure Static Web App
- `api/` - Azure Functions backend
- `agents/` + `agent-fixtures/` - private local-only agent demo

## Azure deployment

Set the repository secret `AZURE_STATIC_WEB_APPS_API_TOKEN` and deploy with the included `azure-static-webapp.yml` workflow.

## XSS agent demo

Run the manual workflow **XSS Two Agent Pipeline** from GitHub Actions.

The workflow serves `agent-fixtures/xss-lab.html` on a temporary local server inside the GitHub runner, so the demo vulnerability is never exposed on the public site.

- testing agent: LLM-guided Playwright loop
- patching agent: patches the local fixture after approval
- final report: combines evidence and patch summary

The patching job pauses on the `patch-approval` environment.
