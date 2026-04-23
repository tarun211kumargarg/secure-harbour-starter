# Secure Harbour Final Repo

This repo is split into two clean concerns:

- `site/` — the safe public website deployed to Azure Static Web Apps
- `api/` — the Azure Functions API used by the public site and owner dashboard
- `agent-fixtures/` — local-only cybersecurity training fixtures used by GitHub Actions
- `agents/` — the testing, patching, and final report scripts for the XSS two-agent demo

## Public website deployment

The Azure workflow is in `.github/workflows/azure-static-webapp.yml`.

Set this GitHub repository secret before expecting production deployment:

- `AZURE_STATIC_WEB_APPS_API_TOKEN`

The Azure workflow deploys only the contents of `site/` as the public app root and `api/` as the serverless backend.

### Azure workflow behavior

- `app_location: site`
- `api_location: api`
- `skip_app_build: true`
- `skip_deploy_on_missing_secrets: true`

That means agent-only commits do not fail loudly if the Azure token is not configured yet.

## XSS two-agent demo

The two-agent workflow is in `.github/workflows/xss-two-agent.yml`.

It uses a **local-only** XSS lab fixture served from `agent-fixtures/xss-lab.html` on the GitHub Actions runner itself. This keeps the public site safe while still giving you a real detection-and-patching demo.

### Agent roles

- `testing_agent` — uses Playwright + GitHub Models to decide the next browser action, test the lab, and write `testing-report.md`
- `patching_agent` — waits for your `patch-approval` environment approval, patches the vulnerable line in the local fixture, writes `patch-report.md`, and can commit the patched fixture back to the repo
- `final_report` — combines testing + patching output into one report artifact

### Required GitHub setup

Create a GitHub Environment named:

- `patch-approval`

Add yourself as a required reviewer if you want a true approval gate.

### How to run the demo

1. Go to **Actions**
2. Open **XSS Two Agent Pipeline**
3. Click **Run workflow**
4. Choose whether to commit the patch back to the repo (`true` or `false`)
5. Start the run
6. Approve the `patch-approval` environment when the patching job pauses

### Where results appear

Artifacts uploaded by the workflow:

- `testing-output`
- `patch-output`
- `final-xss-report`

## Notes on safety

The intentionally vulnerable lab is **not** part of the public Azure site. It is only served locally inside GitHub Actions from `agent-fixtures/`.

## Local repo layout

```text
site/
api/
agent-fixtures/
agents/
.github/workflows/
```
