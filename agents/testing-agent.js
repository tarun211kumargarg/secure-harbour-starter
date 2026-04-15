'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const TARGET_URL = process.env.TARGET_URL;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const LLM_MODEL = process.env.LLM_MODEL || 'openai/gpt-4.1';

if (!TARGET_URL) {
  throw new Error('TARGET_URL is missing');
}

const repoRoot = process.cwd();
const agentsDir = path.join(repoRoot, 'agents');
const screenshotsDir = path.join(agentsDir, 'screenshots');
const findingsPath = path.join(agentsDir, 'findings.json');
const reportPath = path.join(agentsDir, 'testing-report.md');

fs.mkdirSync(screenshotsDir, { recursive: true });

const payloads = [
  {
    label: 'img-onerror',
    value: '<img src=x onerror=alert("SH-XSS-1")>'
  },
  {
    label: 'svg-onload',
    value: '<svg/onload=alert("SH-XSS-2")>'
  }
];

function clip(text, max = 12000) {
  const value = String(text || '');
  return value.length <= max ? value : `${value.slice(0, max)}\n...[truncated]`;
}

function safeFileName(value) {
  return String(value).replace(/[^a-zA-Z0-9_-]+/g, '-');
}

function readIfExists(filePath) {
  if (!fs.existsSync(filePath)) return '';
  return fs.readFileSync(filePath, 'utf8');
}

function collectCodeSignals() {
  const dashboardPath = path.join(repoRoot, 'assets', 'dashboard.js');
  const validationPath = path.join(repoRoot, 'api', 'shared', 'validation.js');

  const dashboardText = readIfExists(dashboardPath);
  const validationText = readIfExists(validationPath);

  return {
    dashboard_js_exists: Boolean(dashboardText),
    dashboard_uses_innerHTML: dashboardText.includes('innerHTML'),
    dashboard_has_escapeHtml: dashboardText.includes('function escapeHtml'),
    dashboard_calls_escapeHtml: dashboardText.includes('escapeHtml(item.name)') || dashboardText.includes('escapeHtml(item.message)'),
    dashboard_uses_textContent_for_detail_fields:
      dashboardText.includes('drawerMessage.textContent = item.message') &&
      dashboardText.includes('drawerTitle.textContent = item.name'),
    validation_js_exists: Boolean(validationText),
    validation_normalizes_strings: validationText.includes('normalizeString('),
    validation_escapes_html: validationText.includes('&lt;') || validationText.includes('escapeHtml')
  };
}

async function runPayloadProbe(browser, baseUrl, payload, index) {
  const context = await browser.newContext({
    ignoreHTTPSErrors: true
  });

  const page = await context.newPage();

  const result = {
    label: payload.label,
    payload: payload.value,
    contact_url: new URL('/contact', baseUrl).toString(),
    dialog_seen: false,
    dialog_message: '',
    page_errors: [],
    api_request_body: null,
    api_response_status: null,
    api_response_body: null,
    reached_thank_you: false,
    current_url: '',
    notice_text: '',
    payload_visible_in_body: false
  };

  page.on('dialog', async (dialog) => {
    result.dialog_seen = true;
    result.dialog_message = dialog.message();
    await dialog.dismiss();
  });

  page.on('pageerror', (error) => {
    result.page_errors.push(String(error));
  });

  page.on('request', (request) => {
    if (request.url().includes('/api/submit-query')) {
      try {
        result.api_request_body = request.postDataJSON();
      } catch (error) {
        result.api_request_body = { error: String(error) };
      }
    }
  });

  page.on('response', async (response) => {
    if (response.url().includes('/api/submit-query')) {
      result.api_response_status = response.status();
      try {
        result.api_response_body = await response.json();
      } catch (error) {
        try {
          result.api_response_body = await response.text();
        } catch {
          result.api_response_body = { error: String(error) };
        }
      }
    }
  });

  const suffix = `${Date.now()}-${index}`;
  const beforeShot = path.join(screenshotsDir, `${safeFileName(payload.label)}-before.png`);
  const afterShot = path.join(screenshotsDir, `${safeFileName(payload.label)}-after.png`);

  try {
    await page.goto(result.contact_url, { waitUntil: 'domcontentloaded', timeout: 20000 });

    await page.fill('input[name="name"]', payload.value);
    await page.fill('input[name="company"]', 'Secure Harbour QA');
    await page.fill('input[name="email"]', `xss-scout+${safeFileName(payload.label)}-${suffix}@example.com`);
    await page.fill('input[name="phone"]', '9999999999');
    await page.selectOption('select[name="serviceInterestedIn"]', 'Penetration Testing');
    await page.fill('textarea[name="message"]', payload.value);

    await page.screenshot({ path: beforeShot, fullPage: true });

    const thankYouPromise = page.waitForURL(/\/thank-you(?:$|\?)/, {
      timeout: 15000
    }).then(() => true).catch(() => false);

    await page.click('button[type="submit"]');

    result.reached_thank_you = await thankYouPromise;
    result.current_url = page.url();

    const notice = page.locator('[data-form-notice]');
    if (await notice.count()) {
      result.notice_text = (await notice.textContent()) || '';
    }

    const bodyText = await page.locator('body').innerText().catch(() => '');
    result.payload_visible_in_body = bodyText.includes(payload.value);

    await page.screenshot({ path: afterShot, fullPage: true });
  } catch (error) {
    result.error = String(error);
    result.current_url = page.url();
    try {
      await page.screenshot({ path: afterShot, fullPage: true });
    } catch {
      // ignore screenshot failure
    }
  } finally {
    await context.close();
  }

  return result;
}

async function generateAiSummary(findings) {
  const fallback = [
    '# Verdict',
    findings.summary.dialog_count > 0
      ? 'Possible XSS execution observed because a browser dialog fired during testing.'
      : findings.summary.reached_thank_you_count > 0
        ? 'No reflected XSS execution was observed in the public contact flow during these probes.'
        : 'Testing completed, but the public flow did not provide enough evidence of reflected XSS.',
    '',
    '# Pages checked',
    '- /contact',
    '- /thank-you (when submission succeeded)',
    '',
    '# Payloads tried',
    ...findings.payload_results.map((item) => `- ${item.label}: \`${item.payload}\``),
    '',
    '# Browser observations',
    `- Successful submissions: ${findings.summary.reached_thank_you_count}/${findings.summary.total_payloads}`,
    `- Dialogs seen: ${findings.summary.dialog_count}`,
    `- Payload visible back in public response body: ${findings.summary.visible_payload_count}`,
    '',
    '# Stored-XSS view',
    'The public flow was tested directly. Stored XSS in the owner dashboard was not executed end-to-end because the dashboard requires authentication.',
    '',
    '# Evidence from code',
    `- dashboard.js uses innerHTML: ${findings.code_signals.dashboard_uses_innerHTML}`,
    `- dashboard.js has escapeHtml helper: ${findings.code_signals.dashboard_has_escapeHtml}`,
    `- dashboard detail fields use textContent: ${findings.code_signals.dashboard_uses_textContent_for_detail_fields}`,
    `- validation.js escapes HTML before storage: ${findings.code_signals.validation_escapes_html}`,
    '',
    '# Next steps',
    '- Review the admin dashboard with authenticated testing if you want stored-XSS confirmation.',
    '- Keep using escaped rendering and avoid inserting untrusted HTML.'
  ].join('\n');

  if (!GITHUB_TOKEN) {
    return fallback;
  }

  const prompt = [
    'You are Secure Harbour’s testing agent summarizer.',
    'Write a concise markdown report from these REAL browser and code findings.',
    'Do not invent facts.',
    'Use these exact section headers in this order:',
    '# Verdict',
    '# Pages checked',
    '# Payloads tried',
    '# Browser observations',
    '# Stored-XSS view',
    '# Evidence from code',
    '# Next steps',
    '',
    'Here are the findings as JSON:',
    clip(JSON.stringify(findings, null, 2), 15000)
  ].join('\n');

  try {
    const response = await fetch('https://models.github.ai/inference/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/vnd.github+json',
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        'X-GitHub-Api-Version': '2022-11-28'
      },
      body: JSON.stringify({
        model: LLM_MODEL,
        temperature: 0.1,
        messages: [
          {
            role: 'system',
            content: 'You create short, factual security testing summaries from supplied evidence.'
          },
          {
            role: 'user',
            content: prompt
          }
        ]
      })
    });

    const text = await response.text();

    if (!response.ok) {
      return `${fallback}\n\n## AI summary note\nGitHub Models call failed: ${text}`;
    }

    const parsed = JSON.parse(text);
    const content = parsed?.choices?.[0]?.message?.content;

    if (!content) {
      return `${fallback}\n\n## AI summary note\nGitHub Models returned no content.`;
    }

    return content;
  } catch (error) {
    return `${fallback}\n\n## AI summary note\nGitHub Models request failed: ${String(error)}`;
  }
}

async function main() {
  const browser = await chromium.launch({
    headless: true
  });

  try {
    const payloadResults = [];

    for (let i = 0; i < payloads.length; i += 1) {
      const result = await runPayloadProbe(browser, TARGET_URL, payloads[i], i + 1);
      payloadResults.push(result);
    }

    const codeSignals = collectCodeSignals();

    const findings = {
      target_url: TARGET_URL,
      tested_at: new Date().toISOString(),
      payload_results: payloadResults,
      code_signals: codeSignals,
      summary: {
        total_payloads: payloadResults.length,
        reached_thank_you_count: payloadResults.filter((x) => x.reached_thank_you).length,
        dialog_count: payloadResults.filter((x) => x.dialog_seen).length,
        visible_payload_count: payloadResults.filter((x) => x.payload_visible_in_body).length,
        api_201_count: payloadResults.filter((x) => x.api_response_status === 201).length
      }
    };

    fs.writeFileSync(findingsPath, JSON.stringify(findings, null, 2), 'utf8');

    const report = await generateAiSummary(findings);
    fs.writeFileSync(reportPath, report, 'utf8');

    console.log('Testing findings written to:', findingsPath);
    console.log('Testing report written to:', reportPath);
    console.log(report);
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});