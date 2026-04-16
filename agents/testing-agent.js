'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('playwright');

const TARGET_URL = process.env.TARGET_URL;
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const LLM_MODEL = process.env.LLM_MODEL || 'openai/gpt-4.1';
const MAX_AGENT_TURNS = Number(process.env.MAX_AGENT_TURNS || '6');

if (!TARGET_URL) throw new Error('TARGET_URL is missing');
if (!GITHUB_TOKEN) throw new Error('GITHUB_TOKEN is missing');

const repoRoot = process.cwd();
const agentsDir = path.join(repoRoot, 'agents');
const screenshotsDir = path.join(agentsDir, 'screenshots');
const findingsPath = path.join(agentsDir, 'findings.json');
const reportPath = path.join(agentsDir, 'testing-report.md');

fs.mkdirSync(screenshotsDir, { recursive: true });

const state = {
  dialogs: [],
  pageErrors: [],
  requestBodies: [],
  responseSummaries: [],
  turnResults: [],
  currentUrl: '',
  lastPayload: '',
  lastScreenshot: '',
  lastBodyExcerpt: '',
  visited: []
};

function clip(text, max = 9000) {
  const value = String(text || '');
  return value.length <= max ? value : `${value.slice(0, max)}\n...[truncated]`;
}

function stripCodeFences(text) {
  return String(text || '')
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/i, '')
    .replace(/```$/i, '')
    .trim();
}

function extractJsonObject(text) {
  const cleaned = stripCodeFences(text);
  const first = cleaned.indexOf('{');
  const last = cleaned.lastIndexOf('}');
  if (first === -1 || last === -1 || last <= first) {
    throw new Error(`Could not find JSON object in model output:\n${cleaned}`);
  }
  return JSON.parse(cleaned.slice(first, last + 1));
}

function safeFileName(value) {
  return String(value || 'file').replace(/[^a-zA-Z0-9_-]+/g, '-');
}

function readIfExists(filePath) {
  return fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
}

function repoRenderingHints() {
  const dashboardPath = path.join(repoRoot, 'assets', 'dashboard.js');
  const validationPath = path.join(repoRoot, 'api', 'shared', 'validation.js');

  const dashboard = readIfExists(dashboardPath);
  const validation = readIfExists(validationPath);

  return {
    dashboard_js_exists: Boolean(dashboard),
    dashboard_uses_innerHTML: dashboard.includes('innerHTML'),
    dashboard_has_escapeHtml: dashboard.includes('function escapeHtml'),
    dashboard_uses_textContent_for_detail_fields:
      dashboard.includes('drawerMessage.textContent = item.message') &&
      dashboard.includes('drawerTitle.textContent = item.name'),
    validation_js_exists: Boolean(validation),
    validation_normalizes_strings: validation.includes('normalizeString('),
    validation_explicit_html_escape: /&lt;|escapeHtml/i.test(validation)
  };
}

async function uniqueEmail(label) {
  const stamp = Date.now();
  return `xss-agent+${safeFileName(label)}-${stamp}@example.com`;
}

async function getBodyExcerpt(page) {
  try {
    const bodyText = await page.locator('body').innerText();
    return clip(bodyText, 6000);
  } catch {
    return '';
  }
}

async function screenshot(page, label) {
  const filePath = path.join(
    screenshotsDir,
    `${Date.now()}-${safeFileName(label)}.png`
  );
  await page.screenshot({ path: filePath, fullPage: true });
  state.lastScreenshot = filePath;
  return filePath;
}

async function checkHeaders(url) {
  const response = await fetch(url, {
    headers: { 'User-Agent': 'SecureHarbour-XSS-Agent/1.0' },
    redirect: 'follow'
  });

  return {
    url: response.url,
    status: response.status,
    headers: {
      'content-security-policy': response.headers.get('content-security-policy'),
      'x-frame-options': response.headers.get('x-frame-options'),
      'x-content-type-options': response.headers.get('x-content-type-options'),
      'strict-transport-security': response.headers.get('strict-transport-security'),
      'referrer-policy': response.headers.get('referrer-policy')
    }
  };
}

// ---------------------------------------------------------
// THIS IS YOUR LLM WRAPPER FUNCTION
// The real model/API call is the fetch(...) line inside it.
// ---------------------------------------------------------
async function askTestingLLM(messages) {
  // >>> ACTUAL LLM API CALL STARTS HERE
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
      messages
    })
  });
  // <<< ACTUAL LLM API CALL ENDS HERE

  const text = await response.text();

  if (!response.ok) {
    throw new Error(`GitHub Models API error ${response.status}: ${text}`);
  }

  const parsed = JSON.parse(text);
  return parsed?.choices?.[0]?.message?.content || '';
}

async function openContactPage(page) {
  const contactUrl = new URL('/contact', TARGET_URL).toString();
  await page.goto(contactUrl, { waitUntil: 'domcontentloaded', timeout: 20000 });

  state.currentUrl = page.url();
  state.visited.push(state.currentUrl);

  const fields = await page.evaluate(() => {
    return Array.from(
      document.querySelectorAll('input[name], textarea[name], select[name]')
    ).map((el) => ({
      tag: el.tagName.toLowerCase(),
      name: el.getAttribute('name'),
      type: el.getAttribute('type')
    }));
  });

  const title = await page.title();
  const bodyExcerpt = await getBodyExcerpt(page);
  state.lastBodyExcerpt = bodyExcerpt;
  const shot = await screenshot(page, 'contact-page');

  return {
    action: 'open_contact_page',
    url: state.currentUrl,
    title,
    fields,
    screenshot: shot,
    body_excerpt: bodyExcerpt
  };
}

async function submitPayload(page, args = {}) {
  const payload = args.payload || '<img src=x onerror=alert("SH-XSS")>';
  const targetFields = Array.isArray(args.target_fields) && args.target_fields.length
    ? args.target_fields
    : ['name', 'message'];

  const service = args.service || 'Penetration Testing';
  const email = await uniqueEmail(args.label || 'probe');

  state.lastPayload = payload;

  if (!page.url().includes('/contact')) {
    await openContactPage(page);
  }

  const valueFor = (fieldName) => {
    if (targetFields.includes(fieldName)) return payload;
    if (fieldName === 'company') return 'Secure Harbour QA';
    if (fieldName === 'email') return email;
    if (fieldName === 'phone') return '9999999999';
    if (fieldName === 'serviceInterestedIn') return service;
    return '';
  };

  await page.fill('input[name="name"]', valueFor('name'));
  await page.fill('input[name="company"]', valueFor('company'));
  await page.fill('input[name="email"]', valueFor('email'));
  await page.fill('input[name="phone"]', valueFor('phone'));
  await page.selectOption('select[name="serviceInterestedIn"]', valueFor('serviceInterestedIn'));
  await page.fill('textarea[name="message"]', valueFor('message'));

  const thankYouPromise = page.waitForURL(/\/thank-you(?:$|\?)/, {
    timeout: 15000
  }).then(() => true).catch(() => false);

  await page.click('button[type="submit"]');

  const reachedThankYou = await thankYouPromise;
  state.currentUrl = page.url();

  const noticeText = await page.locator('[data-form-notice]').textContent().catch(() => '');
  const bodyExcerpt = await getBodyExcerpt(page);
  state.lastBodyExcerpt = bodyExcerpt;
  const shot = await screenshot(page, `submit-${args.label || 'payload'}`);

  return {
    action: 'submit_payload',
    submitted_payload: payload,
    target_fields: targetFields,
    reached_thank_you: reachedThankYou,
    current_url: state.currentUrl,
    notice_text: noticeText || '',
    dialog_count: state.dialogs.length,
    latest_dialog: state.dialogs.at(-1) || null,
    latest_api_request: state.requestBodies.at(-1) || null,
    latest_api_response: state.responseSummaries.at(-1) || null,
    body_excerpt: bodyExcerpt,
    screenshot: shot
  };
}

async function inspectCurrentPage(page, args = {}) {
  const marker = args.marker || state.lastPayload || 'SH-XSS';

  const bodyExcerpt = await getBodyExcerpt(page);
  state.lastBodyExcerpt = bodyExcerpt;
  const title = await page.title();
  const shot = await screenshot(page, 'inspect-page');

  return {
    action: 'inspect_current_page',
    current_url: page.url(),
    title,
    marker,
    marker_visible_in_body: bodyExcerpt.includes(marker),
    dialog_count: state.dialogs.length,
    latest_dialog: state.dialogs.at(-1) || null,
    page_errors: state.pageErrors.slice(-5),
    body_excerpt: bodyExcerpt,
    screenshot: shot
  };
}

async function inspectRepoHints() {
  return {
    action: 'inspect_repo_hints',
    hints: repoRenderingHints()
  };
}

async function toolRunner(page, action, args) {
  switch (action) {
    case 'open_contact_page':
      return openContactPage(page);
    case 'submit_payload':
      return submitPayload(page, args);
    case 'inspect_current_page':
      return inspectCurrentPage(page, args);
    case 'check_headers':
      return checkHeaders(new URL('/contact', TARGET_URL).toString());
    case 'inspect_repo_hints':
      return inspectRepoHints();
    default:
      return {
        action,
        error: `Unsupported action: ${action}`
      };
  }
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();

  page.on('dialog', async (dialog) => {
    state.dialogs.push({
      type: dialog.type(),
      message: dialog.message()
    });
    await dialog.dismiss();
  });

  page.on('pageerror', (error) => {
    state.pageErrors.push(String(error));
  });

  page.on('request', (request) => {
    if (request.url().includes('/api/submit-query')) {
      try {
        state.requestBodies.push({
          url: request.url(),
          method: request.method(),
          body: request.postDataJSON()
        });
      } catch {
        state.requestBodies.push({
          url: request.url(),
          method: request.method(),
          body: request.postData()
        });
      }
    }
  });

  page.on('response', async (response) => {
    if (response.url().includes('/api/submit-query')) {
      let body;
      try {
        body = await response.json();
      } catch {
        try {
          body = await response.text();
        } catch {
          body = '';
        }
      }

      state.responseSummaries.push({
        url: response.url(),
        status: response.status(),
        body: body
      });
    }
  });

  const messages = [
    {
      role: 'system',
      content:
        'You are Secure Harbour’s XSS testing agent. ' +
        'Your job is to choose the next testing action, one turn at a time. ' +
        'You are allowed exactly these actions: ' +
        'open_contact_page, submit_payload, inspect_current_page, check_headers, inspect_repo_hints, finish. ' +
        'Return STRICT JSON only with this shape: ' +
        '{"action":"...","args":{},"reason":"...","report_markdown":"only when action is finish"} ' +
        'Rules: stay on the same target site, test /contact first, use small controlled XSS payloads, and finish with a markdown report. ' +
        'Required report sections in this exact order: ' +
        '# Verdict\n# Pages checked\n# Actions taken\n# Payloads tried\n# Browser evidence\n# Stored-XSS view\n# Next steps'
    },
    {
      role: 'user',
      content:
        `Start testing this site for XSS.\n` +
        `Target URL: ${TARGET_URL}\n` +
        `You may use up to ${MAX_AGENT_TURNS} turns.\n` +
        `Choose the first action now.`
    }
  ];

  try {
    for (let turn = 1; turn <= MAX_AGENT_TURNS; turn += 1) {
      // THIS LINE ASKS THE LLM WHAT TO DO NEXT
      const rawDecision = await askTestingLLM(messages);
      console.log(`\n=== MODEL TURN ${turn} ===\n${rawDecision}\n`);

      let decision;
      try {
        decision = extractJsonObject(rawDecision);
      } catch (error) {
        messages.push({ role: 'assistant', content: rawDecision });
        messages.push({
          role: 'user',
          content:
            'Your previous reply was not valid JSON. ' +
            'Reply again in strict JSON only with keys action, args, reason, report_markdown.'
        });
        continue;
      }

      if (decision.action === 'finish') {
        const report = decision.report_markdown || '# Verdict\nNo report provided.';
        fs.writeFileSync(reportPath, report, 'utf8');

        const findings = {
          target_url: TARGET_URL,
          finished_at: new Date().toISOString(),
          llm_model: LLM_MODEL,
          turns: state.turnResults,
          dialogs: state.dialogs,
          page_errors: state.pageErrors,
          requests: state.requestBodies,
          responses: state.responseSummaries,
          visited_urls: state.visited,
          last_payload: state.lastPayload,
          screenshots_dir: screenshotsDir,
          final_report_path: reportPath
        };

        fs.writeFileSync(findingsPath, JSON.stringify(findings, null, 2), 'utf8');

        console.log('Testing findings written to:', findingsPath);
        console.log('Testing report written to:', reportPath);
        console.log(report);
        return;
      }

      const toolResult = await toolRunner(page, decision.action, decision.args || {});
      state.turnResults.push({
        turn,
        model_decision: decision,
        tool_result: toolResult
      });

      messages.push({
        role: 'assistant',
        content: rawDecision
      });

      messages.push({
        role: 'user',
        content:
          `TOOL_RESULT for action "${decision.action}":\n` +
          `${JSON.stringify(toolResult, null, 2)}\n\n` +
          `Decide the next action now. If you have enough evidence, use finish.`
      });
    }

    const forcedFinish = await askTestingLLM([
      ...messages,
      {
        role: 'user',
        content:
          'You have reached the turn limit. Do not ask for more actions. ' +
          'Return finish JSON now with the full markdown report in report_markdown.'
      }
    ]);

    const finishDecision = extractJsonObject(forcedFinish);
    const report = finishDecision.report_markdown || '# Verdict\nNo report provided.';
    fs.writeFileSync(reportPath, report, 'utf8');

    const findings = {
      target_url: TARGET_URL,
      finished_at: new Date().toISOString(),
      llm_model: LLM_MODEL,
      turns: state.turnResults,
      dialogs: state.dialogs,
      page_errors: state.pageErrors,
      requests: state.requestBodies,
      responses: state.responseSummaries,
      visited_urls: state.visited,
      last_payload: state.lastPayload,
      screenshots_dir: screenshotsDir,
      final_report_path: reportPath
    };

    fs.writeFileSync(findingsPath, JSON.stringify(findings, null, 2), 'utf8');

    console.log('Testing findings written to:', findingsPath);
    console.log('Testing report written to:', reportPath);
    console.log(report);
  } finally {
    await context.close();
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});