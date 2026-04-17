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
  turnResults: [],
  currentUrl: '',
  lastPayload: '',
  visited: [],
  screenshots: []
};

function clip(text, max = 8000) {
  const value = String(text || '');
  return value.length <= max ? value : `${value.slice(0, max)}\n...[truncated]`;
}

function safeFileName(value) {
  return String(value || 'file').replace(/[^a-zA-Z0-9_-]+/g, '-');
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
    throw new Error(`Could not parse JSON from model output:\n${cleaned}`);
  }
  return JSON.parse(cleaned.slice(first, last + 1));
}

async function saveShot(page, label) {
  const filePath = path.join(
    screenshotsDir,
    `${Date.now()}-${safeFileName(label)}.png`
  );
  await page.screenshot({ path: filePath, fullPage: true });
  state.screenshots.push(filePath);
  return filePath;
}

async function getBodyExcerpt(page) {
  try {
    const bodyText = await page.locator('body').innerText();
    return clip(bodyText, 5000);
  } catch {
    return '';
  }
}

// ACTUAL LLM CALL
async function askTestingLLM(messages) {
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

  const text = await response.text();

  if (!response.ok) {
    throw new Error(`GitHub Models API error ${response.status}: ${text}`);
  }

  const parsed = JSON.parse(text);
  return parsed?.choices?.[0]?.message?.content || '';
}

async function openLab(page) {
  const labUrl = new URL('/demo/xss-lab.html', TARGET_URL).toString();
  await page.goto(labUrl, { waitUntil: 'domcontentloaded', timeout: 20000 });

  state.currentUrl = page.url();
  state.visited.push(state.currentUrl);

  const bodyExcerpt = await getBodyExcerpt(page);
  const screenshot = await saveShot(page, 'lab-open');

  return {
    action: 'open_lab',
    url: state.currentUrl,
    title: await page.title(),
    body_excerpt: bodyExcerpt,
    screenshot
  };
}

async function submitPayload(page, args = {}) {
  const payload = args.payload || '<img src=x onerror=alert("XSS-LAB")>';
  state.lastPayload = payload;

  if (!page.url().includes('/demo/xss-lab.html')) {
    await openLab(page);
  }

  await page.fill('#message', payload);
  await page.click('#renderBtn');

  const bodyExcerpt = await getBodyExcerpt(page);
  const htmlContent = await page.locator('#preview').innerHTML().catch(() => '');
  const textContent = await page.locator('#preview').innerText().catch(() => '');
  const screenshot = await saveShot(page, 'lab-submit');

  return {
    action: 'submit_payload',
    payload,
    current_url: page.url(),
    preview_inner_html: clip(htmlContent, 2000),
    preview_inner_text: clip(textContent, 2000),
    body_excerpt: bodyExcerpt,
    dialog_count: state.dialogs.length,
    latest_dialog: state.dialogs.at(-1) || null,
    page_errors: state.pageErrors.slice(-5),
    screenshot
  };
}

async function inspectPage(page, args = {}) {
  const marker = args.marker || state.lastPayload || 'XSS-LAB';
  const bodyExcerpt = await getBodyExcerpt(page);
  const htmlContent = await page.locator('#preview').innerHTML().catch(() => '');
  const screenshot = await saveShot(page, 'lab-inspect');

  return {
    action: 'inspect_page',
    current_url: page.url(),
    marker,
    marker_visible_in_body: bodyExcerpt.includes(marker),
    marker_visible_in_preview_html: htmlContent.includes(marker),
    preview_inner_html: clip(htmlContent, 2000),
    dialog_count: state.dialogs.length,
    latest_dialog: state.dialogs.at(-1) || null,
    page_errors: state.pageErrors.slice(-5),
    screenshot
  };
}

async function inspectRepoFile() {
  const filePath = path.join(repoRoot, 'demo', 'xss-lab.html');
  const text = fs.readFileSync(filePath, 'utf8');

  return {
    action: 'inspect_repo_file',
    file: 'demo/xss-lab.html',
    vulnerable_innerhtml_present: text.includes('preview.innerHTML = messageInput.value;'),
    file_excerpt: clip(text, 4000)
  };
}

async function runTool(page, action, args) {
  switch (action) {
    case 'open_lab':
      return openLab(page);
    case 'submit_payload':
      return submitPayload(page, args);
    case 'inspect_page':
      return inspectPage(page, args);
    case 'inspect_repo_file':
      return inspectRepoFile();
    default:
      return { error: `Unsupported action: ${action}` };
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

  const messages = [
    {
      role: 'system',
      content:
        'You are a browser XSS testing agent. ' +
        'You must choose exactly one action at a time. ' +
        'Allowed actions: open_lab, submit_payload, inspect_page, inspect_repo_file, finish. ' +
        'Return STRICT JSON only with keys action, args, reason, report_markdown. ' +
        'Use /demo/xss-lab.html as the target page. ' +
        'Use small controlled payloads. ' +
        'When enough evidence exists, finish with markdown report using these exact sections: ' +
        '# Verdict\n# Pages checked\n# Actions taken\n# Payloads tried\n# Browser evidence\n# Source-code evidence\n# Next steps'
    },
    {
      role: 'user',
      content:
        `Start testing for XSS.\n` +
        `Base URL: ${TARGET_URL}\n` +
        `Target page: /demo/xss-lab.html\n` +
        `Maximum turns: ${MAX_AGENT_TURNS}\n` +
        `Choose the first action.`
    }
  ];

  try {
    for (let turn = 1; turn <= MAX_AGENT_TURNS; turn += 1) {
      const rawDecision = await askTestingLLM(messages);
      console.log(`\n=== MODEL TURN ${turn} ===\n${rawDecision}\n`);

      let decision;
      try {
        decision = extractJsonObject(rawDecision);
      } catch {
        messages.push({ role: 'assistant', content: rawDecision });
        messages.push({
          role: 'user',
          content: 'Reply again in strict JSON only.'
        });
        continue;
      }

      if (decision.action === 'finish') {
        const report = decision.report_markdown || '# Verdict\nNo report provided.';
        fs.writeFileSync(reportPath, report, 'utf8');

        const findings = {
          target_url: TARGET_URL,
          target_page: '/demo/xss-lab.html',
          finished_at: new Date().toISOString(),
          llm_model: LLM_MODEL,
          turns: state.turnResults,
          dialogs: state.dialogs,
          page_errors: state.pageErrors,
          visited_urls: state.visited,
          last_payload: state.lastPayload,
          screenshots: state.screenshots
        };

        fs.writeFileSync(findingsPath, JSON.stringify(findings, null, 2), 'utf8');

        console.log(report);
        return;
      }

      const toolResult = await runTool(page, decision.action, decision.args || {});
      state.turnResults.push({
        turn,
        model_decision: decision,
        tool_result: toolResult
      });

      messages.push({ role: 'assistant', content: rawDecision });
      messages.push({
        role: 'user',
        content:
          `TOOL_RESULT:\n${JSON.stringify(toolResult, null, 2)}\n\n` +
          `Choose the next action. If there is enough evidence, use finish.`
      });
    }

    const forced = await askTestingLLM([
      ...messages,
      {
        role: 'user',
        content:
          'Turn limit reached. Return finish JSON now with the full markdown report.'
      }
    ]);

    const finalDecision = extractJsonObject(forced);
    const report = finalDecision.report_markdown || '# Verdict\nNo report provided.';
    fs.writeFileSync(reportPath, report, 'utf8');

    const findings = {
      target_url: TARGET_URL,
      target_page: '/demo/xss-lab.html',
      finished_at: new Date().toISOString(),
      llm_model: LLM_MODEL,
      turns: state.turnResults,
      dialogs: state.dialogs,
      page_errors: state.pageErrors,
      visited_urls: state.visited,
      last_payload: state.lastPayload,
      screenshots: state.screenshots
    };

    fs.writeFileSync(findingsPath, JSON.stringify(findings, null, 2), 'utf8');
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