'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createChatCompletion, getAssistantText } = require('./llm-client');

const TARGET_URL = process.env.TARGET_URL;
const MAX_TURNS = Number(process.env.MAX_AGENT_TURNS || '6');

if (!TARGET_URL) {
  throw new Error('TARGET_URL is missing');
}

const repoRoot = process.cwd();
const reportPath = path.join(repoRoot, 'agents', 'xss-report.md');
const targetBase = new URL(TARGET_URL);
const targetOrigin = targetBase.origin;

function clip(text, max = 7000) {
  return text.length <= max ? text : `${text.slice(0, max)}\n...[truncated]`;
}

function resolveSameOriginUrl(rawUrl) {
  const url = new URL(rawUrl, targetBase);
  if (url.origin !== targetOrigin) {
    throw new Error(`Cross-origin blocked: ${url.toString()}`);
  }
  return url;
}

async function fetchPage(url) {
  const finalUrl = resolveSameOriginUrl(url).toString();

  const res = await fetch(finalUrl, {
    headers: {
      'User-Agent': 'SecureHarbour-XSS-Scout/1.0'
    },
    redirect: 'follow'
  });

  const html = await res.text();

  return {
    url: res.url,
    status: res.status,
    headers: {
      'content-security-policy': res.headers.get('content-security-policy'),
      'x-frame-options': res.headers.get('x-frame-options'),
      'x-content-type-options': res.headers.get('x-content-type-options'),
      'strict-transport-security': res.headers.get('strict-transport-security'),
      'referrer-policy': res.headers.get('referrer-policy')
    },
    html_excerpt: clip(html)
  };
}

function extractAttr(tag, attrName) {
  const regex = new RegExp(`${attrName}\\s*=\\s*["']([^"']+)["']`, 'i');
  const match = tag.match(regex);
  return match ? match[1] : null;
}

async function extractForms(url) {
  const page = await fetchPage(url);
  const html = page.html_excerpt.includes('...[truncated]')
    ? (await (await fetch(resolveSameOriginUrl(url).toString())).text())
    : page.html_excerpt;

  const forms = [];
  const formMatches = [...html.matchAll(/<form\b[\s\S]*?<\/form>/gi)];

  for (const formMatch of formMatches.slice(0, 10)) {
    const formHtml = formMatch[0];
    const openTagMatch = formHtml.match(/<form\b[^>]*>/i);
    const openTag = openTagMatch ? openTagMatch[0] : '<form>';

    const fields = [];
    const fieldMatches = [...formHtml.matchAll(/<(input|textarea|select)\b[^>]*>/gi)];

    for (const fieldMatch of fieldMatches.slice(0, 30)) {
      const tag = fieldMatch[0];
      const kind = fieldMatch[1].toLowerCase();
      fields.push({
        tag: kind,
        name: extractAttr(tag, 'name'),
        type: extractAttr(tag, 'type') || (kind === 'textarea' ? 'textarea' : null),
        id: extractAttr(tag, 'id')
      });
    }

    forms.push({
      action: extractAttr(openTag, 'action'),
      method: (extractAttr(openTag, 'method') || 'GET').toUpperCase(),
      fields
    });
  }

  return {
    url: page.url,
    status: page.status,
    forms
  };
}

function lineNumber(text, index) {
  let line = 1;
  for (let i = 0; i < index; i += 1) {
    if (text.charCodeAt(i) === 10) line += 1;
  }
  return line;
}

function walk(dir, files = []) {
  const ignoreDirs = new Set(['.git', 'node_modules']);

  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (ignoreDirs.has(entry.name)) continue;

    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      walk(fullPath, files);
      continue;
    }

    const ext = path.extname(entry.name).toLowerCase();
    if (['.js', '.cjs', '.mjs', '.html', '.ts', '.tsx'].includes(ext)) {
      files.push(fullPath);
    }
  }

  return files;
}

function scanCodeSinks() {
  const patterns = [
    { name: 'innerHTML assignment', regex: /\.innerHTML\s*=/g },
    { name: 'outerHTML assignment', regex: /\.outerHTML\s*=/g },
    { name: 'insertAdjacentHTML', regex: /insertAdjacentHTML\s*\(/g },
    { name: 'document.write', regex: /document\.write\s*\(/g },
    { name: 'eval', regex: /\beval\s*\(/g },
    { name: 'Function constructor', regex: /\bnew\s+Function\s*\(/g }
  ];

  const findings = [];

  for (const file of walk(repoRoot)) {
    const text = fs.readFileSync(file, 'utf8');

    for (const pattern of patterns) {
      const matches = [...text.matchAll(pattern.regex)];
      for (const match of matches.slice(0, 3)) {
        const index = match.index || 0;
        const start = Math.max(0, index - 120);
        const end = Math.min(text.length, index + 220);

        findings.push({
          file: path.relative(repoRoot, file).replace(/\\/g, '/'),
          pattern: pattern.name,
          line: lineNumber(text, index),
          snippet: text.slice(start, end)
        });
      }
    }
  }

  return {
    total_findings: findings.length,
    findings: findings.slice(0, 30)
  };
}

function readFileSnippet(filePath, searchTerm = '') {
  const fullPath = path.normalize(path.join(repoRoot, filePath));

  if (!fullPath.startsWith(repoRoot)) {
    throw new Error('Path escapes repository root');
  }

  if (!fs.existsSync(fullPath)) {
    throw new Error(`File not found: ${filePath}`);
  }

  const text = fs.readFileSync(fullPath, 'utf8');
  let index = 0;

  if (searchTerm) {
    const found = text.indexOf(searchTerm);
    index = found >= 0 ? found : 0;
  }

  const start = Math.max(0, index - 400);
  const end = Math.min(text.length, index + 1400);

  return {
    file: filePath,
    snippet: text.slice(start, end)
  };
}

const toolMap = {
  fetch_page: async (args) => fetchPage(args.url),
  extract_forms: async (args) => extractForms(args.url),
  scan_code_sinks: async () => scanCodeSinks(),
  read_file_snippet: async (args) => readFileSnippet(args.file_path, args.search_term || '')
};

function extractJson(text) {
  const cleaned = text.trim().replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/```$/i, '').trim();
  const first = cleaned.indexOf('{');
  const last = cleaned.lastIndexOf('}');
  if (first === -1 || last === -1 || last <= first) {
    throw new Error(`Could not find JSON object in model response: ${cleaned}`);
  }
  return JSON.parse(cleaned.slice(first, last + 1));
}

async function askModel(messages) {
  const response = await createChatCompletion(messages);
  const text = getAssistantText(response);
  if (!text) {
    throw new Error('Model returned empty content');
  }
  return text;
}

async function main() {
  const messages = [
    {
      role: 'system',
      content:
        `You are Secure Harbour's autonomous XSS testing agent.\n` +
        `Scope is limited to the same-origin target ${TARGET_URL} and the checked-out repository.\n` +
        `You must choose exactly one action per turn from this list:\n` +
        `1. fetch_page { "url": "..." }\n` +
        `2. extract_forms { "url": "..." }\n` +
        `3. scan_code_sinks { }\n` +
        `4. read_file_snippet { "file_path": "...", "search_term": "optional" }\n` +
        `5. finish { "report_markdown": "..." }\n\n` +
        `Reply in STRICT JSON only, with this shape:\n` +
        `{"action":"fetch_page|extract_forms|scan_code_sinks|read_file_snippet|finish","args":{},"reason":"...","report_markdown":"...only for finish"}\n\n` +
        `Priorities:\n` +
        `- inspect public pages first\n` +
        `- identify user input points\n` +
        `- identify dangerous DOM sinks\n` +
        `- connect user-controlled inputs to unsafe rendering paths\n` +
        `- finish with a markdown report using these sections in order:\n` +
        `# Verdict\n# Pages checked\n# Likely XSS areas\n# Evidence\n# Recommended fixes\n# Next probes`
    },
    {
      role: 'user',
      content:
        `Start by assessing this site for reflected or stored XSS risk.\n` +
        `Target URL: ${TARGET_URL}\n` +
        `Repository root is available through tools.\n` +
        `You may take up to ${MAX_TURNS} tool turns before finishing.`
    }
  ];

  for (let turn = 1; turn <= MAX_TURNS; turn += 1) {
    const reply = await askModel(messages);
    console.log(`\n=== MODEL TURN ${turn} ===\n${reply}\n`);

    let decision;
    try {
      decision = extractJson(reply);
    } catch (err) {
      messages.push({
        role: 'assistant',
        content: reply
      });
      messages.push({
        role: 'user',
        content:
          `Your last reply was not valid JSON. Reply again in STRICT JSON with keys action, args, reason, report_markdown.`
      });
      continue;
    }

    const action = decision.action;
    const args = decision.args || {};

    if (action === 'finish') {
      const report = decision.report_markdown || '# Verdict\nNo report produced.';
      fs.writeFileSync(reportPath, report, 'utf8');
      console.log('\n===== FINAL XSS AGENT REPORT =====\n');
      console.log(report);
      return;
    }

    if (!toolMap[action]) {
      messages.push({
        role: 'assistant',
        content: reply
      });
      messages.push({
        role: 'user',
        content: `The action "${action}" is not allowed. Choose one of: ${Object.keys(toolMap).join(', ')}, finish.`
      });
      continue;
    }

    let toolResult;
    try {
      toolResult = await toolMap[action](args);
    } catch (err) {
      toolResult = { error: String(err) };
    }

    messages.push({
      role: 'assistant',
      content: reply
    });
    messages.push({
      role: 'user',
      content:
        `TOOL_RESULT for ${action}:\n` +
        `${JSON.stringify(toolResult, null, 2)}\n\n` +
        `Decide the next best action. If you have enough evidence, use finish.`
    });
  }

  const finalReply = await askModel([
    ...messages,
    {
      role: 'user',
      content:
        `You have reached the turn limit. Do not ask for more tools. Reply with finish JSON now and include the full markdown report in report_markdown.`
    }
  ]);

  const finalDecision = extractJson(finalReply);
  const report = finalDecision.report_markdown || '# Verdict\nNo report produced.';
  fs.writeFileSync(reportPath, report, 'utf8');

  console.log('\n===== FINAL XSS AGENT REPORT =====\n');
  console.log(report);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});