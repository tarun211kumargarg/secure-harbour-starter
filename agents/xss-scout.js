const fs = require('node:fs');
const path = require('node:path');

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const TARGET_URL = process.env.TARGET_URL;
const OPENAI_MODEL = process.env.OPENAI_MODEL || 'gpt-5.4';
const ALLOW_FORM_POST = String(process.env.ALLOW_FORM_POST || 'false').toLowerCase() === 'true';
const MAX_AGENT_TURNS = Number(process.env.MAX_AGENT_TURNS || '6');

if (!OPENAI_API_KEY) {
  throw new Error('OPENAI_API_KEY is missing');
}

if (!TARGET_URL) {
  throw new Error('TARGET_URL is missing');
}

const repoRoot = process.cwd();
const reportPath = path.join(repoRoot, 'agents', 'xss-report.md');
const targetBase = new URL(TARGET_URL);
const targetOrigin = targetBase.origin;

const INTERESTING_HEADERS = [
  'content-type',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'strict-transport-security',
  'referrer-policy',
  'permissions-policy'
];

function resolveSameOriginUrl(rawUrl) {
  const url = new URL(rawUrl, targetBase);
  if (url.origin !== targetOrigin) {
    throw new Error(`Cross-origin blocked: ${url.toString()}`);
  }
  return url;
}

async function fetchText(url, options = {}) {
  const headers = {
    'user-agent': 'SecureHarbour-XSS-Agent/1.0',
    ...(options.headers || {})
  };

  const res = await fetch(url, {
    ...options,
    headers,
    redirect: 'follow'
  });

  const body = await res.text();
  const selectedHeaders = {};

  for (const headerName of INTERESTING_HEADERS) {
    selectedHeaders[headerName] = res.headers.get(headerName);
  }

  return {
    final_url: res.url,
    status: res.status,
    headers: selectedHeaders,
    body
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
    if (['.js', '.cjs', '.mjs', '.ts', '.tsx', '.html'].includes(ext)) {
      files.push(fullPath);
    }
  }

  return files;
}

function clip(text, max = 9000) {
  return text.length <= max ? text : `${text.slice(0, max)}\n...[truncated]`;
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
        const snippetStart = Math.max(0, index - 120);
        const snippetEnd = Math.min(text.length, index + 220);

        findings.push({
          file: path.relative(repoRoot, file).replace(/\\/g, '/'),
          pattern: pattern.name,
          line: lineNumber(text, index),
          snippet: text.slice(snippetStart, snippetEnd)
        });
      }
    }
  }

  return {
    total_findings: findings.length,
    findings: findings.slice(0, 40)
  };
}

function extractAttr(tag, attrName) {
  const regex = new RegExp(`${attrName}\\s*=\\s*["']([^"']+)["']`, 'i');
  const match = tag.match(regex);
  return match ? match[1] : null;
}

function extractFormsFromHtml(html) {
  const forms = [];
  const formMatches = [...html.matchAll(/<form\b[\s\S]*?<\/form>/gi)];

  for (const formMatch of formMatches.slice(0, 10)) {
    const formHtml = formMatch[0];
    const openTagMatch = formHtml.match(/<form\b[^>]*>/i);
    const openTag = openTagMatch ? openTagMatch[0] : '<form>';

    const fields = [];
    const fieldMatches = [
      ...formHtml.matchAll(/<(input|textarea|select)\b[^>]*>/gi)
    ];

    for (const fieldMatch of fieldMatches.slice(0, 30)) {
      const tag = fieldMatch[0];
      fields.push({
        tag: fieldMatch[1].toLowerCase(),
        name: extractAttr(tag, 'name'),
        type: extractAttr(tag, 'type') || (fieldMatch[1].toLowerCase() === 'textarea' ? 'textarea' : null),
        id: extractAttr(tag, 'id')
      });
    }

    forms.push({
      action: extractAttr(openTag, 'action'),
      method: (extractAttr(openTag, 'method') || 'GET').toUpperCase(),
      fields
    });
  }

  return forms;
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

async function postJsonProbe(args) {
  if (!ALLOW_FORM_POST) {
    return {
      blocked: true,
      reason: 'ALLOW_FORM_POST is false'
    };
  }

  const url = resolveSameOriginUrl(args.url).toString();
  const jsonBody = args.json_body || {};

  const res = await fetchText(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json'
    },
    body: JSON.stringify(jsonBody)
  });

  return {
    final_url: res.final_url,
    status: res.status,
    headers: res.headers,
    body_excerpt: clip(res.body, 5000)
  };
}

async function runTool(name, args) {
  switch (name) {
    case 'fetch_page': {
      const url = resolveSameOriginUrl(args.url).toString();
      const res = await fetchText(url);
      return {
        final_url: res.final_url,
        status: res.status,
        headers: res.headers,
        body_excerpt: clip(res.body, 8000)
      };
    }

    case 'extract_forms': {
      const url = resolveSameOriginUrl(args.url).toString();
      const res = await fetchText(url);
      return {
        final_url: res.final_url,
        status: res.status,
        forms: extractFormsFromHtml(res.body)
      };
    }

    case 'scan_code_sinks':
      return scanCodeSinks();

    case 'read_file_snippet':
      return readFileSnippet(args.file_path, args.search_term || '');

    case 'post_json_probe':
      return postJsonProbe(args);

    default:
      return {
        error: `Unknown tool: ${name}`
      };
  }
}

const tools = [
  {
    type: 'function',
    name: 'fetch_page',
    description: 'Fetch a same-origin page and return status, selected security headers, and an HTML excerpt.',
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string' }
      },
      required: ['url'],
      additionalProperties: false
    }
  },
  {
    type: 'function',
    name: 'extract_forms',
    description: 'Fetch a same-origin page and list forms, methods, actions, and fields.',
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string' }
      },
      required: ['url'],
      additionalProperties: false
    }
  },
  {
    type: 'function',
    name: 'scan_code_sinks',
    description: 'Scan the checked-out repository for common DOM XSS sinks and dangerous rendering patterns.',
    parameters: {
      type: 'object',
      properties: {},
      additionalProperties: false
    }
  },
  {
    type: 'function',
    name: 'read_file_snippet',
    description: 'Read a specific repository file and return a snippet around a search term.',
    parameters: {
      type: 'object',
      properties: {
        file_path: { type: 'string' },
        search_term: { type: 'string' }
      },
      required: ['file_path'],
      additionalProperties: false
    }
  },
  {
    type: 'function',
    name: 'post_json_probe',
    description: 'Send one controlled JSON POST probe to a same-origin endpoint. Use only if active probing is enabled.',
    parameters: {
      type: 'object',
      properties: {
        url: { type: 'string' },
        json_body: { type: 'object' }
      },
      required: ['url', 'json_body'],
      additionalProperties: false
    }
  }
];

async function createResponse(input, previousResponseId) {
  const body = {
    model: OPENAI_MODEL,
    tools,
    input
  };

  if (previousResponseId) {
    body.previous_response_id = previousResponseId;
  }

  const res = await fetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${OPENAI_API_KEY}`
    },
    body: JSON.stringify(body)
  });

  const text = await res.text();

  if (!res.ok) {
    throw new Error(`OpenAI API error ${res.status}: ${text}`);
  }

  return JSON.parse(text);
}

function getFunctionCalls(response) {
  return (response.output || []).filter((item) => item.type === 'function_call');
}

function extractFinalText(response) {
  if (typeof response.output_text === 'string' && response.output_text.trim()) {
    return response.output_text;
  }

  const chunks = [];

  for (const item of response.output || []) {
    if (item.type === 'message' && Array.isArray(item.content)) {
      for (const contentItem of item.content) {
        if (contentItem.type === 'output_text' && typeof contentItem.text === 'string') {
          chunks.push(contentItem.text);
        } else if (contentItem.type === 'text' && typeof contentItem.text === 'string') {
          chunks.push(contentItem.text);
        }
      }
    }
  }

  return chunks.join('\n\n').trim() || JSON.stringify(response, null, 2);
}

async function main() {
  const kickoffPrompt = `
You are Secure Harbour's autonomous XSS testing agent.

Rules:
- Scope is LIMITED to the same-origin target: ${TARGET_URL}
- Scope also includes the checked-out source repository for this target
- Do not inspect or call any off-origin URL
- Use tools autonomously
- Maximum tool rounds: ${MAX_AGENT_TURNS}
- Active POST probing is ${ALLOW_FORM_POST ? 'ENABLED' : 'DISABLED'}
- If active POST probing is disabled, do not use post_json_probe unless you are explaining what would be tested next

Mission:
1. Identify likely reflected and stored XSS areas
2. Inspect public pages first
3. Prioritize form pages, client-side rendering code, admin/dashboard rendering, and risky DOM sinks
4. Use scan_code_sinks and read_file_snippet when you need code evidence
5. If you see likely API routes in HTML or code, mention them
6. Finish with markdown sections exactly in this order:

# Verdict
# Pages checked
# Likely XSS areas
# Evidence
# Recommended fixes
# Next probes
`;

  let response = await createResponse(kickoffPrompt);

  for (let turn = 0; turn < MAX_AGENT_TURNS; turn += 1) {
    const functionCalls = getFunctionCalls(response);

    if (!functionCalls.length) {
      break;
    }

    const toolOutputs = [];

    for (const call of functionCalls) {
      let args = {};
      try {
        args = call.arguments ? JSON.parse(call.arguments) : {};
      } catch (error) {
        args = {
          parse_error: String(error),
          raw_arguments: call.arguments || ''
        };
      }

      console.log(`\n[tool-call] ${call.name}`);
      console.log(JSON.stringify(args, null, 2));

      const result = await runTool(call.name, args);

      toolOutputs.push({
        type: 'function_call_output',
        call_id: call.call_id,
        output: JSON.stringify(result)
      });
    }

    response = await createResponse(toolOutputs, response.id);
  }

  if (getFunctionCalls(response).length) {
    response = await createResponse(
      'Stop using tools now and provide the final markdown report only.',
      response.id
    );
  }

  const finalReport = extractFinalText(response);

  fs.writeFileSync(reportPath, finalReport, 'utf8');

  console.log('\n===== FINAL XSS AGENT REPORT =====\n');
  console.log(finalReport);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});