import fs from 'node:fs';
import path from 'node:path';
import OpenAI from 'openai';

const baseUrl = process.env.TARGET_URL;
const model = process.env.OPENAI_MODEL || 'gpt-5';

if (!baseUrl) {
  throw new Error('TARGET_URL is missing');
}

if (!process.env.OPENAI_API_KEY) {
  throw new Error('OPENAI_API_KEY is missing');
}

const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

const ROOT = process.cwd();
const EXTENSIONS = new Set(['.html', '.js', '.mjs', '.cjs']);
const IGNORE_DIRS = new Set(['node_modules', '.git']);

function walk(dir, files = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (IGNORE_DIRS.has(entry.name)) continue;

    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      walk(fullPath, files);
    } else if (EXTENSIONS.has(path.extname(entry.name))) {
      files.push(fullPath);
    }
  }
  return files;
}

function scanDangerousSinks() {
  const patterns = [
    { name: 'innerHTML', regex: /\.innerHTML\s*=/g },
    { name: 'outerHTML', regex: /\.outerHTML\s*=/g },
    { name: 'insertAdjacentHTML', regex: /insertAdjacentHTML\s*\(/g },
    { name: 'document.write', regex: /document\.write\s*\(/g },
    { name: 'eval', regex: /\beval\s*\(/g }
  ];

  const findings = [];

  for (const file of walk(ROOT)) {
    const text = fs.readFileSync(file, 'utf8');

    for (const pattern of patterns) {
      const matches = [...text.matchAll(pattern.regex)];
      for (const match of matches.slice(0, 5)) {
        findings.push({
          file: path.relative(ROOT, file),
          pattern: pattern.name,
          position: match.index
        });
      }
    }
  }

  return findings;
}

async function fetchHeaders(url) {
  const res = await fetch(url, { redirect: 'follow' });

  const wantedHeaders = [
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
    'strict-transport-security'
  ];

  const headers = {};
  for (const key of wantedHeaders) {
    headers[key] = res.headers.get(key);
  }

  return {
    finalUrl: res.url,
    status: res.status,
    headers
  };
}

async function fetchText(url) {
  const res = await fetch(url, { redirect: 'follow' });
  return await res.text();
}

function clip(text, max = 12000) {
  return text.length <= max ? text : text.slice(0, max);
}

async function main() {
  const domFindings = scanDangerousSinks();
  const siteHeaders = await fetchHeaders(baseUrl);
  const contactHtml = await fetchText(new URL('/contact', baseUrl).toString());

  const prompt = `
You are reviewing ONLY my own website for XSS risk.

Website URL:
${baseUrl}

Evidence 1: dangerous DOM sink scan
${JSON.stringify(domFindings, null, 2)}

Evidence 2: site response headers
${JSON.stringify(siteHeaders, null, 2)}

Evidence 3: contact page HTML excerpt
${clip(contactHtml)}

Return STRICT JSON with exactly these keys:
{
  "risk_level": "low|medium|high",
  "likely_xss_areas": ["..."],
  "recommended_next_tests": ["..."],
  "code_fixes": ["..."],
  "final_verdict": "pass|review|fail",
  "summary": "..."
}
`;

  const response = await client.responses.create({
    model,
    input: prompt
  });

  fs.writeFileSync('xss-report.txt', response.output_text, 'utf8');
  console.log(response.output_text);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});