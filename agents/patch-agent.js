'use strict';

const fs = require('node:fs');
const path = require('node:path');

const repoRoot = process.cwd();
const agentsDir = path.join(repoRoot, 'agents');
const testingOutputDir = path.join(agentsDir, 'testing-output');

const findingsPath = path.join(testingOutputDir, 'findings.json');
const testingReportPath = path.join(testingOutputDir, 'testing-report.md');
const patchReportPath = path.join(agentsDir, 'patch-report.md');
const remediationPatchPath = path.join(agentsDir, 'remediation.patch');

const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const LLM_MODEL = process.env.LLM_MODEL || 'openai/gpt-4.1';

if (!fs.existsSync(findingsPath)) {
  throw new Error(`Missing testing findings file: ${findingsPath}`);
}

function clip(text, max = 14000) {
  const value = String(text || '');
  return value.length <= max ? value : `${value.slice(0, max)}\n...[truncated]`;
}

function readIfExists(filePath) {
  return fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
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
      for (const match of matches.slice(0, 2)) {
        const index = match.index || 0;
        const start = Math.max(0, index - 150);
        const end = Math.min(text.length, index + 300);

        findings.push({
          file: path.relative(repoRoot, file).replace(/\\/g, '/'),
          pattern: pattern.name,
          line: lineNumber(text, index),
          snippet: text.slice(start, end)
        });
      }
    }
  }

  return findings.slice(0, 25);
}

function extractJsonObject(text) {
  const cleaned = String(text || '')
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/i, '')
    .replace(/```$/i, '')
    .trim();

  const first = cleaned.indexOf('{');
  const last = cleaned.lastIndexOf('}');

  if (first === -1 || last === -1 || last <= first) {
    throw new Error(`No JSON object found in model output:\n${cleaned}`);
  }

  return JSON.parse(cleaned.slice(first, last + 1));
}

async function callGitHubModel(prompt) {
  if (!GITHUB_TOKEN) {
    throw new Error('GITHUB_TOKEN is missing');
  }

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
          content:
            'You are Secure Harbour’s patching agent. ' +
            'You must propose minimal, conservative remediation based only on supplied evidence. ' +
            'Return STRICT JSON with keys patch_report_markdown and remediation_patch. ' +
            'remediation_patch must be a unified diff patch string, or an empty string if no safe patch can be proposed.'
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
    throw new Error(`GitHub Models API error ${response.status}: ${text}`);
  }

  const parsed = JSON.parse(text);
  return parsed?.choices?.[0]?.message?.content || '';
}

function buildFallbackOutput(evidence) {
  const report = [
    '# Patch Agent Verdict',
    'No automatic code patch was applied. This job only proposes a patch for your review.',
    '',
    '# Summary',
    'The patching agent reviewed the testing findings and suspicious code patterns. Manual review is still required before any change is merged.',
    '',
    '# Key signals',
    `- Browser dialogs observed: ${evidence.findings.summary?.dialog_count || 0}`,
    `- Public payload reflections observed: ${evidence.findings.summary?.visible_payload_count || 0}`,
    `- Risky DOM sink matches found in repo: ${evidence.sinkFindings.length}`,
    '',
    '# Proposed action',
    'Review the files listed below and replace unsafe DOM insertion with text-only rendering where appropriate.',
    '',
    '# Files to inspect',
    ...evidence.sinkFindings.slice(0, 10).map((item) => `- ${item.file}:${item.line} (${item.pattern})`),
    '',
    '# Patch status',
    'No safe deterministic patch was generated in fallback mode.'
  ].join('\n');

  return {
    patch_report_markdown: report,
    remediation_patch: ''
  };
}

async function main() {
  const findings = JSON.parse(fs.readFileSync(findingsPath, 'utf8'));
  const testingReport = readIfExists(testingReportPath);
  const sinkFindings = scanCodeSinks();

  const dashboardJs = readIfExists(path.join(repoRoot, 'assets', 'dashboard.js'));
  const validationJs = readIfExists(path.join(repoRoot, 'api', 'shared', 'validation.js'));
  const contactJs = readIfExists(path.join(repoRoot, 'assets', 'contact.js'));

  const evidence = {
    findings,
    sinkFindings,
    repo_files: {
      'assets/dashboard.js': clip(dashboardJs, 6000),
      'api/shared/validation.js': clip(validationJs, 6000),
      'assets/contact.js': clip(contactJs, 4000)
    },
    prior_testing_report: clip(testingReport, 7000)
  };

  let output;

  try {
    const prompt = [
      'Create a patch proposal from this evidence.',
      'Rules:',
      '- Keep changes minimal and conservative.',
      '- Do not invent files that do not exist.',
      '- If there is not enough evidence for a safe patch, leave remediation_patch empty and explain why.',
      '- If you do propose a patch, output a unified diff.',
      '',
      'Evidence JSON:',
      clip(JSON.stringify(evidence, null, 2), 20000)
    ].join('\n');

    const modelText = await callGitHubModel(prompt);
    output = extractJsonObject(modelText);
  } catch (error) {
    output = buildFallbackOutput(evidence);
    output.patch_report_markdown += `\n\n# AI note\nModel call or parsing failed: ${String(error)}`;
  }

  fs.writeFileSync(patchReportPath, output.patch_report_markdown || '', 'utf8');
  fs.writeFileSync(remediationPatchPath, output.remediation_patch || '', 'utf8');

  console.log('Patch report written to:', patchReportPath);
  console.log('Patch file written to:', remediationPatchPath);
  console.log(output.patch_report_markdown || '');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});