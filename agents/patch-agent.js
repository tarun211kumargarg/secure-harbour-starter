'use strict';

const fs = require('node:fs');
const path = require('node:path');

const repoRoot = process.cwd();
const agentsDir = path.join(repoRoot, 'agents');
const testingOutputDir = path.join(agentsDir, 'testing-output');

const findingsPath = path.join(testingOutputDir, 'findings.json');
const patchReportPath = path.join(agentsDir, 'patch-report.md');
const remediationPatchPath = path.join(agentsDir, 'remediation.patch');
const targetFilePath = path.join(repoRoot, process.env.LAB_SOURCE_FILE || 'agent-fixtures/xss-lab.html');
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const LLM_MODEL = process.env.LLM_MODEL || 'openai/gpt-4.1';

if (!fs.existsSync(findingsPath)) {
  throw new Error(`Missing findings.json: ${findingsPath}`);
}

if (!fs.existsSync(targetFilePath)) {
  throw new Error(`Missing target file: ${targetFilePath}`);
}

const findings = JSON.parse(fs.readFileSync(findingsPath, 'utf8'));
const original = fs.readFileSync(targetFilePath, 'utf8');
const relativeTarget = path.relative(repoRoot, targetFilePath).replace(/\\/g, '/');

const vulnerableLine = 'preview.innerHTML = messageInput.value;';
const safeLine = 'preview.textContent = messageInput.value;';

let patchApplied = false;
let patched = original;

if (original.includes(vulnerableLine)) {
  patched = original.replace(vulnerableLine, safeLine);
  patchApplied = true;
}

const remediationPatch = patchApplied
  ? [
      `--- a/${relativeTarget}`,
      `+++ b/${relativeTarget}`,
      '@@',
      `-      ${vulnerableLine}`,
      `+      ${safeLine}`
    ].join('\n')
  : '';

function fallbackReport() {
  return [
    '# Patch Agent Verdict',
    patchApplied
      ? 'A direct DOM-XSS sink was found and patched.'
      : 'No matching vulnerable sink was found, so no patch was applied.',
    '',
    '# Evidence from testing agent',
    `- Target page: ${findings.target_page || '/xss-lab.html'}`,
    `- Source file: ${findings.source_file || relativeTarget}`,
    `- Payload tested: ${findings.last_payload || 'unknown'}`,
    `- Dialogs seen: ${findings.dialogs?.length || 0}`,
    '',
    '# File checked',
    `- ${relativeTarget}`,
    '',
    '# Change made',
    patchApplied
      ? `- Replaced \`${vulnerableLine}\` with \`${safeLine}\``
      : '- No change',
    '',
    '# Recommendation',
    patchApplied
      ? '- Re-run the testing agent to confirm the payload no longer executes.'
      : '- Review the fixture manually.'
  ].join('\n');
}

async function generatePatchReportWithLLM() {
  if (!GITHUB_TOKEN) return fallbackReport();

  const prompt = [
    'You are Secure Harbour\'s patching agent.',
    'Write a concise markdown report based only on the supplied evidence.',
    'Do not invent facts.',
    'Use these exact section headers in order:',
    '# Patch Agent Verdict',
    '# Evidence from testing agent',
    '# File checked',
    '# Change made',
    '# Recommendation',
    '',
    'Evidence JSON:',
    JSON.stringify({
      findings,
      targetFile: relativeTarget,
      patchApplied,
      vulnerableLine,
      safeLine,
      remediationPatch
    }, null, 2)
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
            content: 'You create short factual remediation summaries from supplied evidence.'
          },
          {
            role: 'user',
            content: prompt
          }
        ]
      })
    });

    const text = await response.text();
    if (!response.ok) return `${fallbackReport()}\n\n## AI note\nGitHub Models call failed: ${text}`;

    const parsed = JSON.parse(text);
    const content = parsed?.choices?.[0]?.message?.content;
    return content || fallbackReport();
  } catch (error) {
    return `${fallbackReport()}\n\n## AI note\nGitHub Models request failed: ${String(error)}`;
  }
}

async function main() {
  const patchReport = await generatePatchReportWithLLM();
  fs.writeFileSync(patchReportPath, patchReport, 'utf8');
  fs.writeFileSync(remediationPatchPath, remediationPatch, 'utf8');

  if (patchApplied) {
    fs.writeFileSync(targetFilePath, patched, 'utf8');
  }

  console.log(patchReport);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
