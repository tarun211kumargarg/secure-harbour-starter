'use strict';

const fs = require('node:fs');
const path = require('node:path');

const repoRoot = process.cwd();
const agentsDir = path.join(repoRoot, 'agents');
const testingOutputDir = path.join(agentsDir, 'testing-output');

const findingsPath = path.join(testingOutputDir, 'findings.json');
const patchReportPath = path.join(agentsDir, 'patch-report.md');
const remediationPatchPath = path.join(agentsDir, 'remediation.patch');

if (!fs.existsSync(findingsPath)) {
  throw new Error(`Missing findings.json: ${findingsPath}`);
}

const rootFile = path.join(repoRoot, 'xss-lab.html');
const demoFile = path.join(repoRoot, 'demo', 'xss-lab.html');
const targetFilePath = fs.existsSync(rootFile) ? rootFile : demoFile;

if (!fs.existsSync(targetFilePath)) {
  throw new Error(`Missing target file: ${targetFilePath}`);
}

const findings = JSON.parse(fs.readFileSync(findingsPath, 'utf8'));
const original = fs.readFileSync(targetFilePath, 'utf8');

const vulnerableLine = 'preview.innerHTML = messageInput.value;';
const safeLine = 'preview.textContent = messageInput.value;';

let patchApplied = false;
let patched = original;

if (original.includes(vulnerableLine)) {
  patched = original.replace(vulnerableLine, safeLine);
  patchApplied = true;
}

const relativeTarget = path.relative(repoRoot, targetFilePath).replace(/\\/g, '/');

const patchReport = [
  '# Patch Agent Verdict',
  patchApplied
    ? 'A direct DOM-XSS sink was found and patched.'
    : 'No matching vulnerable sink was found, so no patch was applied.',
  '',
  '# Evidence from testing agent',
  `- Target page: ${findings.target_page || '/xss-lab.html'}`,
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
    : '- Review the file manually.'
].join('\n');

const remediationPatch = patchApplied
  ? [
      `--- a/${relativeTarget}`,
      `+++ b/${relativeTarget}`,
      '@@',
      `-      ${vulnerableLine}`,
      `+      ${safeLine}`
    ].join('\n')
  : '';

fs.writeFileSync(patchReportPath, patchReport, 'utf8');
fs.writeFileSync(remediationPatchPath, remediationPatch, 'utf8');

if (patchApplied) {
  fs.writeFileSync(targetFilePath, patched, 'utf8');
}

console.log(patchReport);