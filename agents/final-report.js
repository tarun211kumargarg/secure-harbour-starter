'use strict';

const fs = require('node:fs');
const path = require('node:path');

const repoRoot = process.cwd();
const agentsDir = path.join(repoRoot, 'agents');

const testingReportPath = path.join(agentsDir, 'testing-output', 'testing-report.md');
const findingsPath = path.join(agentsDir, 'testing-output', 'findings.json');
const patchReportPath = path.join(agentsDir, 'patch-output', 'patch-report.md');
const remediationPatchPath = path.join(agentsDir, 'patch-output', 'remediation.patch');
const finalReportPath = path.join(agentsDir, 'final-report.md');

function readIfExists(filePath) {
  return fs.existsSync(filePath) ? fs.readFileSync(filePath, 'utf8') : '';
}

const testingReport = readIfExists(testingReportPath);
const patchReport = readIfExists(patchReportPath);
const remediationPatch = readIfExists(remediationPatchPath);

let findingsSummary = '';
if (fs.existsSync(findingsPath)) {
  try {
    const findings = JSON.parse(fs.readFileSync(findingsPath, 'utf8'));
    findingsSummary = [
      '- Target URL: ' + (findings.target_url || 'unknown'),
      '- Target page: ' + (findings.target_page || 'unknown'),
      '- Lab file: ' + (findings.lab_file || 'unknown'),
      '- Browser dialogs observed: ' + ((findings.dialogs || []).length),
      '- Turns executed: ' + ((findings.turns || []).length)
    ].join('\n');
  } catch {
    findingsSummary = '- Could not parse findings.json';
  }
}

const finalReport = [
  '# Secure Harbour XSS Two-Agent Final Report',
  '',
  '## Testing summary',
  findingsSummary || '- No structured findings summary available.',
  '',
  '## Testing agent report',
  testingReport || 'No testing report was produced.',
  '',
  '## Patching agent report',
  patchReport || 'No patch report was produced.',
  '',
  '## Proposed remediation patch',
  remediationPatch
    ? ['```diff', remediationPatch, '```'].join('\n')
    : 'No patch was proposed.',
  '',
  '## Decision',
  'Review the proposed patch manually before applying it to any deployed environment.'
].join('\n');

fs.writeFileSync(finalReportPath, finalReport, 'utf8');
console.log(finalReport);
