function compactFinding(finding) {
  return {
    severity: finding.severity,
    owasp: finding.owasp,
    title: finding.title,
    path: finding.path,
    line: finding.line,
    confidence: finding.confidence,
    recommendation: finding.recommendation
  };
}

function topEntries(counts, limit = 3) {
  return Object.entries(counts || {})
    .filter(([, count]) => count > 0)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit);
}

function uniqueValues(values, limit = 3) {
  return Array.from(new Set(values.filter(Boolean))).slice(0, limit);
}

function sentenceJoin(parts) {
  return parts.filter(Boolean).join(' ');
}

function buildLocalReviewerSummary(scanSummary, findings) {
  if (!findings.length) {
    return 'The local OWASP triage engine did not identify source-code risk indicators within the configured demo limits. This should still be treated as a lightweight demo result; production assurance should add dependency scanning, secrets scanning, data-flow analysis, authentication testing, and manual validation.';
  }

  const selected = findings.slice(0, 15).map(compactFinding);
  const high = scanSummary.severityCounts.High || 0;
  const critical = scanSummary.severityCounts.Critical || 0;
  const medium = scanSummary.severityCounts.Medium || 0;
  const topCategories = topEntries(scanSummary.owaspCounts, 3)
    .map(([category, count]) => `${category} (${count})`)
    .join(', ');
  const highConfidence = selected.filter((finding) => finding.confidence === 'High');
  const priorityFindings = selected.filter((finding) => ['Critical', 'High'].includes(finding.severity));
  const priorityFiles = uniqueValues(priorityFindings.map((finding) => finding.path), 3).join(', ');
  const immediateThemes = uniqueValues(priorityFindings.map((finding) => finding.title), 3).join(', ');
  const validationHint = highConfidence.length
    ? `${highConfidence.length} high-confidence indicator(s) should be validated first.`
    : 'Validate the highest-severity indicators first because rule matches can include false positives.';

  return sentenceJoin([
    `Local OWASP triage identified ${scanSummary.totalFindings} potential issue(s) with an overall ${scanSummary.riskLevel} risk rating.`,
    `Severity mix: ${critical} critical, ${high} high, and ${medium} medium finding(s).`,
    topCategories ? `Most represented OWASP areas: ${topCategories}.` : '',
    priorityFiles ? `Prioritize review in: ${priorityFiles}.` : '',
    immediateThemes ? `Immediate remediation themes: ${immediateThemes}.` : '',
    validationHint,
    'No external AI or paid model API was called; this summary is generated locally from deterministic scan results.'
  ]);
}

async function generateAiSummary({ scanSummary, findings }) {
  const safeFindings = Array.isArray(findings) ? findings : [];
  return {
    enabled: true,
    provider: 'local-owasp-triage',
    model: 'deterministic-v1',
    paidTokenRequired: false,
    externalApiCalls: false,
    text: buildLocalReviewerSummary(scanSummary, safeFindings)
  };
}

module.exports = {
  generateAiSummary,
  buildLocalReviewerSummary
};
