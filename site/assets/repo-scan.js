const repoScanForm = document.querySelector('[data-repo-scan-form]');
const scanNotice = document.querySelector('[data-scan-notice]');
const resultSection = document.querySelector('[data-scan-result]');
const resultRepo = document.querySelector('[data-result-repo]');
const resultRisk = document.querySelector('[data-result-risk]');
const resultStats = document.querySelector('[data-result-stats]');
const resultAi = document.querySelector('[data-result-ai]');
const resultRemediation = document.querySelector('[data-result-remediation]');
const resultNotes = document.querySelector('[data-result-notes]');
const resultFindings = document.querySelector('[data-result-findings]');

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function showScanNotice(message, type) {
  if (!scanNotice) return;
  scanNotice.textContent = message;
  scanNotice.className = `notice show ${type}`;
}

function severityClass(value) {
  return String(value || 'Low').replace(/[^A-Za-z]/g, '');
}

function renderStat(label, value) {
  return `
    <div class="scan-stat">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
    </div>
  `;
}

function renderFinding(finding) {
  return `
    <article class="finding-card finding-${severityClass(finding.severity)}">
      <div class="finding-topline">
        <span class="severity-badge severity-${severityClass(finding.severity)}">${escapeHtml(finding.severity)}</span>
        <strong>${escapeHtml(finding.title)}</strong>
      </div>
      <p class="meta">${escapeHtml(finding.owasp)} | ${escapeHtml(finding.path)}:${escapeHtml(finding.line)} | Confidence: ${escapeHtml(finding.confidence)} | Source: ${escapeHtml(finding.source || 'ai')}</p>
      ${finding.evidence ? `<div class="code-evidence">${escapeHtml(finding.evidence)}</div>` : ''}
      <p class="helper-text"><strong>Recommended action:</strong> ${escapeHtml(finding.recommendation)}</p>
    </article>
  `;
}

function renderSimpleList(items, label) {
  if (!Array.isArray(items) || !items.length) return '';
  return `
    <div class="ai-list-block">
      <strong>${escapeHtml(label)}</strong>
      <ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>
    </div>
  `;
}

function renderResult(result) {
  const summary = result.scanSummary || {};
  const repo = result.repo || {};
  const tree = result.scanTree || {};
  const counts = summary.severityCounts || {};
  const findings = Array.isArray(result.findings) ? result.findings : [];
  const ai = result.aiSummary || {};

  resultSection.hidden = false;
  resultRepo.textContent = `${repo.fullName || 'Repository'} scan complete`;
  resultRisk.textContent = `${summary.riskLevel || 'Unknown'} risk`;
  resultRisk.className = `risk-badge risk-${severityClass(summary.riskLevel || 'Low')}`;
  resultStats.innerHTML = [
    renderStat('AI findings', summary.totalFindings || 0),
    renderStat('High / Medium', `${counts.High || 0} / ${counts.Medium || 0}`),
    renderStat('Files analyzed', summary.analyzedFiles || tree.analyzedFiles || 0),
    renderStat('AI files reviewed', summary.filesSentToAi || 0),
    renderStat('Rule signals', summary.ruleSignals || 0),
    renderStat('Engine', summary.engine || 'AI backend scan')
  ].join('');

  resultAi.textContent = ai.text || 'AI scan completed. Review findings and validate before remediation.';
  resultRemediation.innerHTML = renderSimpleList(ai.remediationPlan, 'Priority remediation plan');
  resultNotes.innerHTML = renderSimpleList(ai.reviewNotes, 'Review notes');

  if (!findings.length) {
    resultFindings.innerHTML = '<div class="empty-state">The backend AI scanner did not identify OWASP Top 10 source-code indicators within the demo scan limits.</div>';
  } else {
    resultFindings.innerHTML = findings.slice(0, 12).map(renderFinding).join('');
  }

  resultSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

async function submitRepoScan(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const submitButton = form.querySelector('button[type="submit"]');
  const formData = new FormData(form);
  const payload = {
    repoUrl: String(formData.get('repoUrl') || '').trim(),
    focus: String(formData.get('focus') || '').trim(),
    website: String(formData.get('website') || '').trim()
  };

  if (payload.website) {
    showScanNotice('The scan request could not be submitted.', 'error');
    return;
  }

  submitButton.disabled = true;
  submitButton.textContent = 'AI scanning...';
  showScanNotice('Backend AI scan started. Secure Harbour is fetching selected source files and reviewing OWASP Top 10 risks.', 'success');

  try {
    const response = await fetch('/api/repo-scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.error || 'Unable to run the live AI repository scan right now.');
    }

    showScanNotice('Live AI scan complete. Results are rendered below.', 'success');
    renderResult(result);
  } catch (error) {
    showScanNotice(error.message || 'Something went wrong. Please try again.', 'error');
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = 'Run Live AI Scan';
  }
}

if (repoScanForm) {
  repoScanForm.addEventListener('submit', submitRepoScan);
}
