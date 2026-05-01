const repoScanForm = document.querySelector('[data-repo-scan-form]');
const scanNotice = document.querySelector('[data-scan-notice]');
const resultSection = document.querySelector('[data-scan-result]');
const resultRepo = document.querySelector('[data-result-repo]');
const resultRisk = document.querySelector('[data-result-risk]');
const resultStats = document.querySelector('[data-result-stats]');
const resultAi = document.querySelector('[data-result-ai]');
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
      <p class="meta">${escapeHtml(finding.owasp)} | ${escapeHtml(finding.path)}:${escapeHtml(finding.line)} | Confidence: ${escapeHtml(finding.confidence)}</p>
      <div class="code-evidence">${escapeHtml(finding.evidence)}</div>
      <p class="helper-text"><strong>Recommended action:</strong> ${escapeHtml(finding.recommendation)}</p>
    </article>
  `;
}

function renderResult(result) {
  const summary = result.scanSummary || {};
  const repo = result.repo || {};
  const tree = result.scanTree || {};
  const counts = summary.severityCounts || {};
  const findings = Array.isArray(result.findings) ? result.findings : [];

  resultSection.hidden = false;
  resultRepo.textContent = `${repo.fullName || 'Repository'} scan complete`;
  resultRisk.textContent = `${summary.riskLevel || 'Unknown'} risk`;
  resultRisk.className = `risk-badge risk-${severityClass(summary.riskLevel || 'Low')}`;
  resultStats.innerHTML = [
    renderStat('Total findings', summary.totalFindings || 0),
    renderStat('High / Medium', `${counts.High || 0} / ${counts.Medium || 0}`),
    renderStat('Files analyzed', summary.analyzedFiles || tree.analyzedFiles || 0),
    renderStat('Candidate files', summary.candidateFiles || tree.candidateFiles || 0)
  ].join('');
  resultAi.textContent = result.aiSummary && result.aiSummary.text
    ? result.aiSummary.text
    : 'Local triage summary was not returned for this run.';

  if (!findings.length) {
    resultFindings.innerHTML = '<div class="empty-state">No OWASP source-code indicators were identified within the demo scan limits.</div>';
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
  const payload = Object.fromEntries(formData.entries());

  if (payload.website) {
    showScanNotice('The scan request could not be submitted.', 'error');
    return;
  }

  submitButton.disabled = true;
  submitButton.textContent = 'Scanning...';
  showScanNotice('Scanning selected source files through the GitHub API. This usually takes a moment for small public repositories.', 'success');

  try {
    const response = await fetch('/api/submit-repo-scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.error || 'Unable to run the repository scan right now.');
    }

    showScanNotice('Demo scan complete. The request is also available in the owner dashboard.', 'success');
    renderResult(result);
  } catch (error) {
    showScanNotice(error.message || 'Something went wrong. Please try again.', 'error');
  } finally {
    submitButton.disabled = false;
    submitButton.textContent = 'Run Demo Scan';
  }
}

if (repoScanForm) {
  repoScanForm.addEventListener('submit', submitRepoScan);
}
