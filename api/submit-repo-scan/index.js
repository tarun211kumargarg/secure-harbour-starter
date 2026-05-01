const crypto = require('crypto');
const { getContainer } = require('../shared/cosmos');
const { isValidEmail, normalizeString } = require('../shared/validation');
const { collectRepositoryFiles, PublicScanError } = require('../shared/github');
const { scanFiles } = require('../shared/sourceScanner');
const { generateAiSummary } = require('../shared/aiReviewer');

function sanitizeScanPayload(payload) {
  return {
    name: normalizeString(payload.name, 120),
    company: normalizeString(payload.company, 120),
    email: normalizeString(payload.email, 180).toLowerCase(),
    repoUrl: normalizeString(payload.repoUrl, 320),
    message: normalizeString(payload.message, 1500),
    website: normalizeString(payload.website, 120)
  };
}

function publicFindings(findings) {
  return findings.slice(0, 25).map((finding) => ({
    id: finding.id,
    ruleId: finding.ruleId,
    owasp: finding.owasp,
    title: finding.title,
    severity: finding.severity,
    confidence: finding.confidence,
    path: finding.path,
    line: finding.line,
    evidence: finding.evidence,
    recommendation: finding.recommendation
  }));
}

module.exports = async function (context, req) {
  try {
    const payload = sanitizeScanPayload(req.body || {});

    if (payload.website) {
      return {
        status: 400,
        body: { error: 'Invalid submission.' }
      };
    }

    if (!payload.name || !payload.email || !payload.repoUrl) {
      return {
        status: 400,
        body: { error: 'Name, email, and GitHub repository URL are required.' }
      };
    }

    if (!isValidEmail(payload.email)) {
      return {
        status: 400,
        body: { error: 'Please enter a valid email address.' }
      };
    }

    const repoContext = await collectRepositoryFiles(payload.repoUrl);
    const { findings, scanSummary } = scanFiles(repoContext.files, repoContext);
    const visibleFindings = publicFindings(findings);
    const aiSummary = await generateAiSummary({
      repository: repoContext.repository,
      scanSummary,
      findings: visibleFindings
    });

    const item = {
      id: crypto.randomUUID(),
      recordType: 'repoScan',
      createdAt: new Date().toISOString(),
      status: 'New',
      name: payload.name,
      company: payload.company,
      email: payload.email,
      phone: '',
      serviceInterestedIn: 'AI Code Security Scan',
      message: payload.message || `Public repository scan requested for ${repoContext.repository.fullName}.`,
      sourcePage: 'repo-scan',
      ownerNotes: '',
      repo: repoContext.repository,
      scanLimits: repoContext.limits,
      scanTree: repoContext.tree,
      scanSummary,
      findings: visibleFindings,
      aiSummary
    };

    const container = getContainer();
    await container.items.create(item);

    return {
      status: 201,
      body: {
        success: true,
        id: item.id,
        repo: item.repo,
        scanSummary: item.scanSummary,
        scanTree: item.scanTree,
        findings: item.findings,
        aiSummary: item.aiSummary,
        dashboardNote: 'The complete demo scan request is available in the owner dashboard.'
      }
    };
  } catch (error) {
    context.log.error(error);
    const status = error instanceof PublicScanError ? error.statusCode : 500;
    return {
      status,
      body: {
        error: status === 500
          ? 'Unable to run the repository scan right now.'
          : error.message
      }
    };
  }
};
