const { normalizeString } = require('../shared/validation');
const { collectRepositoryFiles, PublicScanError } = require('../shared/github');
const { scanFiles, summarizeFindings } = require('../shared/sourceScanner');
const { runAiRepositoryScan, AiScanError } = require('../shared/aiCodeScanner');
const { GitHubModelsError } = require('../shared/githubModels');

const RISK_ORDER = {
  Informational: 0,
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4
};

function sanitizeScanPayload(payload) {
  return {
    repoUrl: normalizeString(payload.repoUrl, 320),
    focus: normalizeString(payload.focus, 500),
    website: normalizeString(payload.website, 120)
  };
}

function publicFindings(findings, limit = 25) {
  return (findings || []).slice(0, limit).map((finding) => ({
    id: finding.id,
    ruleId: finding.ruleId,
    owasp: finding.owasp,
    title: finding.title,
    severity: finding.severity,
    confidence: finding.confidence,
    path: finding.path,
    line: finding.line,
    evidence: finding.evidence,
    recommendation: finding.recommendation,
    source: finding.source || 'rule'
  }));
}

function highestRisk(a, b) {
  return (RISK_ORDER[b] || 0) > (RISK_ORDER[a] || 0) ? b : a;
}

module.exports = async function (context, req) {
  try {
    const payload = sanitizeScanPayload(req.body || {});

    if (payload.website) {
      return {
        status: 400,
        body: { error: 'Invalid scan request.' }
      };
    }

    if (!payload.repoUrl) {
      return {
        status: 400,
        body: { error: 'Public GitHub repository URL is required.' }
      };
    }

    const repoContext = await collectRepositoryFiles(payload.repoUrl);

    // Deterministic rules are used as backend signals and guardrails for the AI scanner.
    // The public report is generated from the AI backend analysis, not from browser-side logic.
    const ruleScan = scanFiles(repoContext.files, repoContext);
    const ruleFindings = publicFindings(ruleScan.findings, 30);

    const aiScan = await runAiRepositoryScan({
      repository: repoContext.repository,
      files: repoContext.files,
      ruleFindings,
      ruleScanSummary: ruleScan.scanSummary,
      focus: payload.focus
    });

    const findings = publicFindings(aiScan.findings, 25);
    const scanSummary = summarizeFindings(findings, repoContext.files, repoContext);
    scanSummary.riskLevel = highestRisk(scanSummary.riskLevel, aiScan.riskLevel);
    scanSummary.engine = aiScan.engine;
    scanSummary.analysisMode = 'live-ai-backend';
    scanSummary.aiModel = aiScan.model;
    scanSummary.filesSentToAi = aiScan.filesSentToAi;
    scanSummary.ruleSignals = ruleFindings.length;

    return {
      status: 200,
      body: {
        success: true,
        repo: repoContext.repository,
        scanSummary,
        scanTree: repoContext.tree,
        scanLimits: {
          github: repoContext.limits,
          ai: aiScan.scanLimits
        },
        findings,
        aiSummary: {
          enabled: true,
          provider: aiScan.provider,
          model: aiScan.model,
          text: aiScan.summary,
          remediationPlan: aiScan.remediationPlan,
          reviewNotes: aiScan.reviewNotes
        },
        metadata: {
          generatedAt: scanSummary.generatedAt,
          codeExecution: false,
          dataSource: 'GitHub API source text',
          note: 'AI findings are indicators for review and should be validated before remediation.'
        }
      }
    };
  } catch (error) {
    context.log.error(error);
    const status = error instanceof PublicScanError || error instanceof AiScanError || error instanceof GitHubModelsError
      ? error.statusCode
      : 500;

    const exposeDiagnostic = process.env.REPO_SCAN_DEBUG === 'true' || status >= 500;

    return {
      status,
      body: {
        error: status === 500
          ? 'Unable to run the live AI repository scan right now.'
          : error.message,
        detail: exposeDiagnostic ? String(error.message || 'Unknown backend error') : undefined,
        errorType: exposeDiagnostic ? String(error.name || 'Error') : undefined,
        diagnostic: exposeDiagnostic ? {
          hasGitHubModelsToken: Boolean(process.env.GITHUB_MODELS_TOKEN || process.env.GITHUB_TOKEN || process.env.SCAN_GITHUB_TOKEN),
          model: process.env.GITHUB_MODELS_MODEL || process.env.AI_SCAN_MODEL || 'microsoft/phi-4-mini-instruct',
          hasFetch: typeof fetch === 'function',
          nodeVersion: process.version
        } : undefined
      }
    };
  }
};
