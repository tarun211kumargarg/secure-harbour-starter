const fs = require('fs');
const path = require('path');
const { collectRepositoryFiles } = require('../api/shared/github');
const { scanFiles, toMarkdownReport } = require('../api/shared/sourceScanner');
const { generateAiSummary } = require('../api/shared/aiReviewer');

async function main() {
  const repositoryUrl = process.env.REPOSITORY_URL || process.argv[2];
  if (!repositoryUrl) {
    throw new Error('Repository URL is required. Set REPOSITORY_URL or pass it as the first argument.');
  }

  console.log(`Scanning ${repositoryUrl}`);
  const repoContext = await collectRepositoryFiles(repositoryUrl);
  const { findings, scanSummary } = scanFiles(repoContext.files, repoContext);
  const aiSummary = await generateAiSummary({
    repository: repoContext.repository,
    scanSummary,
    findings
  });

  const output = {
    repository: repoContext.repository,
    scanLimits: repoContext.limits,
    scanTree: repoContext.tree,
    scanSummary,
    findings,
    aiSummary
  };

  const resultsPath = path.join(__dirname, 'source-scan-results.json');
  const reportPath = path.join(__dirname, 'source-scan-report.md');
  fs.writeFileSync(resultsPath, `${JSON.stringify(output, null, 2)}\n`);
  fs.writeFileSync(reportPath, toMarkdownReport(output));

  console.log(`Risk level: ${scanSummary.riskLevel}`);
  console.log(`Findings: ${scanSummary.totalFindings}`);
  console.log(`Files analyzed: ${scanSummary.analyzedFiles}`);
  console.log(`Wrote ${resultsPath}`);
  console.log(`Wrote ${reportPath}`);

  if ((scanSummary.severityCounts.Critical || 0) > 0) {
    process.exitCode = 2;
  }
}

main().catch((error) => {
  console.error(error.message || error);
  process.exitCode = 1;
});
