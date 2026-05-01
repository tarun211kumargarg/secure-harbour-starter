const MAX_FINDINGS = Number(process.env.SCAN_MAX_FINDINGS || 80);

const SEVERITY_ORDER = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
  Informational: 0
};

const RULES = [
  {
    id: 'A01-CORS-WILDCARD',
    owasp: 'A01: Broken Access Control',
    title: 'Permissive cross-origin access policy',
    severity: 'Medium',
    confidence: 'Medium',
    pattern: /(?:Access-Control-Allow-Origin\s*['"]?\s*[:=]\s*['"]\*|cors\s*\(\s*\))/i,
    recommendation: 'Restrict CORS origins to trusted domains and require authorization on sensitive routes.'
  },
  {
    id: 'A02-HARDCODED-SECRET',
    owasp: 'A02: Cryptographic Failures',
    title: 'Possible hardcoded secret or credential',
    severity: 'High',
    confidence: 'Medium',
    pattern: /(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|ghp_[0-9A-Za-z_]{20,}|xox[baprs]-[0-9A-Za-z-]{10,}|-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----|(?:api[_-]?key|secret|password|passwd|pwd|token)\s*[:=]\s*['"][^'"\s]{8,})/i,
    recommendation: 'Move secrets to a managed secret store, rotate exposed values, and prevent secret commits with pre-commit scanning.'
  },
  {
    id: 'A02-WEAK-HASH',
    owasp: 'A02: Cryptographic Failures',
    title: 'Weak hashing algorithm',
    severity: 'Medium',
    confidence: 'High',
    pattern: /(?:createHash\s*\(\s*['"](?:md5|sha1)['"]|CryptoJS\.(?:MD5|SHA1)\s*\(|hashlib\.(?:md5|sha1)\s*\(|MessageDigest\.getInstance\s*\(\s*['"](?:MD5|SHA-1)['"])/i,
    recommendation: 'Use modern password hashing such as Argon2, bcrypt, or PBKDF2 for passwords, and SHA-256 or stronger where a general digest is appropriate.'
  },
  {
    id: 'A02-PLAINTEXT-HTTP',
    owasp: 'A02: Cryptographic Failures',
    title: 'Plaintext HTTP reference',
    severity: 'Low',
    confidence: 'Medium',
    pattern: /['"]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"]+['"]/i,
    recommendation: 'Use HTTPS endpoints for external traffic and validate TLS certificates.'
  },
  {
    id: 'A03-EVAL',
    owasp: 'A03: Injection',
    title: 'Dynamic code execution',
    severity: 'High',
    confidence: 'High',
    pattern: /\b(?:eval|Function)\s*\(/,
    recommendation: 'Remove dynamic code execution. Prefer explicit parsers, allowlists, and safe interpreters for untrusted input.'
  },
  {
    id: 'A03-SQL-CONCAT',
    owasp: 'A03: Injection',
    title: 'Possible SQL query string concatenation',
    severity: 'High',
    confidence: 'Medium',
    pattern: /(?:query|execute|raw)\s*\([^\n]*(?:SELECT|INSERT|UPDATE|DELETE)[^\n]*(?:\+|`[^`]*\$\{)/i,
    recommendation: 'Use parameterized queries or a safe ORM query builder. Never concatenate request-controlled values into SQL.'
  },
  {
    id: 'A03-COMMAND-EXECUTION',
    owasp: 'A03: Injection',
    title: 'Command execution surface',
    severity: 'High',
    confidence: 'Medium',
    pattern: /(?:child_process\.(?:exec|spawn|execFile)|subprocess\.(?:Popen|call|run)\s*\([^\n]*shell\s*=\s*True|os\.system\s*\(|Runtime\.getRuntime\(\)\.exec)/i,
    recommendation: 'Avoid shell execution for request-controlled input. Use safe library APIs and strict argument allowlists.'
  },
  {
    id: 'A03-XSS-SINK',
    owasp: 'A03: Injection',
    title: 'Browser injection sink',
    severity: 'Medium',
    confidence: 'Medium',
    pattern: /(?:\.innerHTML\s*=|dangerouslySetInnerHTML|v-html\s*=|document\.write\s*\()/i,
    recommendation: 'Render untrusted data as text, sanitize rich HTML with a maintained sanitizer, and enforce a strict CSP.'
  },
  {
    id: 'A04-NO-RATE-LIMIT-HINT',
    owasp: 'A04: Insecure Design',
    title: 'Authentication route may need abuse controls',
    severity: 'Low',
    confidence: 'Low',
    pattern: /(?:app\.(?:post|get)\s*\(\s*['"][^'"]*(?:login|signin|auth)|router\.(?:post|get)\s*\(\s*['"][^'"]*(?:login|signin|auth))/i,
    recommendation: 'Confirm login and token routes have throttling, lockout controls, monitoring, and replay protection.'
  },
  {
    id: 'A05-DEBUG-ENABLED',
    owasp: 'A05: Security Misconfiguration',
    title: 'Debug or unsafe runtime configuration',
    severity: 'Medium',
    confidence: 'High',
    pattern: /(?:debug\s*=\s*True|DEBUG\s*=\s*True|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]0['"]|rejectUnauthorized\s*:\s*false|verify\s*=\s*False)/i,
    recommendation: 'Disable debug behavior in production and keep TLS certificate validation enabled.'
  },
  {
    id: 'A05-DEFAULT-CREDENTIAL',
    owasp: 'A05: Security Misconfiguration',
    title: 'Possible default credential',
    severity: 'Medium',
    confidence: 'Medium',
    pattern: /(?:username|user|login)\s*[:=]\s*['"]admin['"][^\n]{0,80}(?:password|pass|pwd)\s*[:=]\s*['"](?:admin|password|changeme|123456)['"]/i,
    recommendation: 'Remove default credentials and require unique secrets during deployment.'
  },
  {
    id: 'A06-UNPINNED-DEPENDENCY',
    owasp: 'A06: Vulnerable and Outdated Components',
    title: 'Unpinned dependency version',
    severity: 'Low',
    confidence: 'Medium',
    pattern: /"[^"]+"\s*:\s*"(?:\*|latest|x)"/i,
    filePattern: /(^|\/)package\.json$/i,
    recommendation: 'Pin dependency versions and enable automated dependency vulnerability scanning.'
  },
  {
    id: 'A07-JWT-DECODE-ONLY',
    owasp: 'A07: Identification and Authentication Failures',
    title: 'JWT decoded without verification',
    severity: 'High',
    confidence: 'High',
    pattern: /(?:jwt\.decode\s*\(|verify_signature\s*[:=]\s*False|options\s*=\s*\{[^}]*verify_signature[^}]*False)/i,
    recommendation: 'Verify JWT signature, issuer, audience, expiry, and accepted algorithms before trusting token claims.'
  },
  {
    id: 'A07-COOKIE-FLAGS',
    owasp: 'A07: Identification and Authentication Failures',
    title: 'Cookie may be missing security flags',
    severity: 'Medium',
    confidence: 'Low',
    pattern: /(?:res\.cookie\s*\(|Set-Cookie)/i,
    condition: (line) => !/httpOnly/i.test(line) || !/secure/i.test(line) || !/sameSite/i.test(line),
    recommendation: 'Set HttpOnly, Secure, and SameSite attributes on session and authentication cookies.'
  },
  {
    id: 'A08-POSTINSTALL-SCRIPT',
    owasp: 'A08: Software and Data Integrity Failures',
    title: 'Install-time script execution',
    severity: 'Medium',
    confidence: 'Medium',
    pattern: /"(?:preinstall|install|postinstall)"\s*:/i,
    filePattern: /(^|\/)package\.json$/i,
    recommendation: 'Review install-time scripts, pin trusted packages, and use software supply-chain controls.'
  },
  {
    id: 'A08-UNSAFE-DESERIALIZATION',
    owasp: 'A08: Software and Data Integrity Failures',
    title: 'Unsafe deserialization pattern',
    severity: 'High',
    confidence: 'High',
    pattern: /(?:pickle\.loads?\s*\(|yaml\.load\s*\(|ObjectInputStream\s*\(|Marshal\.load\s*\(|BinaryFormatter\s*\()/i,
    recommendation: 'Avoid unsafe deserialization of untrusted data. Use safe parsers and strict schemas.'
  },
  {
    id: 'A09-SECRET-LOGGING',
    owasp: 'A09: Security Logging and Monitoring Failures',
    title: 'Sensitive value may be logged',
    severity: 'Medium',
    confidence: 'Medium',
    pattern: /(?:console\.log|logger\.(?:info|debug|warn|error)|print)\s*\([^\n]*(?:password|passwd|secret|token|api[_-]?key|authorization)/i,
    recommendation: 'Do not log secrets or authorization headers. Redact sensitive values before logging.'
  },
  {
    id: 'A10-SSRF-USER-URL',
    owasp: 'A10: Server-Side Request Forgery',
    title: 'Outbound request may use user-controlled URL',
    severity: 'High',
    confidence: 'Medium',
    pattern: /(?:fetch|axios\.(?:get|post|request)|request\s*\(|http\.get|https\.get|requests\.(?:get|post|request))\s*\([^\n]*(?:req\.|request\.|params|query|body|url)/i,
    recommendation: 'Validate destination URLs with an allowlist, block private IP ranges, and route outbound calls through controlled egress.'
  },
  {
    id: 'A01-PATH-TRAVERSAL',
    owasp: 'A01: Broken Access Control',
    title: 'File access may use request-controlled path',
    severity: 'Medium',
    confidence: 'Medium',
    pattern: /(?:readFile|createReadStream|sendFile|open)\s*\([^\n]*(?:req\.|request\.|params|query|body)/i,
    recommendation: 'Normalize paths, enforce a safe base directory, and never pass request-controlled paths directly into file APIs.'
  }
];

function redactSensitive(value) {
  return String(value || '')
    .replace(/AKIA[0-9A-Z]{16}/g, 'AKIA****************')
    .replace(/AIza[0-9A-Za-z_-]{20,}/g, 'AIza****************')
    .replace(/ghp_[0-9A-Za-z_]{20,}/g, 'ghp_****************')
    .replace(/xox[baprs]-[0-9A-Za-z-]{10,}/g, 'xox*-****************')
    .replace(/((?:api[_-]?key|secret|password|passwd|pwd|token)\s*[:=]\s*['"])[^'"\s]{4,}(['"])/gi, '$1[REDACTED]$2');
}

function truncate(value, max = 220) {
  const normalized = redactSensitive(String(value || '').trim().replace(/\s+/g, ' '));
  return normalized.length > max ? `${normalized.slice(0, max - 1)}…` : normalized;
}

function shouldRunRule(rule, filePath) {
  return !rule.filePattern || rule.filePattern.test(filePath);
}

function scanLine(rule, line, filePath) {
  if (!shouldRunRule(rule, filePath)) return false;
  rule.pattern.lastIndex = 0;
  if (!rule.pattern.test(line)) return false;
  return !rule.condition || rule.condition(line, filePath);
}

function findingSort(a, b) {
  return (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0) || a.path.localeCompare(b.path) || a.line - b.line;
}

function scanFiles(files, repoContext = {}) {
  const findings = [];
  const seen = new Set();

  for (const file of files || []) {
    const lines = String(file.content || '').split(/\r?\n/);

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      if (!line || line.length > 2000) continue;

      for (const rule of RULES) {
        if (findings.length >= MAX_FINDINGS) break;
        if (!scanLine(rule, line, file.path)) continue;

        const key = `${rule.id}:${file.path}:${index + 1}`;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push({
          id: `${rule.id}-${findings.length + 1}`,
          ruleId: rule.id,
          owasp: rule.owasp,
          title: rule.title,
          severity: rule.severity,
          confidence: rule.confidence,
          path: file.path,
          line: index + 1,
          evidence: truncate(line),
          recommendation: rule.recommendation
        });
      }
    }
  }

  findings.sort(findingSort);
  return {
    findings,
    scanSummary: summarizeFindings(findings, files, repoContext)
  };
}

function summarizeFindings(findings, files, repoContext = {}) {
  const severityCounts = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Informational: 0
  };
  const owaspCounts = {};

  for (const finding of findings || []) {
    severityCounts[finding.severity] = (severityCounts[finding.severity] || 0) + 1;
    owaspCounts[finding.owasp] = (owaspCounts[finding.owasp] || 0) + 1;
  }

  let riskLevel = 'Low';
  if (severityCounts.Critical > 0 || severityCounts.High >= 3) riskLevel = 'Critical';
  else if (severityCounts.High > 0 || severityCounts.Medium >= 4) riskLevel = 'High';
  else if (severityCounts.Medium > 0) riskLevel = 'Medium';

  const topCategories = Object.entries(owaspCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([category, count]) => ({ category, count }));

  return {
    riskLevel,
    totalFindings: findings.length,
    severityCounts,
    owaspCounts,
    topCategories,
    analyzedFiles: files.length,
    candidateFiles: repoContext.tree ? repoContext.tree.candidateFiles : files.length,
    treeTruncated: Boolean(repoContext.tree && repoContext.tree.truncated),
    generatedAt: new Date().toISOString(),
    engine: 'Secure Harbour OWASP source rules v1'
  };
}

function toMarkdownReport({ repository, scanSummary, findings, aiSummary }) {
  const lines = [];
  lines.push(`# OWASP Source Scan Report`);
  lines.push('');
  lines.push(`Repository: ${repository.fullName}`);
  lines.push(`URL: ${repository.url}`);
  lines.push(`Default branch: ${repository.defaultBranch}`);
  lines.push(`Risk level: ${scanSummary.riskLevel}`);
  lines.push(`Findings: ${scanSummary.totalFindings}`);
  lines.push(`Files analyzed: ${scanSummary.analyzedFiles}`);
  lines.push('');
  lines.push('## Local OWASP triage summary');
  lines.push('');
  lines.push(aiSummary && aiSummary.text ? aiSummary.text : 'Local OWASP triage summary was not generated for this run.');
  lines.push('');
  lines.push('## Findings');
  lines.push('');

  if (!findings.length) {
    lines.push('No rule-based findings were identified within the scan limits.');
  }

  for (const finding of findings) {
    lines.push(`### ${finding.severity}: ${finding.title}`);
    lines.push('');
    lines.push(`- OWASP: ${finding.owasp}`);
    lines.push(`- File: ${finding.path}:${finding.line}`);
    lines.push(`- Confidence: ${finding.confidence}`);
    lines.push(`- Evidence: \`${finding.evidence.replace(/`/g, '\\`')}\``);
    lines.push(`- Recommendation: ${finding.recommendation}`);
    lines.push('');
  }

  return lines.join('\n');
}

module.exports = {
  RULES,
  scanFiles,
  summarizeFindings,
  toMarkdownReport
};
