import type {
  ProjectFile,
  ScanReport,
  ScanStage,
  ScanTarget,
  VulnerabilityFinding,
} from '../types/security';

export const SCAN_STAGES: ScanStage[] = [
  { id: 'stage-1', name: 'Project Ingestion', description: 'Reading source files and preparing rule checks', weight: 15, status: 'pending' },
  { id: 'stage-2', name: 'Source Pattern Review', description: 'Checking source code for risky input and execution patterns', weight: 25, status: 'pending' },
  { id: 'stage-3', name: 'Security Rule Evaluation', description: 'Mapping matches to CWE and OWASP categories', weight: 25, status: 'pending' },
  { id: 'stage-4', name: 'Finding Analysis', description: 'Preparing impact descriptions and safer implementation examples', weight: 20, status: 'pending' },
  { id: 'stage-5', name: 'Report Generation', description: 'Calculating the illustrative score and building the report', weight: 15, status: 'pending' },
];

export interface ScanProgressUpdate {
  stageIndex: number;
  overallPercent: number;
  currentStageId: string;
  stageName: string;
  microTask: string;
  tokensAnalyzed: number;
  rulesEvaluated: number;
  threatsDetected: number;
  newFinding?: VulnerabilityFinding;
  currentFile?: string;
  fileIndex?: number;
  totalFiles?: number;
}

export interface ScanControl {
  aborted: boolean;
  paused?: boolean;
}

const delay = (ms: number) => new Promise<void>((resolve) => window.setTimeout(resolve, ms));

async function waitForScan(ms: number, control?: ScanControl, speed: '1x' | '2x' = '1x') {
  const total = Math.max(30, Math.round(ms / (speed === '2x' ? 2 : 1)));
  let elapsed = 0;
  while (elapsed < total) {
    if (control?.aborted) throw new Error('Scan cancelled by user.');
    while (control?.paused && !control.aborted) await delay(100);
    if (control?.aborted) throw new Error('Scan cancelled by user.');
    const step = Math.min(50, total - elapsed);
    await delay(step);
    elapsed += step;
  }
}

function lineOf(content: string, regex: RegExp): number {
  const lines = content.split(/\r?\n/);
  const index = lines.findIndex((line) => regex.test(line));
  return index >= 0 ? index + 1 : 1;
}

function lineText(content: string, line: number): string {
  return content.split(/\r?\n/)[line - 1]?.trim() || '';
}

function createFinding(
  file: ProjectFile,
  rule: {
    id: string;
    title: string;
    cwe: string;
    owasp: string;
    severity: VulnerabilityFinding['severity'];
    pattern: RegExp;
    matched: string;
    explanation: string;
    impact: string;
    vulnerable: string;
    secure: string;
    language?: string;
    remediation: string;
    headers?: string[];
  },
): VulnerabilityFinding {
  const lineNumber = lineOf(file.content, rule.pattern);
  return {
    id: `${rule.id}-${file.id}-${lineNumber}`,
    title: rule.title,
    cwe: rule.cwe,
    owaspCategory: rule.owasp,
    severity: rule.severity,
    endpoint: file.path,
    filePath: file.path,
    lineNumber,
    matchedPattern: lineText(file.content, lineNumber) || rule.matched,
    aiExplanation: rule.explanation,
    impactAnalysis: rule.impact,
    remediation: {
      vulnerableSnippet: lineText(file.content, lineNumber) || rule.vulnerable,
      secureSnippet: rule.secure,
      language: rule.language || file.language || 'text',
      explanation: rule.remediation,
    },
    mitigationHeaders: rule.headers,
    remediated: false,
  };
}

function detectFileFindings(file: ProjectFile): VulnerabilityFinding[] {
  const code = file.content;
  const findings: VulnerabilityFinding[] = [];
  const commentFreeCode = code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|\s)\/\/.*$/gm, '$1');
  const lower = commentFreeCode.toLowerCase();

  // SQL injection: SQL construction plus interpolation/concatenation.
  const sqlLine = /\b(select|insert\s+into|update\s+\w+\s+set|delete\s+from)\b.*(\+\s*[\w$({]|\$\{[^}]+\})/i;
  const sqlDynamic = /\b(select|insert\s+into|update\s+\w+\s+set|delete\s+from)\b[\s\S]{0,500}(\+\s*(?:req\.|input|user|search|query|param|filter)|\$\{(?:req\.|input|user|search|query|param|filter))/i;
  if (sqlDynamic.test(code) || sqlLine.test(code)) {
    findings.push(createFinding(file, {
      id: 'sqli', title: 'Potential SQL Injection', cwe: 'CWE-89', owasp: 'A03:2021-Injection', severity: 'critical',
      pattern: /\b(select|insert\s+into|update\s+\w+\s+set|delete\s+from)\b/i,
      matched: 'Dynamic SQL statement construction',
      explanation: 'A SQL statement appears to be assembled using string concatenation or interpolation. If untrusted input reaches this statement, an attacker may alter the intended SQL command. This is a heuristic source-code match, not proof of exploitability.',
      impact: 'Potential impact includes unauthorized data access, data modification, or authentication bypass, depending on database permissions and the input path.',
      vulnerable: 'const sql = "SELECT * FROM users WHERE name = " + userInput;',
      secure: "// Use a parameterized query. Keep dynamic identifiers on a strict allowlist.\nconst sql = 'SELECT * FROM users WHERE name = $1';\nconst result = await db.query(sql, [userInput]);",
      remediation: 'Use prepared statements or parameterized queries for values. SQL identifiers such as column names cannot usually be parameterized; select them from a fixed allowlist.',
    }));
  }

  // XSS: dangerous HTML sinks. Flag direct HTML writes; reviewers must verify whether data is tainted.
  const xssPattern = /(\.innerHTML\s*(?:\+?=)|dangerouslySetInnerHTML|document\.write\s*\()/i;
  if (xssPattern.test(code)) {
    findings.push(createFinding(file, {
      id: 'xss', title: 'Potential Cross-Site Scripting (XSS) Sink', cwe: 'CWE-79', owasp: 'A03:2021-Injection', severity: 'high',
      pattern: xssPattern,
      matched: 'Assignment to an HTML execution sink',
      explanation: 'The code writes content to an HTML parsing sink. If the value contains untrusted data, attacker-controlled markup or script-capable attributes may execute in a user browser. Confirm the data source and any sanitization before treating this as exploitable.',
      impact: 'Potential impact includes actions performed in a victim session, page manipulation, phishing overlays, or exposure of accessible page data.',
      vulnerable: 'element.innerHTML = userProvidedValue;',
      secure: "// For plain text, do not parse HTML.\nelement.textContent = userProvidedValue;\n\n// If rich HTML is required, sanitize with a maintained allowlist sanitizer.\n// Example: element.innerHTML = DOMPurify.sanitize(untrustedHtml);",
      remediation: 'Prefer textContent for text. If HTML is a requirement, sanitize with a maintained sanitizer such as DOMPurify and use a restrictive Content Security Policy.',
      headers: ["Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'"],
    }));
  }

  // SSRF: outbound request plus a request-controlled URL/host variable.
  const outbound = /(\bfetch\s*\(|axios\.(?:get|post|request)\s*\(|https?\.request\s*\()/i;
  const requestInput = /(req\.(?:query|body|params)|callbackUrl|targetUrl|userSuppliedUrl|webhookUrl|destinationUrl)/i;
  if (outbound.test(code) && requestInput.test(code)) {
    findings.push(createFinding(file, {
      id: 'ssrf', title: 'Potential Server-Side Request Forgery (SSRF)', cwe: 'CWE-918', owasp: 'A10:2021-Server-Side Request Forgery', severity: 'critical',
      pattern: outbound,
      matched: 'Outbound HTTP request may use user-controlled destination',
      explanation: 'An outbound HTTP request appears in the same file as a request-controlled URL or destination variable. If that value reaches the request without strict validation, the server may be induced to contact internal services or cloud metadata endpoints.',
      impact: 'Potential impact includes access to internal services, exposure of cloud metadata, or use of the server as a network pivot.',
      vulnerable: 'await fetch(userSuppliedUrl);',
      secure: "// Prefer a strict hostname allowlist and enforce HTTPS.\nconst allowedHosts = new Set(['hooks.example.com']);\nconst destination = new URL(userSuppliedUrl);\nif (destination.protocol !== 'https:' || !allowedHosts.has(destination.hostname)) {\n  throw new Error('Destination is not allowed');\n}\n// On a server, also enforce DNS/IP and redirect protections at connection time.",
      remediation: 'Use a strict destination allowlist. On the server, validate DNS results and block loopback, private, link-local, and metadata IP ranges; prevent DNS rebinding and unsafe redirects at connection time.',
    }));
  }

  // Hardcoded credentials: avoid generic long strings and obvious placeholders.
  const secretPattern = /\b(?:api[_-]?key|client[_-]?secret|password|passwd|access[_-]?token|auth[_-]?token|secret)\b\s*[:=]\s*(['"])([^'"\r\n]{8,})\1/i;
  const secretMatch = code.match(secretPattern);
  if (secretMatch && !/^(?:example|sample|changeme|your[_-]?|replace[_-]?|dummy|test|placeholder)/i.test(secretMatch[2])) {
    findings.push(createFinding(file, {
      id: 'secret', title: 'Possible Hardcoded Secret', cwe: 'CWE-798', owasp: 'A07:2021-Identification and Authentication Failures', severity: 'high',
      pattern: secretPattern,
      matched: 'Credential-like variable assigned a string literal',
      explanation: 'A credential-like variable is assigned a string literal. This may be a real secret or a harmless test value; verify it before taking action. Any real secret committed to source control should be rotated.',
      impact: 'A real exposed credential may allow unauthorized access to APIs, databases, cloud resources, or user accounts.',
      vulnerable: "const API_KEY = 'hardcoded-value';",
      secure: "// Configure the secret in the deployment environment or a secret manager.\nconst apiKey = process.env.API_KEY;\nif (!apiKey) throw new Error('API_KEY is not configured');",
      remediation: 'Move real credentials to environment variables or a secrets manager, remove them from repository history where necessary, and rotate exposed credentials.',
    }));
  }

  // Wildcard CORS is only reported when an explicit response/header setting is present.
  if (/access-control-allow-origin[\s'"`]*[:=][\s'"`]*\*/i.test(code) || /cors\s*\(\s*\{[^}]*origin\s*:\s*['"]\*['"]/is.test(code)) {
    findings.push(createFinding(file, {
      id: 'cors', title: 'Wildcard Cross-Origin Policy', cwe: 'CWE-942', owasp: 'A05:2021-Security Misconfiguration', severity: 'medium',
      pattern: /access-control-allow-origin|cors\s*\(/i,
      matched: 'Wildcard Access-Control-Allow-Origin policy',
      explanation: 'The source appears to allow cross-origin requests from any origin. This may be acceptable for public, non-credentialed resources, but is risky when sensitive data or credentialed requests are involved.',
      impact: 'A permissive policy can expose response data to arbitrary websites if combined with sensitive endpoints or credentialed CORS settings.',
      vulnerable: "res.setHeader('Access-Control-Allow-Origin', '*');",
      secure: "// Allow only trusted origins.\nconst allowedOrigins = new Set(['https://app.example.com']);\nif (origin && allowedOrigins.has(origin)) {\n  res.setHeader('Access-Control-Allow-Origin', origin);\n  res.setHeader('Vary', 'Origin');\n}",
      remediation: 'Use an explicit origin allowlist. Do not combine wildcard origins with credentials. Review methods, headers, and credential settings.',
    }));
  }

  // Security middleware omission: only for files that look like Express/server setup code.
  const looksLikeServer = /express\s*\(|createServer\s*\(|app\.(?:get|post|put|delete|use)\s*\(/i.test(commentFreeCode);
  const hasSecurityMiddleware = /helmet\s*\(|content-security-policy|strict-transport-security|x-frame-options/i.test(lower);
  if (looksLikeServer && !hasSecurityMiddleware) {
    findings.push(createFinding(file, {
      id: 'headers', title: 'Security Headers Middleware Not Detected', cwe: 'CWE-693', owasp: 'A05:2021-Security Misconfiguration', severity: 'low',
      pattern: /express\s*\(|createServer\s*\(|app\.(?:get|post|put|delete|use)\s*\(/i,
      matched: 'Server setup found without an obvious security-header configuration',
      explanation: 'This server-like source file does not contain an obvious security-header middleware or header configuration. The configuration may exist in another file or at a reverse proxy, so this is an informational heuristic.',
      impact: 'Missing defense-in-depth headers can increase the impact of other vulnerabilities, for example by weakening browser-side protections.',
      vulnerable: '// Server starts without visible security-header middleware',
      secure: "import helmet from 'helmet';\napp.use(helmet());\n// Review the Content-Security-Policy for your app's actual resource requirements.",
      remediation: 'Configure security headers centrally (for example with Helmet in Express or at a trusted reverse proxy). Confirm headers in the deployed response before marking this finding resolved.',
      headers: ["Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'", 'X-Content-Type-Options: nosniff', 'Referrer-Policy: strict-origin-when-cross-origin'],
    }));
  }

  return findings;
}

function calculateGrade(score: number): ScanReport['grade'] {
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

function scoreFindings(findings: VulnerabilityFinding[]): number {
  const weights = { critical: 30, high: 20, medium: 10, low: 4, info: 0 };
  return Math.max(0, Math.min(100, 100 - findings.reduce((total, item) => total + weights[item.severity], 0)));
}

function buildReport(targetUrl: string, method: string, start: number, findings: VulnerabilityFinding[]): ScanReport {
  const overallScore = scoreFindings(findings);
  return {
    id: `sentinel-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
    timestamp: new Date().toISOString(),
    targetUrl,
    method,
    durationMs: Date.now() - start,
    overallScore,
    grade: calculateGrade(overallScore),
    findings,
    recommendedHeaders: [
      { name: 'Content-Security-Policy', recommendedValue: "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'", reason: 'Restricts resource loading and framing. Adapt directives to the application.' },
      { name: 'Strict-Transport-Security', recommendedValue: 'max-age=31536000; includeSubDomains', reason: 'Enforces HTTPS after the browser has received the policy over HTTPS.' },
      { name: 'X-Content-Type-Options', recommendedValue: 'nosniff', reason: 'Reduces MIME-type confusion.' },
      { name: 'Referrer-Policy', recommendedValue: 'strict-origin-when-cross-origin', reason: 'Limits referrer information sent to other origins.' },
      { name: 'X-Frame-Options', recommendedValue: 'DENY', reason: 'Provides legacy clickjacking protection; CSP frame-ancestors is preferred.' },
    ],
  };
}

export async function analyzeProjectFilesDefensively(
  files: ProjectFile[],
  onProgress: (update: ScanProgressUpdate) => void,
  control?: ScanControl,
  speed: '1x' | '2x' = '1x',
): Promise<ScanReport> {
  if (!files.length) throw new Error('No project files selected. Add at least one supported source file.');
  const start = Date.now();
  const findings: VulnerabilityFinding[] = [];
  let tokensAnalyzed = 0;
  let rulesEvaluated = 0;
  const totalFiles = files.length;

  for (let index = 0; index < files.length; index += 1) {
    const file = files[index];
    const base = (index / totalFiles) * 90;
    onProgress({ stageIndex: 0, overallPercent: Math.round(base + 3), currentStageId: SCAN_STAGES[0].id, stageName: `Reading ${file.path}`, microTask: `Reading ${file.size.toLocaleString()} bytes from ${file.path}`, tokensAnalyzed, rulesEvaluated, threatsDetected: findings.length, currentFile: file.path, fileIndex: index + 1, totalFiles });
    await waitForScan(120, control, speed);

    onProgress({ stageIndex: 1, overallPercent: Math.round(base + 12), currentStageId: SCAN_STAGES[1].id, stageName: `Reviewing ${file.path}`, microTask: 'Checking source text against defensive security rules (heuristic analysis; not a compiler AST).', tokensAnalyzed, rulesEvaluated, threatsDetected: findings.length, currentFile: file.path, fileIndex: index + 1, totalFiles });
    await waitForScan(180, control, speed);

    const fileFindings = detectFileFindings(file);
    tokensAnalyzed += Math.ceil(file.content.length / 4);
    rulesEvaluated += 6;
    for (const finding of fileFindings) {
      findings.push(finding);
      onProgress({ stageIndex: 2, overallPercent: Math.min(95, Math.round(base + 18)), currentStageId: SCAN_STAGES[2].id, stageName: `Finding: ${finding.title}`, microTask: `${finding.cwe} pattern matched in ${file.path}:${finding.lineNumber ?? 1}`, tokensAnalyzed, rulesEvaluated, threatsDetected: findings.length, newFinding: finding, currentFile: file.path, fileIndex: index + 1, totalFiles });
      await waitForScan(70, control, speed);
    }
  }

  onProgress({ stageIndex: 4, overallPercent: 100, currentStageId: SCAN_STAGES[4].id, stageName: 'Report generated', microTask: `Completed heuristic review of ${totalFiles} file(s); ${findings.length} finding(s) require manual validation.`, tokensAnalyzed, rulesEvaluated, threatsDetected: findings.length, totalFiles });
  return buildReport(`${totalFiles} project file(s)`, 'SOURCE_REVIEW', start, findings);
}

export async function analyzeTargetDefensively(
  target: ScanTarget,
  onProgress: (update: ScanProgressUpdate) => void,
  control?: ScanControl,
  speed: '1x' | '2x' = '1x',
): Promise<ScanReport> {
  const file: ProjectFile = {
    id: target.id,
    name: `${target.id}.txt`,
    path: target.name,
    content: target.endpointCodeSnippet,
    size: target.endpointCodeSnippet.length,
    language: 'javascript',
    uploadedAt: 'Sample scenario',
  };
  const report = await analyzeProjectFilesDefensively([file], onProgress, control, speed);
  report.targetUrl = target.targetUrl;
  report.method = target.method;
  report.id = `scenario-${Date.now()}`;
  return report;
}
