import type { ProjectFile, ScanReport, VulnerabilityFinding } from '../types/security';
import { SCAN_STAGES, type ScanControl, type ScanProgressUpdate } from './analyzer';

const SUPPORTED_EXTENSIONS = new Set(['.js', '.jsx', '.ts', '.tsx', '.py', '.sql', '.php', '.html', '.json', '.java', '.go', '.rb', '.cs']);
const MAX_FILES = 20;
const MAX_FILE_BYTES = 256_000;
const MAX_TOTAL_BYTES = 2_000_000;

function extensionOf(name: string): string {
  const index = name.lastIndexOf('.');
  return index >= 0 ? name.slice(index).toLowerCase() : '';
}

function parseGitHubRepo(input: string): { owner: string; repo: string } {
  const trimmed = input.trim();
  if (/^[\w.-]+\/[\w.-]+$/.test(trimmed)) {
    const [owner, repo] = trimmed.split('/');
    return { owner, repo: repo.replace(/\.git$/i, '') };
  }
  let url: URL;
  try { url = new URL(trimmed); } catch { throw new Error('Enter a GitHub URL such as https://github.com/owner/repository.'); }
  if (url.protocol !== 'https:' || url.hostname.toLowerCase() !== 'github.com') {
    throw new Error('Only public repositories hosted on https://github.com are supported.');
  }
  const parts = url.pathname.split('/').filter(Boolean);
  if (parts.length < 2) throw new Error('The URL must include both repository owner and repository name.');
  return { owner: parts[0], repo: parts[1].replace(/\.git$/i, '') };
}

export async function fetchGitHubRepoFiles(repoUrl: string, onStatus?: (message: string) => void): Promise<ProjectFile[]> {
  const { owner, repo } = parseGitHubRepo(repoUrl);
  const headers = { Accept: 'application/vnd.github+json' };
  onStatus?.(`Looking up public repository ${owner}/${repo}...`);
  const repositoryResponse = await fetch(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, { headers });
  if (!repositoryResponse.ok) {
    if (repositoryResponse.status === 404) throw new Error('Repository not found or it is private. Only public repositories can be imported.');
    if (repositoryResponse.status === 403) throw new Error('GitHub API rate limit reached. Wait and try again, or upload files manually.');
    throw new Error(`GitHub returned HTTP ${repositoryResponse.status}.`);
  }
  const repository = await repositoryResponse.json() as { default_branch?: string; full_name?: string };
  const branch = repository.default_branch || 'main';
  onStatus?.(`Listing source files from ${repository.full_name || `${owner}/${repo}`}...`);

  const treeResponse = await fetch(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(branch)}?recursive=1`, { headers });
  if (!treeResponse.ok) throw new Error(`Could not read repository file tree (HTTP ${treeResponse.status}).`);
  const treeData = await treeResponse.json() as { tree?: Array<{ path: string; type: string; size?: number; url?: string }>; truncated?: boolean };
  const candidates = (treeData.tree || []).filter((entry) => entry.type === 'blob' && SUPPORTED_EXTENSIONS.has(extensionOf(entry.path)) && (entry.size ?? 0) <= MAX_FILE_BYTES).slice(0, MAX_FILES);
  if (!candidates.length) throw new Error('No supported source files under the configured size limit were found.');

  const files: ProjectFile[] = [];
  let totalBytes = 0;
  for (const entry of candidates) {
    if (totalBytes >= MAX_TOTAL_BYTES) break;
    onStatus?.(`Downloading ${entry.path}...`);
    const rawUrl = `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(branch)}/${entry.path.split('/').map(encodeURIComponent).join('/')}`;
    const response = await fetch(rawUrl);
    if (!response.ok) continue;
    const content = await response.text();
    const size = new TextEncoder().encode(content).length;
    if (size > MAX_FILE_BYTES || totalBytes + size > MAX_TOTAL_BYTES) continue;
    totalBytes += size;
    const ext = extensionOf(entry.path);
    const language = ext === '.py' ? 'python' : ext === '.sql' ? 'sql' : ext === '.html' ? 'html' : ext === '.json' ? 'json' : ext.slice(1);
    files.push({
      id: `github-${entry.path}-${Date.now()}-${files.length}`,
      name: entry.path.split('/').pop() || entry.path,
      path: entry.path,
      content,
      size,
      language,
      uploadedAt: `GitHub: ${owner}/${repo}@${branch}`,
    });
  }
  if (!files.length) throw new Error('The repository had no downloadable supported files within the import limits.');
  onStatus?.(`Imported ${files.length} file(s). ${treeData.truncated ? 'GitHub reported a truncated repository tree.' : ''}`);
  return files;
}

function buildUrlFinding(input: {
  id: string; title: string; cwe: string; severity: VulnerabilityFinding['severity']; endpoint: string;
  matchedPattern: string; explanation: string; impact: string; vulnerable: string; secure: string; remediation: string;
}): VulnerabilityFinding {
  return {
    id: input.id,
    title: input.title,
    cwe: input.cwe,
    owaspCategory: 'A05:2021-Security Misconfiguration',
    severity: input.severity,
    endpoint: input.endpoint,
    matchedPattern: input.matchedPattern,
    aiExplanation: input.explanation,
    impactAnalysis: input.impact,
    remediation: { vulnerableSnippet: input.vulnerable, secureSnippet: input.secure, language: 'text', explanation: input.remediation },
    remediated: false,
  };
}

async function wait(ms: number, control?: ScanControl, speed: '1x' | '2x' = '1x') {
  const duration = speed === '2x' ? Math.max(30, Math.round(ms / 2)) : ms;
  let done = 0;
  while (done < duration) {
    if (control?.aborted) throw new Error('URL pre-check cancelled by user.');
    while (control?.paused && !control.aborted) await new Promise((resolve) => window.setTimeout(resolve, 100));
    if (control?.aborted) throw new Error('URL pre-check cancelled by user.');
    const step = Math.min(50, duration - done);
    await new Promise((resolve) => window.setTimeout(resolve, step));
    done += step;
  }
}

/**
 * Browser-only URL hygiene check. It intentionally does not fetch the target,
 * because browser CORS and server-side request security prevent reliable header auditing here.
 */
export async function analyzeLiveUrlSecurity(
  targetUrl: string,
  onProgress: (update: ScanProgressUpdate) => void,
  control?: ScanControl,
  speed: '1x' | '2x' = '1x',
): Promise<ScanReport> {
  let parsed: URL;
  try { parsed = new URL(targetUrl); } catch { throw new Error('Enter a valid URL including https:// or http://.'); }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Only HTTP and HTTPS URLs are supported.');
  if (parsed.username || parsed.password) throw new Error('Remove embedded username/password credentials from the URL.');

  const start = Date.now();
  const findings: VulnerabilityFinding[] = [];
  const emit = (stageIndex: number, percent: number, text: string) => onProgress({
    stageIndex, overallPercent: percent, currentStageId: SCAN_STAGES[stageIndex].id,
    stageName: SCAN_STAGES[stageIndex].name, microTask: text,
    tokensAnalyzed: 0, rulesEvaluated: stageIndex + 1, threatsDetected: findings.length,
  });

  emit(0, 15, 'Parsing URL scheme, hostname, port and query parameter names. No network request is sent.');
  await wait(180, control, speed);

  if (parsed.protocol === 'http:') {
    findings.push(buildUrlFinding({
      id: 'url-http-transport', title: 'URL Uses Unencrypted HTTP', cwe: 'CWE-319', severity: 'high', endpoint: parsed.origin,
      matchedPattern: 'http:// scheme', explanation: 'The supplied URL uses HTTP rather than HTTPS. This check evaluates only the URL text; it does not verify the remote server or TLS certificate.',
      impact: 'If the endpoint is actually served over HTTP, traffic can be observed or modified in transit.',
      vulnerable: 'http://example.com/account', secure: 'https://example.com/account',
      remediation: 'Use HTTPS and verify the deployed service redirects HTTP to HTTPS with a valid certificate.',
    }));
  }

  const sensitiveParams = [...parsed.searchParams.keys()].filter((key) => /token|api[_-]?key|password|secret|authorization|bearer|session/i.test(key));
  if (sensitiveParams.length) {
    findings.push(buildUrlFinding({
      id: 'url-sensitive-query', title: 'Possible Sensitive Data in URL Query', cwe: 'CWE-598', severity: 'high', endpoint: parsed.origin,
      matchedPattern: `Sensitive-looking query parameter name(s): ${sensitiveParams.join(', ')}`,
      explanation: 'The URL contains query parameter names commonly used for credentials. The actual values are deliberately not copied into the report. Query strings can be retained in browser history, logs and referrer data.',
      impact: 'If these parameters contain live credentials, they may be exposed through logs, browser history, analytics or referrer headers.',
      vulnerable: 'https://example.com/api?access_token=VALUE', secure: 'https://example.com/api with credentials sent in an Authorization header',
      remediation: 'Do not place credentials in URLs. Rotate any real secret already exposed and transmit credentials using an appropriate authorization header or secure request body.',
    }));
  }

  const reportUrl = new URL(parsed.toString());
  for (const key of [...reportUrl.searchParams.keys()]) {
    if (/token|api[_-]?key|password|secret|authorization|bearer|session/i.test(key)) {
      reportUrl.searchParams.set(key, '[REDACTED]');
    }
  }

  const port = parsed.port;
  if (port && !['80', '443'].includes(port)) {
    findings.push(buildUrlFinding({
      id: 'url-nonstandard-port', title: 'Non-Standard URL Port', cwe: 'CWE-16', severity: 'info', endpoint: parsed.origin,
      matchedPattern: `Explicit port ${port}`, explanation: 'The URL specifies a non-default HTTP(S) port. This is not inherently a vulnerability, but the service exposure and firewall policy should be intentional.',
      impact: 'Unexpected exposed services can increase attack surface if they are not documented and access-controlled.',
      vulnerable: `https://${parsed.hostname}:${port}/`, secure: 'Use only the required, documented service ports.',
      remediation: 'Confirm that the port is expected, protected by a firewall, and mapped to the intended service.',
    }));
  }

  emit(2, 65, 'Evaluating URL-only hygiene rules. Remote response headers, cookies, CORS and TLS certificates are not inspected.');
  await wait(180, control, speed);
  emit(4, 100, `URL pre-check complete. ${findings.length} observation(s) need manual verification.`);

  const weights = { critical: 30, high: 20, medium: 10, low: 4, info: 0 };
  const score = Math.max(0, 100 - findings.reduce((sum, item) => sum + weights[item.severity], 0));
  const grade: ScanReport['grade'] = score >= 95 ? 'A+' : score >= 85 ? 'A' : score >= 70 ? 'B' : score >= 55 ? 'C' : score >= 40 ? 'D' : 'F';
  return {
    id: `url-precheck-${Date.now()}`, timestamp: new Date().toISOString(), targetUrl: reportUrl.toString(), method: 'URL_PRECHECK',
    durationMs: Date.now() - start, overallScore: score, grade, findings,
    recommendedHeaders: [
      { name: 'Strict-Transport-Security', recommendedValue: 'max-age=31536000; includeSubDomains', reason: 'Enable only after HTTPS is configured correctly on the host.' },
      { name: 'Content-Security-Policy', recommendedValue: "default-src 'self'; object-src 'none'; base-uri 'self'", reason: 'Adapt a restrictive policy to the resources used by the application.' },
      { name: 'X-Content-Type-Options', recommendedValue: 'nosniff', reason: 'Reduces MIME-type confusion.' },
      { name: 'Referrer-Policy', recommendedValue: 'strict-origin-when-cross-origin', reason: 'Limits referrer leakage.' },
    ],
  };
}
