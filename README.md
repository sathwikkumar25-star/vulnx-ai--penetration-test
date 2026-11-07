# Sentinel AI — Web Security & Vulnerability Auditor

Sentinel AI is an educational React + TypeScript dashboard for defensive source-code review. It checks uploaded source files and selected public GitHub repository files against transparent heuristic patterns, presents possible findings with CWE/OWASP context and remediation examples, and generates an audit report.

## Run in VS Code

Requirements: Node.js 22 LTS (Node 22.12+ recommended) and npm.

```powershell
npm install
npm run lint
npm run build
npm run dev
```

Open http://localhost:3000.

## Features

- Upload and inspect local source files.
- Review sample code scenarios.
- Import a bounded number of files from public GitHub repositories.
- Heuristic checks for possible SQL injection, XSS sinks, SSRF patterns, hardcoded secrets, permissive CORS, and visible security-header middleware configuration.
- URL-text hygiene pre-check for HTTP URLs, credential-like query parameter names, and non-standard ports.
- Findings, remediation examples, report export, progress, pause/resume/cancel, and 3D visualization.
- Local demo profile stored in browser localStorage.

## Important technical limitations

This is a defensive educational prototype, not a production security scanner or penetration-testing tool.

- Source scanning uses regular expressions and text heuristics. It is not full AST parsing, taint analysis, exploit validation, or proof that a finding is exploitable.
- URL mode inspects only the URL string. It does not contact the remote target or verify live response headers, TLS, cookies, CORS, or server configuration.
- Explanations are predefined rule-based guidance. A generative AI model is not connected in this build.
- Sign-in is a local demo profile only. It is not password-backed or suitable for real account security.
- The remediation control records review status; it does not automatically rewrite source files.
- GitHub import is for public repositories and is subject to GitHub API limits.
- Findings and scores are indicative; manually verify each result.

## Ethical use

Only inspect source code and repositories you own or are explicitly authorized to review. Do not upload private keys, production secrets, customer data, or confidential source code to an untrusted environment.

## Project structure

```text
components/  React UI components
context/     Demo authentication context
data/        Sample scan targets
services/    Analyzer, GitHub importer, URL pre-check, audio
types/       Shared TypeScript interfaces
App.tsx      Main application
main.tsx     React entry point
index.html   Vite HTML entry point
```

## Academic description

**Title:** Sentinel AI — Web Security & Vulnerability Auditor  
**Domain:** Application Security / Secure Software Engineering  
**Objective:** Demonstrate how selected insecure coding patterns can be identified and explained through defensive, rule-based source review and how developers can apply safer coding practices.
