# SENTINEL AI — WEB SECURITY & VULNERABILITY AUDITOR

## Major Project Report

### 1. Abstract
Sentinel AI is an educational web application security review dashboard. It accepts local source files and selected files from public GitHub repositories, applies predefined heuristic rules to source text, displays possible weaknesses with CWE and OWASP mappings, and produces a structured audit report. It also includes a URL-only hygiene pre-check, a 3D dashboard visualization, local demo profiles, and remediation examples.

### 2. Problem Statement
Developers can introduce security weaknesses when constructing SQL queries, rendering untrusted HTML, making outbound HTTP requests, embedding credentials in source code, or configuring cross-origin policies. Reviewing every source file manually can be time-consuming. This project demonstrates how a small set of defensive rules can help identify suspicious patterns and guide secure coding discussions.

### 3. Objectives
- Provide a browser-based interface for defensive source review.
- Detect selected risky patterns using transparent heuristic rules.
- Map findings to CWE identifiers and OWASP categories.
- Explain potential impact and provide safer code examples.
- Import a bounded set of source files from public GitHub repositories.
- Perform URL-text hygiene checks without contacting arbitrary targets.
- Generate a structured audit summary.

### 4. Scope and Limitations
The source analyzer uses regular expressions and string-pattern heuristics. It is not a full AST parser, taint-analysis engine, penetration-testing scanner, or proof of exploitability. The URL pre-check only inspects the submitted URL string; it does not fetch the target or inspect real response headers, cookies, CORS policy, TLS certificates, or server behavior. Demo sign-in stores a profile in browser localStorage and is not real authentication. No generative-AI model is connected; explanations are predefined rule-based guidance. Findings and scores are illustrative and require manual validation.

### 5. Technology Stack
- React 19 and TypeScript — user interface and application logic.
- Vite — development server and production bundling.
- Tailwind CSS 4 — styling.
- Three.js — 3D visualization.
- lucide-react — interface icons.
- Browser localStorage — demo profile and project-file state.

### 6. Main Modules
1. Dashboard and 3D visualization.
2. Source file uploader and code preview.
3. Rule-based source analyzer.
4. Public GitHub repository importer.
5. URL hygiene pre-check.
6. Vulnerability cards and remediation guidance.
7. Audit report generator.
8. Demo profile sign-in.

### 7. Detection Rules
- SQL injection indicators (CWE-89).
- Potential cross-site scripting sinks (CWE-79).
- Potential server-side request forgery paths (CWE-918).
- Possible hardcoded credentials (CWE-798).
- Wildcard CORS configuration (CWE-942).
- Missing visible security-header middleware in server-like files (CWE-693).
- HTTP URL scheme and sensitive-looking query parameter names.

### 8. Methodology
The user uploads source files, chooses a sample scenario, or imports a limited set of files from a public GitHub repository. The application evaluates source text against predefined detection patterns. A matching rule creates a finding containing severity, CWE/OWASP mapping, source location where available, explanation, impact, and a safer code example. The URL pre-check parses the submitted URL and checks its scheme, query parameter names, and explicit non-standard port. Sensitive-looking query values are redacted from the report URL. Findings are collected into a report with an illustrative score.

### 9. Verification Performed
- Parsed all 19 TypeScript/TSX source files with the TypeScript compiler API; no syntax diagnostics were reported.
- Checked relative source imports; no missing relative imports were found.
- Type-checked the dependency-free analyzer and URL-check modules against the shared security types.
- Ran smoke checks that observed expected SQL injection, XSS, and SSRF heuristic findings.
- Confirmed a parameterized SQL sample did not trigger the SQL injection rule.
- Confirmed the URL pre-check detects a sensitive-looking query parameter and redacts its value from the report URL.

A complete Vite production build was not run in the preparation environment because npm registry DNS access failed during dependency installation. Run `npm install`, `npm run lint`, and `npm run build` on the submission computer before submission.

### 10. Security and Ethical Use
Review only source code and repositories that you own or are authorized to assess. Do not upload production secrets, private keys, customer data, or confidential source code to an untrusted environment. GitHub import supports public repositories only and is subject to API limits. Demo authentication is not suitable for protecting real accounts. Confirm each finding manually before making security decisions.

### 11. Future Enhancements
- Add language-aware parsers and AST-based analysis.
- Add source-to-sink data-flow tracking.
- Add a trusted backend for real HTTP header checks with strict target authorization and SSRF protections.
- Add real authentication and access control.
- Add optional LLM explanations through a backend-managed API key.
- Add automated unit/integration tests and persistent audit history.

### 12. Conclusion
Sentinel AI demonstrates a practical workflow for introducing developers to common web-application security weaknesses and secure coding practices. It combines source-code review, vulnerability explanations, remediation examples, and reporting, while clearly identifying the limits of heuristic analysis.

### 13. References
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- MITRE CWE: https://cwe.mitre.org/
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- MDN Web Security: https://developer.mozilla.org/en-US/docs/Web/Security
