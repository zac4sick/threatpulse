# Security policy

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through
[GitHub private vulnerability reporting](https://github.com/zac4sick/threatpulse/security/advisories/new).
You'll get a reply within 7 days. Please allow time for a fix before any disclosure.

In scope: the published site (https://zac4sick.github.io/threatpulse/), this repository's code and its GitHub Actions workflows.
Out of scope: third-party data sources and their content.

## How ThreatPulse protects itself

| Area | Control |
| --- | --- |
| Secrets | Stored only as GitHub Actions secrets, exposed to one build step, never written to the site. Each build checks that no secret value appears in `data.json`. Workflows never run on forked pull requests with secrets. |
| Workflow permissions | No default permissions. The build job is read-only. A separate deploy job has no secrets and can only publish Pages. `persist-credentials: false` on every checkout. |
| Supply chain | Every GitHub Action is pinned to a full commit SHA. Test dependencies are hash-pinned (`--require-hashes`). The data pipeline uses only the Python standard library. Dependabot proposes weekly updates. |
| Code scanning | CodeQL (`security-extended`) on Python, JavaScript and the workflows themselves, on every push and weekly. OpenSSF Scorecard runs weekly. |
| Browser | Strict Content-Security-Policy: no inline scripts, nothing from other origins, Trusted Types enforced. Subresource Integrity (sha384) on all scripts and styles. Anti-framing guard. `no-referrer`. |
| Untrusted feed data | Treated as hostile. HTML is stripped server-side, the DOM is built with `textContent` only, only `http(s)` links are rendered, onion links are removed, and malware indicators are shown defanged. |
| Data minimisation | No leaked data, credentials or leak-site screenshots are ever stored or linked. |
