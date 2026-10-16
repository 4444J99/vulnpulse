# Security Policy

VulnPulse is a defender-side tool, so we take reports about VulnPulse itself seriously.

## Supported versions

Only the current `main` branch, as deployed at https://vulnpulse.ivixivi.workers.dev, gets security fixes.

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/4444J99/vulnpulse/security/advisories/new)
("Security" tab → "Report a vulnerability"). Include:

- what is affected (endpoint, webhook, build step or dependency)
- steps to reproduce or a proof of concept
- the impact you expect (data exposure, auth bypass, denial of service, …)

You can expect an acknowledgement within 7 days and a status update after triage.
Please give us a reasonable window to ship a fix before you disclose anything publicly.

## Scope

In scope: the VulnPulse Worker, its API and webhooks, and this repository's code and CI.

Out of scope: vulnerabilities in the upstream CVE data itself (report those to NVD or the
CNA that published the record), and findings that need a compromised Cloudflare account.
