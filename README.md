# VulnPulse

> Defender-side CVE feed. Patch what matters, ignore the rest.

**Live:** https://vulnpulse.ivixivi.workers.dev

VulnPulse polls the NVD JSON 2.0 feed every 6 hours for high+critical CVEs (CVSS ≥ 7.0)
modified in the last 24h, AI-summarizes each one for impact + mitigation priority, and
serves a free daily digest plus paid real-time webhooks for security teams that need
to know which CVE actually requires action *today*.

## What you get

- **Daily digest** — top high+critical CVEs from the last 24h, AI-summarized
- **patch_now flag** — automated triage: which ones a defender actually needs to act on this week
- **Plain-English impact** — what an attacker gets, auth required, network reachable
- **Mitigation guidance** — patch version, config change, or workaround
- **Tag classification** — web, auth, rce, ssrf, deserialize, supply-chain, container, cloud, iot, …
- **Class breakdown** — web-app, network-stack, os-kernel, browser, library, sdk, cms, …

## API

```
GET  /api/digest/latest      — Today's full digest
GET  /api/digest/history     — Last 30 daily digests
GET  /api/critical           — Just CVSS 9.0+ from latest digest
GET  /api/patch-now          — Highlights flagged patch_now
GET  /api/cve/CVE-YYYY-XXXXX — Specific CVE detail
POST /api/subscribe          — Email or webhook subscription (JSON body)
GET  /api/rails              — Active payment rails (crypto/sponsors/stripe/bmc)
GET  /api/status             — System health
POST /api/run-now            — Manual collection trigger (1/hour/IP rate limit)
```

## Pricing

| Tier  | Price          | What's included                                                   |
|-------|----------------|-------------------------------------------------------------------|
| Free  | $0             | Daily digest + email + public API (50/day) + 24h-delayed CVEs    |
| Pro   | $29/mo         | Real-time webhook on patch_now + custom filters + API (5000/day) |
| Team  | $99/mo         | 5 webhooks (Slack/Teams/PagerDuty) + API (50000/day) + 5-min SLA |

**Pay any rail:**
- Crypto (USDC) — see `/api/rails`
- GitHub Sponsors — https://github.com/sponsors/4444J99
- Buy Me a Coffee — see `/api/rails`
- Stripe Checkout — activating

## Stack

- Cloudflare Workers (compute + cron)
- Cloudflare Workers AI — Llama 3.3 70B for CVE summarization
- Cloudflare KV — CVE storage, daily digest archive, subscription list
- NVD JSON 2.0 API — public CVE source

## Sister products

VulnPulse is part of an intelligence portfolio:

- [PromptScope](https://promptscope.ivixivi.workers.dev) — LLM system-prompt analyzer
- [EdgarFlash](https://edgarflash.ivixivi.workers.dev) — Real-time SEC EDGAR alerts
- [WriteLens](https://writelens.ivixivi.workers.dev) — Pay-per-call text quality scoring
- [BountyScope](https://bountyscope.ivixivi.workers.dev) — Bug-bounty intel + smart-contract analyzer
- [TrendPulse](https://trendpulse.ivixivi.workers.dev) — Daily emerging-tech digest

## License

MIT — see [LICENSE](./LICENSE).
