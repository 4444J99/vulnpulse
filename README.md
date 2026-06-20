# VulnPulse

> Defender-side CVE intelligence. Patch what matters, ignore the rest.

**Live:** https://vulnpulse.ivixivi.workers.dev

**API docs:** [docs/API.md](./docs/API.md)

VulnPulse turns the NVD CVE firehose into a short, defender-focused feed. It
pulls high and critical CVEs (CVSS >= 7.0) from the NVD JSON 2.0 API, runs the
top findings through Cloudflare Workers AI, and stores a daily digest with
plain-English impact, mitigation guidance, exploitability, tags, and a
`patch_now` priority flag.

The hosted service is useful without an account: anonymous callers get the free
tier, metered by IP. API keys unlock quota tracking by account, and paid tiers
unlock the full real-time feed, raw CVE detail without the free-tier delay, and
webhook-oriented workflows.

## What It Is

VulnPulse is a Cloudflare Worker with three jobs:

- **Collect** - scheduled Worker cron fetches recently modified high and
  critical CVEs from NVD. The deployed cron runs daily at 12:00 UTC and fetches
  the last 24 hours.
- **Summarize** - Workers AI summarizes the highest-priority CVEs for impact,
  likely exploitability, mitigation, tags, and product class.
- **Gate and serve** - JSON endpoints expose the latest digest, digest history,
  critical-only views, patch-now views, and individual CVE detail under a
  tiered API key model.

The output is intentionally operational. Instead of asking an engineer to read
every NVD entry, VulnPulse answers:

- What does an attacker get?
- Is this remotely reachable or auth-gated?
- Is there enough signal to patch this week?
- Is there a mitigation or only a vendor patch?
- Which class of system is affected: web app, library, cloud, container,
  browser, IoT, kernel, and so on?

## Who Pays

VulnPulse is built for teams that already care about CVEs but do not want to
triage the full NVD stream manually.

- **Free users** are individual defenders, founders, students, and small teams
  who want a daily pulse and a small public API budget.
- **Pro buyers** are security engineers, platform teams, SREs, and startup
  operators who need real-time raw CVE detail, full digests, higher API limits,
  and `patch_now` automation.
- **Team buyers** are SOCs, MSSPs, platform/security teams, and product security
  groups that need multiple webhook destinations, larger quotas, and an
  operational SLA.

The commercial hook is time saved during patch triage. Free gives enough signal
to trust the feed; paid unlocks the parts teams wire into Slack, Teams,
PagerDuty, internal dashboards, and patch-management workflows.

## Install

### Use The Hosted API

You can use the hosted API immediately:

```sh
curl https://vulnpulse.ivixivi.workers.dev/api/digest/latest
```

No key means anonymous free tier. To get a free API key:

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/subscribe \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com"}'
```

Send the returned key as `Authorization: Bearer <api_key>`.

### Run Your Own Worker

Prerequisites:

- Node.js 20+
- npm
- A Cloudflare account with Workers, Workers AI, Workers KV, and Wrangler access

Clone and install:

```sh
git clone https://github.com/4444J99/vulnpulse.git
cd vulnpulse
npm install
```

Create the KV namespaces if you are deploying your own copy:

```sh
npx wrangler kv namespace create VP_CVES
npx wrangler kv namespace create VP_DIGEST
npx wrangler kv namespace create VP_SUBS
```

Put the generated namespace IDs into `wrangler.toml`.

Required binding/config:

- `AI` - Cloudflare Workers AI binding
- `ASSETS` - static asset binding for `public/`
- `VP_CVES` - CVE records and rate counters
- `VP_DIGEST` - latest and historical digest records
- `VP_SUBS` - subscriptions, pending quotes, and API key records
- `USER_AGENT` - NVD-friendly user agent string
- `STRIPE_SECRET_KEY` plus `STRIPE_PRO_PRICE_ID` / `STRIPE_TEAM_PRICE_ID` -
  preferred paid subscription checkout
- `STRIPE_WEBHOOK_SECRET` - verifies Stripe events at `/api/webhooks/stripe`
- `PAYRAIL` service binding or `PAYRAIL_URL` - USDC checkout/receipt fallback

Optional monetization settings:

```sh
npx wrangler secret put TREASURY_WALLET
npx wrangler secret put SHIP_HMAC_SECRET
npx wrangler secret put STRIPE_PUBLIC
npx wrangler secret put BMC_HANDLE
```

Run checks:

```sh
npm test
npm run typecheck
npm run build
```

Run locally:

```sh
npx wrangler dev
```

Deploy:

```sh
npx wrangler deploy
```

## Usage

All API responses are JSON.

For customer-ready endpoint contracts, response schemas, payment flows, and
copy-paste integration examples, see the full [API guide](./docs/API.md).

### Authentication

Keys can be supplied three ways:

```http
Authorization: Bearer <api_key>
X-API-Key: <api_key>
?api_key=<api_key>
```

No key resolves to anonymous **free** tier, metered by source IP. A bad key
returns `401 invalid_api_key`; it does not silently downgrade to free.

Gated responses include quota headers:

```http
X-RateLimit-Limit: 50
X-RateLimit-Remaining: 49
X-VulnPulse-Tier: free
```

When the daily budget is spent, the API returns `429 rate_limited` with
`Retry-After` seconds until the next UTC reset.

### Common Calls

Get the latest digest:

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/digest/latest \
  -H "Authorization: Bearer $VULNPULSE_API_KEY"
```

Get only CVSS 9.0+ records from the latest digest:

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/critical \
  -H "Authorization: Bearer $VULNPULSE_API_KEY"
```

Get the current `patch_now` list:

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/patch-now \
  -H "Authorization: Bearer $VULNPULSE_API_KEY"
```

Fetch a specific CVE:

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/cve/CVE-2026-12345 \
  -H "Authorization: Bearer $VULNPULSE_API_KEY"
```

Check your resolved tier and quota usage without spending quota:

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/me \
  -H "Authorization: Bearer $VULNPULSE_API_KEY"
```

Trigger a manual collection run:

```sh
curl -sS -X POST https://vulnpulse.ivixivi.workers.dev/api/run-now
```

`/api/run-now` is separately rate-limited to one request per hour per IP.

## API Reference

The full customer reference lives in [docs/API.md](./docs/API.md). The short
index below mirrors the implemented route surface.

Gated CVE-intelligence endpoints resolve a tier and count against the caller's
daily quota:

```http
GET /api/digest/latest
GET /api/digest/history
GET /api/critical
GET /api/patch-now
GET /api/cve/CVE-YYYY-XXXXX
```

Control-plane and discovery endpoints are not counted against the CVE
intelligence quota:

```http
POST /api/subscribe
POST /api/checkout
GET  /api/checkout/claim
POST /api/checkout/claim
POST /api/confirm
GET  /api/pay-status
GET  /api/pricing
GET  /api/me
GET  /api/rails
GET  /api/status
POST /api/run-now
```

## Pricing And Monetization

The source of truth for the current tier matrix is the machine-readable
`GET /api/pricing` endpoint. The prose below mirrors the implemented product
model.

| Tier | Price | Daily API quota | Digest | Raw CVE detail | Commercial use case |
| --- | ---: | ---: | --- | --- | --- |
| Free | $0 | 50/day | Top 5 highlights | 24h delayed | Try the feed, daily pulse, light scripts |
| Pro | $29/mo | 5,000/day | Full | Real-time | Patch triage automation for one team |
| Team | $99/mo | 50,000/day | Full | Real-time | SOC/platform workflows with multiple destinations |

Tier entitlements:

- **Free** - daily digest, email digest, public API, top-five highlights on
  digest/list endpoints, and raw CVE detail delayed by 24 hours.
- **Pro** - full digest, real-time raw CVE detail, custom filters, real-time
  `patch_now` webhook entitlement, and 5,000 API calls per day.
- **Team** - everything in Pro, five webhook destinations
  (Slack/Teams/PagerDuty-style workflows), 50,000 API calls per day, and a
  5-minute SLA target from NVD publish.

Paid checkout flow:

1. Start a paid checkout:

   ```sh
   curl -i https://vulnpulse.ivixivi.workers.dev/api/checkout \
     -H 'content-type: application/json' \
     -d '{"email":"sec@example.com","tier":"pro"}'
   ```

2. If Stripe is configured, the API returns `402 payment_required` with
   `provider: "stripe"`, a `checkout_url`, and a `session_id`. Redirect the
   user to `checkout_url`.
3. After Stripe redirects back, claim the paid API key:

   ```sh
   curl -sS https://vulnpulse.ivixivi.workers.dev/api/checkout/claim \
     -H 'content-type: application/json' \
     -d '{"session_id":"cs_test_..."}'
   ```

4. Stripe webhooks also activate and revoke paid licenses. Configure the Stripe
   endpoint as:

   ```http
   POST /api/webhooks/stripe
   ```

5. If Stripe is not configured, the same checkout endpoint falls back to the
   USDC rail and returns a `quote_id`, payment details, instructions, and
   `confirm_url`. Pay through the returned rail, then confirm:

   ```sh
   curl -sS https://vulnpulse.ivixivi.workers.dev/api/confirm \
     -H 'content-type: application/json' \
     -d '{"quote_id":"quote_pro_123","tx_hash":"0x..."}'
   ```

The successful claim/confirm response returns a paid API key. Paid keys work
only while the backing subscription is active; canceled or past-due Stripe
subscriptions return `402 subscription_inactive` on premium endpoints.

Payment/discovery rails:

- **Stripe Checkout** - preferred subscription checkout when
  `STRIPE_SECRET_KEY` and tier price IDs are configured.
- **USDC crypto checkout** - live through the payrail quote/receipt flow.
- **GitHub Sponsors** - https://github.com/sponsors/4444J99
- **Buy Me a Coffee** - exposed when `BMC_HANDLE` is configured.

Clients should read `GET /api/rails` and `GET /api/pricing` instead of
hard-coding payment availability or tier metadata.

Full gate details live in [PRICING.md](./PRICING.md).

## Data Model

Each summarized CVE keeps the NVD basics plus AI triage fields:

```json
{
  "id": "CVE-2026-12345",
  "published": "2026-06-18T00:00:00.000Z",
  "modified": "2026-06-18T12:00:00.000Z",
  "cvss_score": 9.8,
  "severity": "CRITICAL",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "description": "...",
  "references": ["https://example.com/advisory"],
  "cwe_ids": ["CWE-79"],
  "ai_impact": "...",
  "ai_mitigation": "...",
  "ai_exploitability": "poc_likely",
  "ai_priority": "patch_now",
  "ai_tags": ["rce", "web"],
  "ai_class": "web-app"
}
```

## Stack

- Cloudflare Workers for HTTP, cron, and deployment
- Cloudflare Workers AI for CVE summarization
- Cloudflare Workers KV for CVEs, digests, subscriptions, and API counters
- Cloudflare static assets for the hosted page in `public/`
- NVD JSON 2.0 API as the public CVE source
- Stripe Checkout for paid subscriptions and subscription-status webhooks
- Payrail service binding for quote and receipt handling

## Development

Useful commands:

```sh
npm test          # vitest + node:test Worker tests
npm run lint     # eslint
npm run typecheck
npm run build    # wrangler dry-run deploy build
```

The tests use in-memory Worker bindings and do not require live Cloudflare
services.

## Sister Products

VulnPulse is part of an intelligence portfolio:

- [PromptScope](https://promptscope.ivixivi.workers.dev) - LLM system-prompt analyzer
- [EdgarFlash](https://edgarflash.ivixivi.workers.dev) - Real-time SEC EDGAR alerts
- [WriteLens](https://writelens.ivixivi.workers.dev) - Pay-per-call text quality scoring
- [BountyScope](https://bountyscope.ivixivi.workers.dev) - Bug-bounty intel + smart-contract analyzer
- [TrendPulse](https://trendpulse.ivixivi.workers.dev) - Daily emerging-tech digest

## License

MIT - see [LICENSE](./LICENSE).
