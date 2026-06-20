# VulnPulse pricing & API access

VulnPulse gates the CVE-intelligence feed behind an **API key + tier** model.
Free works with no signup (metered by IP); paid tiers unlock real-time data and
higher quotas. The machine-readable version of this table lives at
[`/api/pricing`](https://vulnpulse.ivixivi.workers.dev/api/pricing) — clients
should render their own upgrade UI from that endpoint rather than hard-coding it.

For endpoint contracts, response examples, and paid checkout flows, see the
full customer [API guide](./docs/API.md).

## Tiers

| Tier  | Price   | Daily API | Digest                | Raw CVE detail (`/api/cve/*`) | Real-time webhook |
|-------|---------|-----------|-----------------------|-------------------------------|-------------------|
| Free  | $0      | 50/day    | top 5 highlights      | **delayed 24h**               | —                 |
| Pro   | $29/mo  | 5,000/day | full                  | real-time                     | patch_now + filters |
| Team  | $99/mo  | 50,000/day| full                  | real-time                     | 5 webhooks + 5-min SLA |

"Delayed 24h" means a free caller can read a CVE record only once 24h have
passed since its last modification; newer records return `402` until then.
"top 5 highlights" means free digest/critical/patch-now responses are capped to
5 CVEs and carry a `gated` block telling the caller what's withheld.

## Authenticating

Send your key any of three ways (checked in this order):

```
Authorization: Bearer <api_key>     # preferred
X-API-Key: <api_key>
?api_key=<api_key>                   # convenient for a browser / quick curl
```

No key → you're treated as anonymous **free**, metered per source IP.
An unrecognized key → `401 invalid_api_key` (we don't silently downgrade).

Every gated response carries quota headers:

```
X-RateLimit-Limit: 50
X-RateLimit-Remaining: 47
X-VulnPulse-Tier: free
```

When the daily budget is spent you get `429 rate_limited` with a `Retry-After`
header (seconds until 00:00 UTC, when budgets reset).

## Getting a key

- **Free** — `POST /api/subscribe` with `{ "email": "you@example.com" }`.
  The response includes your `api_key`.
- **Pro / Team** — `POST /api/checkout` with
  `{ "email": "...", "tier": "pro" }`. When Stripe is configured, you'll get a
  `402` carrying `provider: "stripe"`, a `checkout_url`, and `session_id`.
  Complete Stripe Checkout, then `POST /api/checkout/claim` with
  `{ "session_id" }`; the success response includes your paid `api_key`.
  If Stripe is not configured, checkout falls back to a USDC quote and
  `POST /api/confirm` with `{ "quote_id", "tx_hash" }`.

Paid API keys remain tied to their backing subscription. If Stripe later sends a
cancellation or failed-payment webhook, premium endpoints return
`402 subscription_inactive` until the subscription is active again.

See [`/api/rails`](https://vulnpulse.ivixivi.workers.dev/api/rails) for every
active payment rail (crypto, GitHub Sponsors, Buy Me a Coffee, Stripe).

## Which endpoints are gated

Gated (resolve tier + count against quota):

```
GET /api/digest/latest
GET /api/digest/history
GET /api/critical
GET /api/patch-now
GET /api/cve/CVE-YYYY-XXXXX     # also 24h-delayed for free
```

Ungated (control plane & discovery — free, unmetered):

```
POST /api/subscribe   POST /api/checkout  POST /api/checkout/claim
POST /api/confirm     GET /api/pay-status
GET  /api/status      GET /api/rails      GET /api/pricing     GET /api/me
POST /api/run-now     # separately rate-limited: 1/hour/IP
```

`GET /api/me` reports your resolved tier and today's usage without spending a
request — poll it from a dashboard freely.
