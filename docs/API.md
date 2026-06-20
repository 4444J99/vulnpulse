# VulnPulse API Guide

Customer-facing reference for using VulnPulse in scripts, dashboards, patch
triage workflows, and paid subscription onboarding.

Base URL:

```text
https://vulnpulse.ivixivi.workers.dev
```

All API responses are JSON. Request bodies must be JSON and should be sent with
`Content-Type: application/json`.

## Quick Start

Get a free API key:

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/subscribe \
  -H 'content-type: application/json' \
  -d '{"email":"security@example.com"}'
```

Save the returned `api_key` in your environment:

```sh
export VULNPULSE_API_KEY='vpf_...'
```

Read the latest digest:

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/digest/latest \
  -H "Authorization: Bearer $VULNPULSE_API_KEY"
```

Check your tier and quota without spending API quota:

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/me \
  -H "Authorization: Bearer $VULNPULSE_API_KEY"
```

For paid access, start checkout:

```sh
curl -i https://vulnpulse.ivixivi.workers.dev/api/checkout \
  -H 'content-type: application/json' \
  -d '{"email":"security@example.com","tier":"pro"}'
```

The checkout response is intentionally `402 Payment Required`. It contains
either a Stripe Checkout URL or a USDC payrail quote, depending on the active
payment rails.

## Authentication

VulnPulse accepts API keys in this order:

```http
Authorization: Bearer <api_key>
X-API-Key: <api_key>
?api_key=<api_key>
```

Use the `Authorization` header for production integrations. Query-string keys
are convenient for manual browser testing, but they can be logged by browsers,
proxies, and observability tools.

Authentication behavior:

- No key means anonymous `free` tier, metered by source IP.
- A valid free key is still `free` tier, but quota is tracked by key.
- A valid paid key resolves to `pro` or `team`.
- An unknown key returns `401 invalid_api_key`; the API does not silently
  downgrade bad keys to anonymous free access.
- Paid keys only work while the backing subscription is active. Canceled or
  past-due Stripe subscriptions return `402 subscription_inactive`.

Gated CVE-intelligence responses include quota headers:

```http
X-RateLimit-Limit: 5000
X-RateLimit-Remaining: 4999
X-VulnPulse-Tier: pro
```

Daily limits reset at 00:00 UTC. When a daily limit is spent, the API returns
`429 rate_limited` with `Retry-After` and `retry_after_seconds`.

## Tiers

The machine-readable source of truth is `GET /api/pricing`.

| Tier | Monthly price | Daily API quota | Digest access | CVE detail |
| --- | ---: | ---: | --- | --- |
| `free` | `$0` | `50` | Top 5 highlights | 24h delayed |
| `pro` | `$29` | `5,000` | Full | Real-time |
| `team` | `$99` | `50,000` | Full | Real-time |

Free-tier limits:

- Digest-style endpoints only show up to five highlights.
- `GET /api/cve/{id}` returns `402 gated` for records modified less than 24
  hours ago.

Paid-tier benefits:

- Full digest and history payloads.
- Real-time raw CVE detail.
- Higher daily quotas.
- Subscription status is enforced from Stripe license events when Stripe is the
  payment provider.

## Endpoint Summary

Gated endpoints count against daily CVE-intelligence quota:

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/api/digest/latest` | Latest generated daily digest. |
| `GET` | `/api/digest/history` | Up to 30 historical daily digests. |
| `GET` | `/api/critical` | Critical CVEs from the latest digest highlights. |
| `GET` | `/api/patch-now` | Latest highlights with `ai_priority: "patch_now"`. |
| `GET` | `/api/cve/{cve_id}` | Raw/summarized CVE detail from the recent CVE cache. |

Ungated control-plane and discovery endpoints:

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/api/subscribe` | Issue a free key, or start checkout if a paid tier is requested. |
| `POST` | `/api/checkout` | Start paid checkout for `pro` or `team`. |
| `GET` | `/api/checkout/claim` | Claim a paid key after Stripe Checkout. |
| `POST` | `/api/checkout/claim` | Claim a paid key after Stripe Checkout. |
| `POST` | `/api/confirm` | Confirm a USDC payrail payment and issue a paid key. |
| `GET` | `/api/pay-status` | Poll payrail receipt status by quote id. |
| `GET` | `/api/pricing` | Machine-readable pricing and entitlement matrix. |
| `GET` | `/api/me` | Caller tier, subscription state, and quota usage. |
| `GET` | `/api/rails` | Active payment rails. |
| `GET` | `/api/status` | Service status and feature flags. |
| `POST` | `/api/run-now` | Manually trigger collection; separate 1/hour/IP limit. |
| `POST` | `/api/webhooks/stripe` | Stripe license webhook receiver for the operator. |

`/api/webhooks/stripe` is not a customer CVE notification endpoint. Customer
integrations should use the pull endpoints above unless a separate webhook
delivery arrangement is configured by the operator.

## Data Models

### CVE Object

```json
{
  "id": "CVE-2026-12345",
  "published": "2026-06-18T00:00:00.000Z",
  "modified": "2026-06-18T12:00:00.000Z",
  "cvss_score": 9.8,
  "severity": "CRITICAL",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "description": "Vendor-provided NVD description, truncated at 1200 characters.",
  "references": ["https://vendor.example/advisory"],
  "cwe_ids": ["CWE-79"],
  "ai_impact": "Plain-English impact summary for defenders.",
  "ai_mitigation": "Patch or mitigation guidance.",
  "ai_exploitability": "poc_likely",
  "ai_priority": "patch_now",
  "ai_tags": ["rce", "web"],
  "ai_class": "web-app"
}
```

AI fields may be absent when an entry was not summarized or the model did not
return a valid strict JSON summary. Always tolerate missing `ai_*` fields.

Known enum values:

- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`
- `ai_exploitability`: `in_the_wild`, `poc_likely`, `theoretical`, `unknown`
- `ai_priority`: `patch_now`, `patch_soon`, `monitor`, `low`
- `ai_class`: `web-app`, `network-stack`, `os-kernel`, `browser`, `library`,
  `sdk`, `cms`, `container`, `cloud`, `iot-firmware`, `hardware`, `mobile`,
  `ai-ml`, `smart-contract`, `dev-tool`, `other`

### Digest Object

```json
{
  "generated_at": "2026-06-19T12:00:00.000Z",
  "date_label": "2026-06-19",
  "total_cves": 12,
  "critical_count": 4,
  "high_count": 8,
  "one_line": "4 critical / 8 high CVEs in last 24h \u2014 3 flagged patch-now.",
  "highlights": [],
  "by_class": {
    "web-app": 6,
    "library": 3
  },
  "patch_now_ids": ["CVE-2026-12345"]
}
```

Free digest responses add a `gated` object and cap `highlights`:

```json
{
  "gated": {
    "tier": "free",
    "highlights_shown": 5,
    "highlights_total": 10,
    "raw_cve_detail": "delayed 24h on /api/cve/* \u2014 Pro/Team is real-time",
    "upgrade": "/api/pricing"
  }
}
```

## CVE Intelligence Endpoints

### `GET /api/digest/latest`

Returns the latest digest. Counts against daily quota.

Example:

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/digest/latest \
  -H "Authorization: Bearer $VULNPULSE_API_KEY"
```

Response:

```json
{
  "generated_at": "2026-06-19T12:00:00.000Z",
  "date_label": "2026-06-19",
  "total_cves": 2,
  "critical_count": 1,
  "high_count": 1,
  "one_line": "1 critical / 1 high CVEs in last 24h \u2014 1 flagged patch-now.",
  "highlights": [
    {
      "id": "CVE-2026-12345",
      "cvss_score": 9.8,
      "severity": "CRITICAL",
      "ai_priority": "patch_now"
    }
  ],
  "by_class": {
    "web-app": 1
  },
  "patch_now_ids": ["CVE-2026-12345"]
}
```

If no digest has been generated yet, the endpoint returns `202`:

```json
{
  "message": "no digest yet \u2014 first cron run produces it within 6 hours",
  "hint": "POST /api/run-now to trigger collection (rate-limited)"
}
```

### `GET /api/digest/history`

Returns up to 30 historical daily digests, newest first. Counts against daily
quota.

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/digest/history \
  -H "Authorization: Bearer $VULNPULSE_API_KEY"
```

Response:

```json
{
  "count": 2,
  "digests": [
    {
      "generated_at": "2026-06-19T12:00:00.000Z",
      "date_label": "2026-06-19",
      "total_cves": 12,
      "critical_count": 4,
      "high_count": 8,
      "one_line": "4 critical / 8 high CVEs in last 24h \u2014 3 flagged patch-now.",
      "highlights": [],
      "by_class": {},
      "patch_now_ids": []
    }
  ]
}
```

### `GET /api/critical`

Returns `CRITICAL` CVEs from the latest digest highlights. Counts against daily
quota.

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/critical \
  -H "Authorization: Bearer $VULNPULSE_API_KEY"
```

Response:

```json
{
  "generated_at": "2026-06-19T12:00:00.000Z",
  "critical": [
    {
      "id": "CVE-2026-12345",
      "cvss_score": 9.8,
      "severity": "CRITICAL",
      "ai_priority": "patch_now"
    }
  ]
}
```

Free responses may include:

```json
{
  "gated": {
    "tier": "free",
    "limit": 5,
    "upgrade": "/api/pricing"
  }
}
```

### `GET /api/patch-now`

Returns latest digest highlights where `ai_priority` is `patch_now`. Counts
against daily quota.

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/patch-now \
  -H "Authorization: Bearer $VULNPULSE_API_KEY"
```

Response:

```json
{
  "generated_at": "2026-06-19T12:00:00.000Z",
  "patch_now": [
    {
      "id": "CVE-2026-12345",
      "cvss_score": 9.8,
      "severity": "CRITICAL",
      "ai_priority": "patch_now",
      "ai_impact": "Remote unauthenticated compromise is likely."
    }
  ]
}
```

### `GET /api/cve/{cve_id}`

Returns a single CVE record from the recent CVE cache. Counts against daily
quota.

`cve_id` must match `CVE-YYYY-NNNN` with four or more digits in the final
segment.

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/cve/CVE-2026-12345 \
  -H "Authorization: Bearer $VULNPULSE_API_KEY"
```

Paid response:

```json
{
  "id": "CVE-2026-12345",
  "published": "2026-06-18T00:00:00.000Z",
  "modified": "2026-06-18T12:00:00.000Z",
  "cvss_score": 9.8,
  "severity": "CRITICAL",
  "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "description": "A remote attacker can ...",
  "references": ["https://vendor.example/advisory"],
  "cwe_ids": ["CWE-79"],
  "ai_priority": "patch_now"
}
```

Free response for a real-time record:

```json
{
  "error": "gated",
  "reason": "realtime_cve_detail",
  "detail": "Free tier sees CVE detail 24h after last modification. This record is newer.",
  "available_at": "2026-06-19T12:00:00.000Z",
  "upgrade": "/api/pricing"
}
```

## Account And Payment Endpoints

### `POST /api/subscribe`

Creates a free subscription and returns an API key. This endpoint also accepts
paid tiers and starts checkout, but new paid integrations should prefer
`POST /api/checkout`.

Request:

```json
{
  "email": "security@example.com",
  "webhook": "https://example.com/vulnpulse-webhook",
  "filter": {
    "min_score": 7,
    "classes": ["web-app", "library"],
    "tags": ["rce", "auth"]
  }
}
```

`email` or `webhook` is required. `webhook` must be an `http` or `https` URL.

Example:

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/subscribe \
  -H 'content-type: application/json' \
  -d '{"email":"security@example.com"}'
```

Response:

```json
{
  "ok": true,
  "tier": "free",
  "ident_hash": "1a2b3c4d",
  "api_key": "vpf_...",
  "api_key_usage": "send as \"Authorization: Bearer <key>\" or ?api_key=. Free tier: 50 req/day, raw CVE detail delayed 24h."
}
```

### `POST /api/checkout`

Starts paid checkout for `pro` or `team`.

Request:

```json
{
  "email": "security@example.com",
  "tier": "pro",
  "webhook": "https://example.com/vulnpulse-webhook",
  "filter": {
    "min_score": 9,
    "classes": ["web-app"],
    "tags": ["rce"]
  }
}
```

`email` must be valid. `tier` must be `pro` or `team`.

Stripe response:

```json
{
  "status": "payment_required",
  "provider": "stripe",
  "tier": "pro",
  "checkout": "https://checkout.stripe.com/c/pay/cs_test_...",
  "checkout_url": "https://checkout.stripe.com/c/pay/cs_test_...",
  "session_id": "cs_test_...",
  "claim_url": "/api/checkout/claim",
  "instructions": "Complete Stripe Checkout, then return here to claim your paid API key."
}
```

Payrail fallback response:

```json
{
  "status": "payment_required",
  "provider": "payrail",
  "tier": "pro",
  "quote_id": "quote_pro_123",
  "pay_to": {
    "rail": "crypto",
    "chain": "base",
    "asset": "USDC",
    "address": "0xabc...",
    "amount": "29"
  },
  "checkout": null,
  "instructions": "Send USDC and include the quote id.",
  "expires_in_seconds": 900,
  "confirm_url": "/api/confirm"
}
```

### `GET /api/checkout/claim`

Claims a paid API key after Stripe Checkout.

```sh
curl -sS 'https://vulnpulse.ivixivi.workers.dev/api/checkout/claim?session_id=cs_test_...'
```

### `POST /api/checkout/claim`

Claims a paid API key after Stripe Checkout using a JSON body.

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/checkout/claim \
  -H 'content-type: application/json' \
  -d '{"session_id":"cs_test_..."}'
```

Success response:

```json
{
  "ok": true,
  "provider": "stripe",
  "tier": "pro",
  "subscription_status": "active",
  "api_key": "vpp_...",
  "api_key_usage": "send as \"Authorization: Bearer <key>\". Real-time access + 5000 req/day while your subscription is active."
}
```

If checkout is not complete yet:

```json
{
  "error": "payment_pending",
  "message": "Stripe Checkout session is not complete yet",
  "provider": "stripe",
  "session_id": "cs_test_...",
  "status": "open",
  "payment_status": "unpaid"
}
```

### `POST /api/confirm`

Confirms a USDC payrail payment and issues a paid key.

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/confirm \
  -H 'content-type: application/json' \
  -d '{"quote_id":"quote_pro_123","tx_hash":"0xdeadbeef"}'
```

Response:

```json
{
  "ok": true,
  "tier": "pro",
  "api_key": "vpp_...",
  "api_key_usage": "send as \"Authorization: Bearer <key>\". Real-time access + 5000 req/day.",
  "receipt": {
    "id": "receipt_123"
  }
}
```

### `GET /api/pay-status`

Polls payrail receipt status.

```sh
curl -sS 'https://vulnpulse.ivixivi.workers.dev/api/pay-status?quote_id=quote_pro_123'
```

Unpaid response:

```json
{
  "paid": false,
  "quote_id": "quote_pro_123"
}
```

Paid response:

```json
{
  "paid": true,
  "receipt": {
    "id": "receipt_123"
  }
}
```

## Discovery And Status Endpoints

### `GET /api/me`

Reports the caller's resolved tier and quota usage. This endpoint does not count
against daily CVE-intelligence quota.

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/me \
  -H "Authorization: Bearer $VULNPULSE_API_KEY"
```

Response:

```json
{
  "tier": "pro",
  "authenticated": true,
  "active": true,
  "subscription_status": "active",
  "provider": "stripe",
  "daily_limit": 5000,
  "used_today": 17,
  "remaining_today": 4983,
  "resets_in_seconds": 33120
}
```

### `GET /api/pricing`

Returns machine-readable pricing, auth, tier, and checkout metadata.

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/pricing
```

Use this endpoint to render upgrade UI instead of hard-coding tier metadata.

### `GET /api/rails`

Returns currently active payment rails.

```json
{
  "crypto": "0xwallet...",
  "sponsors_url": "https://github.com/sponsors/4444J99",
  "stripe_active": true,
  "stripe_checkout": "/api/checkout",
  "stripe_claim": "/api/checkout/claim",
  "bmc_url": "https://www.buymeacoffee.com/vulnpulse"
}
```

Unavailable rails are returned as `null` or `false`.

### `GET /api/status`

Returns service status, digest availability, subscriber presence, tier limits,
and enabled revenue rails.

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/status
```

Response:

```json
{
  "name": "VulnPulse",
  "has_latest_digest": true,
  "sample_cve": "CVE-2026-4001",
  "has_subscribers": true,
  "subscription_gate": {
    "enabled": true,
    "tiers": {
      "free": 50,
      "pro": 5000,
      "team": 50000
    },
    "free_highlight_cap": 5,
    "free_cve_delay_hours": 24,
    "pricing": "/api/pricing"
  },
  "revenue_rails": {
    "crypto_active": true,
    "sponsors": "github.com/sponsors/4444J99",
    "stripe_active": true,
    "bmc_active": true
  }
}
```

### `POST /api/run-now`

Manually triggers NVD collection, AI summarization, digest storage, and CVE
cache writes. This endpoint is unauthenticated but separately rate-limited to
one call per source IP per hour.

```sh
curl -sS -X POST https://vulnpulse.ivixivi.workers.dev/api/run-now
```

Success response is a digest object. Rate-limited response:

```json
{
  "error": "rate_limited",
  "retry_after_seconds": 3600
}
```

## Error Format

Most errors use this shape:

```json
{
  "error": "validation_error",
  "message": "valid email required for checkout"
}
```

Some errors include endpoint-specific fields, such as `tier`, `limit`,
`retry_after_seconds`, `available_at`, `provider`, `status`, or `upgrade`.

Common status codes:

| Status | Error | Meaning |
| ---: | --- | --- |
| `400` | `validation_error`, `invalid_json`, `invalid_signature` | Bad input or webhook signature. |
| `401` | `invalid_api_key` | Supplied API key was not recognized. |
| `402` | `payment_required`, `payment_pending`, `gated`, `subscription_inactive` | Payment, free-tier, or inactive-subscription gate. |
| `404` | `not_found`, `quote_not_found_or_expired` | Missing CVE or expired quote. |
| `405` | `method_not_allowed` | Wrong HTTP method. |
| `413` | `payload_too_large` | JSON body exceeds 16 KB. |
| `415` | `unsupported_media_type` | Missing or wrong `Content-Type`. |
| `429` | `rate_limited` | Daily quota or run-now limit exceeded. |
| `500` | `internal_error` | Unexpected service error. |
| `502` | `stripe_request_failed`, `rail_unavailable`, `receipt_rejected`, `status_unavailable` | Upstream payment provider failed. |
| `503` | `stripe_not_configured`, `stripe_webhook_not_configured` | Operator configuration is incomplete. |

## Integration Examples

### JavaScript

```js
const BASE_URL = 'https://vulnpulse.ivixivi.workers.dev';
const apiKey = process.env.VULNPULSE_API_KEY;

async function vulnpulse(path) {
  const response = await fetch(`${BASE_URL}${path}`, {
    headers: {
      Authorization: `Bearer ${apiKey}`,
      Accept: 'application/json',
    },
  });

  const body = await response.json();
  if (!response.ok) {
    const retryAfter = response.headers.get('Retry-After');
    throw new Error(`${response.status} ${body.error}${retryAfter ? ` retry_after=${retryAfter}` : ''}`);
  }
  return body;
}

const patchNow = await vulnpulse('/api/patch-now');
for (const cve of patchNow.patch_now) {
  console.log(`${cve.id}: ${cve.ai_impact ?? cve.description}`);
}
```

### Python

```python
import os
import requests

BASE_URL = "https://vulnpulse.ivixivi.workers.dev"
API_KEY = os.environ["VULNPULSE_API_KEY"]

response = requests.get(
    f"{BASE_URL}/api/digest/latest",
    headers={"Authorization": f"Bearer {API_KEY}", "Accept": "application/json"},
    timeout=30,
)

payload = response.json()
if response.status_code == 429:
    raise RuntimeError(f"rate limited, retry in {response.headers.get('Retry-After')} seconds")
response.raise_for_status()

for cve in payload.get("highlights", []):
    print(cve["id"], cve.get("ai_priority"), cve.get("ai_impact"))
```

### Shell: open tickets for patch-now CVEs

```sh
curl -sS https://vulnpulse.ivixivi.workers.dev/api/patch-now \
  -H "Authorization: Bearer $VULNPULSE_API_KEY" |
  jq -r '.patch_now[] | [.id, .cvss_score, .ai_class, (.ai_impact // .description)] | @tsv'
```

## Operational Notes

- The deployed Worker cron is configured to collect once daily at 12:00 UTC.
- Manual collection through `/api/run-now` is useful for testing and recovery,
  but it is not meant as a high-frequency polling mechanism.
- NVD is the source of CVE records. VulnPulse adds triage summaries and
  prioritization, but vendor advisories remain authoritative for exact affected
  versions and fixes.
- CVE records are cached in Workers KV with finite retention. A missing CVE
  means it is not in VulnPulse's recent high/critical cache; it does not mean
  the CVE does not exist.
- AI triage fields are best-effort. Production automation should handle missing
  AI fields and should preserve vendor references for analyst review.
- API keys are bearer credentials. Store them as secrets, avoid logging them,
  and rotate by issuing a new key through the subscription or checkout flow.
