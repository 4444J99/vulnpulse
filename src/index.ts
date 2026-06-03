/**
 * VulnPulse — defender-side CVE feed.
 *
 * Cron polls NVD JSON 2.0 every 6 hours for high+critical CVEs (CVSS >= 7.0)
 * modified in the last 24h, AI-summarizes impact + mitigation priority,
 * serves daily digest + real-time webhooks for paid subs.
 *
 * Multi-rail revenue:
 *   - Crypto: USDC to TREASURY_WALLET (operator sets via wrangler secret)
 *   - GitHub Sponsors: via FUNDING.yml on repo
 *   - Latent Stripe Checkout: PRO/TEAM tier (active when card_payments enabled)
 *   - BMC tip jar: BMC_HANDLE env var
 *
 * Source: NVD (https://services.nvd.nist.gov/rest/json/cves/2.0) — free, public.
 */

interface Env {
  AI: any;
  ASSETS: Fetcher;
  VP_CVES: KVNamespace;
  VP_DIGEST: KVNamespace;
  VP_SUBS: KVNamespace;
  USER_AGENT: string;
  TREASURY_WALLET?: string;
  STRIPE_PUBLIC?: string;
  BMC_HANDLE?: string;
  ADMIN_AUTH?: string;
  // Shared fleet money rail. PAYRAIL is a service binding (preferred — a direct
  // internal worker→worker call that skips the public edge, so it dodges both the
  // *.workers.dev same-zone restriction and edge bot-management). PAYRAIL_URL is the
  // public-hostname fallback (used when the binding is absent, e.g. local/standby).
  // SHIP_HMAC_SECRET (a wrangler secret, unset by default) signs receipt writes.
  PAYRAIL?: Fetcher;
  PAYRAIL_URL?: string;
  SHIP_HMAC_SECRET?: string;
}

interface RawCVE {
  id: string;
  published: string;
  modified: string;
  cvss_score: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  vector?: string;
  description: string;
  references: string[];
  cwe_ids: string[];
}

interface SummarizedCVE extends RawCVE {
  ai_impact?: string;
  ai_mitigation?: string;
  ai_exploitability?: 'in_the_wild' | 'poc_likely' | 'theoretical' | 'unknown';
  ai_priority?: 'patch_now' | 'patch_soon' | 'monitor' | 'low';
  ai_tags?: string[];
  ai_class?: string;
}

interface Digest {
  generated_at: string;
  date_label: string;
  total_cves: number;
  critical_count: number;
  high_count: number;
  one_line: string;
  highlights: SummarizedCVE[];
  by_class: Record<string, number>;
  patch_now_ids: string[];
}

const CVE_KEY_PREFIX = 'cve:';
const DIGEST_KEY_PREFIX = 'digest:';
const LATEST_KEY = 'digest:latest';
const NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const SUMMARY_CAP = 20; // Workers-AI free-tier mindfulness; summarize top-N per cron
const RATE_LIMIT_KEY_PREFIX = 'rl:';
const FREE_DAILY_API_LIMIT = 50;

// === payrail (shared fleet money rail) ===
// vulnpulse plugs into the live payrail Worker instead of re-implementing
// "wallet unset / no checkout". payrail returns where to send money + a memo
// (quote_id); the buyer pays on-chain, then /api/confirm records the receipt.
const PAYRAIL_DEFAULT = 'https://payrail.ivixivi.workers.dev';
const TIER_PRICE: Record<'pro' | 'team', string> = { pro: '29', team: '99' };

interface PayrailQuote {
  quote_id: string;
  pay_to: { rail: string; chain: string; asset: string; address: string; amount: string } | null;
  checkout: string | null;
  instructions: string;
  expires_in_seconds: number;
}

// Single egress point to payrail. Prefers the service binding (an internal
// worker→worker call that never touches the public edge → immune to both the
// *.workers.dev same-zone restriction and edge bot-management). Falls back to the
// public hostname with a browser UA so even the fallback clears bot filters. When
// the binding is used the host in the URL is ignored — only path/query/method/body.
function payrailFetch(env: Env, path: string, init?: RequestInit): Promise<Response> {
  if (env.PAYRAIL) return env.PAYRAIL.fetch(new Request(`https://payrail${path}`, init));
  const base = env.PAYRAIL_URL ?? PAYRAIL_DEFAULT;
  const headers = new Headers(init?.headers);
  if (!headers.has('user-agent')) {
    headers.set('user-agent', 'Mozilla/5.0 (compatible; vulnpulse/1.0; +https://vulnpulse.ivixivi.workers.dev)');
  }
  return fetch(base + path, { ...init, headers });
}

async function payrailQuote(env: Env, tier: 'pro' | 'team'): Promise<PayrailQuote> {
  const qs = new URLSearchParams({
    ship: 'vulnpulse',
    sku: `vulnpulse:${tier}`,
    amount: TIER_PRICE[tier],
    currency: 'USDC',
  });
  const r = await payrailFetch(env, `/pay?${qs.toString()}`);
  if (!r.ok) throw new Error(`payrail /pay ${r.status}`);
  return r.json();
}

// HMAC-SHA256 hex, byte-identical to payrail's hmac() so timingSafeEqual passes.
// Only used when SHIP_HMAC_SECRET is set (payrail has none today → optional).
async function hmacHex(secret: string, message: string): Promise<string> { // allow-secret — `secret` is a typed param name (the HMAC key), not a hardcoded value
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// === NVD fetch ===

async function fetchNVDRecent(env: Env, hoursBack = 24): Promise<RawCVE[]> {
  const end = new Date();
  const start = new Date(end.getTime() - hoursBack * 60 * 60 * 1000);
  // NVD requires ISO-8601 with millis and ±HH:MM offset
  const iso = (d: Date) => `${d.toISOString().slice(0, 23)}+00:00`;
  const u = new URL(NVD_API);
  u.searchParams.set('lastModStartDate', iso(start));
  u.searchParams.set('lastModEndDate', iso(end));
  u.searchParams.set('cvssV3Severity', 'HIGH'); // also matches CRITICAL? we'll re-fetch
  u.searchParams.set('resultsPerPage', '50');

  const r = await fetch(u.toString(), {
    headers: { 'User-Agent': env.USER_AGENT, 'Accept': 'application/json' },
  });
  if (!r.ok) {
    console.error('NVD fetch HIGH failed:', r.status, await r.text().catch(() => ''));
  }
  const high = r.ok ? parseNVDResponse(await r.json()) : [];

  u.searchParams.set('cvssV3Severity', 'CRITICAL');
  const r2 = await fetch(u.toString(), {
    headers: { 'User-Agent': env.USER_AGENT, 'Accept': 'application/json' },
  });
  if (!r2.ok) {
    console.error('NVD fetch CRITICAL failed:', r2.status, await r2.text().catch(() => ''));
  }
  const crit = r2.ok ? parseNVDResponse(await r2.json()) : [];

  const merged = [...crit, ...high];
  const dedup = new Map<string, RawCVE>();
  for (const c of merged) dedup.set(c.id, c);
  return [...dedup.values()].sort((a, b) => b.cvss_score - a.cvss_score);
}

function parseNVDResponse(data: any): RawCVE[] {
  const vulns = data?.vulnerabilities ?? [];
  const out: RawCVE[] = [];
  for (const v of vulns) {
    const cve = v?.cve;
    if (!cve?.id) continue;
    const desc = (cve.descriptions ?? []).find((d: any) => d.lang === 'en')?.value ?? '';
    const m31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
    const m30 = cve.metrics?.cvssMetricV30?.[0]?.cvssData;
    const m2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData;
    const data = m31 ?? m30 ?? m2;
    if (!data) continue;
    const score = Number(data.baseScore ?? 0);
    if (score < 7.0) continue;
    const sev = (data.baseSeverity ?? severityFromScore(score)) as RawCVE['severity'];
    const cwe_ids: string[] = [];
    for (const w of cve.weaknesses ?? []) {
      for (const d of w.description ?? []) {
        if (typeof d?.value === 'string' && d.value.startsWith('CWE-')) cwe_ids.push(d.value);
      }
    }
    const refs = (cve.references ?? []).map((r: any) => String(r.url)).filter(Boolean).slice(0, 8);
    out.push({
      id: String(cve.id),
      published: String(cve.published ?? ''),
      modified: String(cve.lastModified ?? ''),
      cvss_score: score,
      severity: sev,
      vector: data.vectorString ? String(data.vectorString) : undefined,
      description: desc.slice(0, 1200),
      references: refs,
      cwe_ids,
    });
  }
  return out;
}

function severityFromScore(s: number): RawCVE['severity'] {
  if (s >= 9.0) return 'CRITICAL';
  if (s >= 7.0) return 'HIGH';
  if (s >= 4.0) return 'MEDIUM';
  if (s > 0) return 'LOW';
  return 'NONE';
}

// === AI summarization ===

const SUMMARY_SYSTEM = `You are VulnPulse, a defender-side CVE summarizer. For each raw CVE, produce a strict JSON summary helping a security engineer triage it FAST.

Output JSON only:
{
  "ai_impact": "<2 sentences. What does an attacker get? Auth required? Network reachable? Be concrete.>",
  "ai_mitigation": "<1-2 sentences on the SOP fix: patch version, config change, mitigation if no patch.>",
  "ai_exploitability": "in_the_wild | poc_likely | theoretical | unknown",
  "ai_priority": "patch_now | patch_soon | monitor | low",
  "ai_tags": ["<lowercase short tags: web, auth, rce, ssrf, xxe, deserialize, sqli, xss, path-traversal, dos, info-leak, supply-chain, container, cloud, iot, mobile, kernel, browser, ai-llm, smart-contract>"],
  "ai_class": "<one of: web-app, network-stack, os-kernel, browser, library, sdk, cms, container, cloud, iot-firmware, hardware, mobile, ai-ml, smart-contract, dev-tool, other>"
}

Rules:
- patch_now = CVSS >= 9.0 AND (network OR low complexity OR auth-bypass) OR known-exploited-in-wild language in description.
- patch_soon = CVSS 7-8.9 with clear exploit path.
- monitor = CVSS 7+ but high complexity or local-only.
- low = nothing here a defender needs to act on this week.

Return ONLY the JSON object.`;

function tryParseJson(s: unknown): any | null {
  if (s == null) return null;
  if (typeof s === 'object') return s;
  const str = typeof s === 'string' ? s : String(s);
  let cleaned = str.replace(/^```json\s*|\s*```$/g, '').trim();
  const firstBrace = cleaned.indexOf('{');
  const lastBrace = cleaned.lastIndexOf('}');
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    cleaned = cleaned.slice(firstBrace, lastBrace + 1);
  }
  try { return JSON.parse(cleaned); } catch { return null; }
}

async function summarizeCVE(cve: RawCVE, env: Env): Promise<SummarizedCVE> {
  const prompt = `CVE: ${cve.id}
CVSS: ${cve.cvss_score} (${cve.severity})
Vector: ${cve.vector ?? '(unknown)'}
CWE: ${cve.cwe_ids.join(', ') || '(none)'}

Description:
${cve.description}

Respond with the JSON object only.`;
  let aiResp: any;
  try {
    aiResp = await env.AI.run('@cf/meta/llama-3.3-70b-instruct-fp8-fast', {
      messages: [
        { role: 'system', content: SUMMARY_SYSTEM },
        { role: 'user', content: prompt },
      ],
      max_tokens: 600,
    });
  } catch (err) {
    console.error('summarize failed for', cve.id, err);
    return cve;
  }
  const raw = aiResp?.response ?? aiResp?.result ?? aiResp;
  const parsed = tryParseJson(raw);
  if (!parsed) return cve;
  return {
    ...cve,
    ai_impact: typeof parsed.ai_impact === 'string' ? parsed.ai_impact : undefined,
    ai_mitigation: typeof parsed.ai_mitigation === 'string' ? parsed.ai_mitigation : undefined,
    ai_exploitability: ['in_the_wild', 'poc_likely', 'theoretical', 'unknown'].includes(parsed.ai_exploitability)
      ? parsed.ai_exploitability : 'unknown',
    ai_priority: ['patch_now', 'patch_soon', 'monitor', 'low'].includes(parsed.ai_priority)
      ? parsed.ai_priority : undefined,
    ai_tags: Array.isArray(parsed.ai_tags) ? parsed.ai_tags.slice(0, 10).map(String) : undefined,
    ai_class: typeof parsed.ai_class === 'string' ? parsed.ai_class : undefined,
  };
}

// === Cron ===

async function runCron(env: Env): Promise<Digest> {
  const raw = await fetchNVDRecent(env, 24);
  console.log(`vulnpulse: NVD returned ${raw.length} CVEs (CVSS>=7.0, last 24h)`);

  // Cap summarization to top N by score to stay within Workers-AI quota.
  // Skip puts for CVEs already in KV (the 24h rolling window overlaps prior
  // crons). Workers KV gets are 100k/day free vs puts at 1k/day, so the
  // pre-check is cheap insurance against the limit even if cron cadence
  // changes back to multiple-per-day.
  const targets = raw.slice(0, SUMMARY_CAP);
  const summaries: SummarizedCVE[] = [];
  for (const cve of targets) {
    const s = await summarizeCVE(cve, env);
    summaries.push(s);
    const key = `${CVE_KEY_PREFIX}${cve.id}`;
    const existing = await env.VP_CVES.get(key);
    if (!existing) {
      await env.VP_CVES.put(key, JSON.stringify(s), {
        expirationTtl: 60 * 60 * 24 * 30,
      });
    }
  }
  // Store the un-summarized rest verbatim so list endpoints have full count.
  for (const c of raw.slice(SUMMARY_CAP)) {
    const key = `${CVE_KEY_PREFIX}${c.id}`;
    const existing = await env.VP_CVES.get(key);
    if (!existing) {
      await env.VP_CVES.put(key, JSON.stringify(c), {
        expirationTtl: 60 * 60 * 24 * 30,
      });
    }
  }

  const critical = raw.filter(r => r.severity === 'CRITICAL');
  const high = raw.filter(r => r.severity === 'HIGH');
  const byClass: Record<string, number> = {};
  for (const s of summaries) {
    if (s.ai_class) byClass[s.ai_class] = (byClass[s.ai_class] ?? 0) + 1;
  }
  const patchNow = summaries.filter(s => s.ai_priority === 'patch_now').map(s => s.id);
  const oneLine = composeHeadline(raw, summaries);

  const digest: Digest = {
    generated_at: new Date().toISOString(),
    date_label: new Date().toISOString().slice(0, 10),
    total_cves: raw.length,
    critical_count: critical.length,
    high_count: high.length,
    one_line: oneLine,
    highlights: summaries.slice(0, 10),
    by_class: byClass,
    patch_now_ids: patchNow,
  };

  await env.VP_DIGEST.put(`${DIGEST_KEY_PREFIX}${digest.date_label}`, JSON.stringify(digest));
  await env.VP_DIGEST.put(LATEST_KEY, JSON.stringify(digest));
  console.log(`vulnpulse: digest ${digest.date_label}, ${digest.total_cves} CVEs (${critical.length} crit), ${patchNow.length} patch-now`);
  return digest;
}

function composeHeadline(raw: RawCVE[], summaries: SummarizedCVE[]): string {
  const c = raw.filter(r => r.severity === 'CRITICAL').length;
  const h = raw.filter(r => r.severity === 'HIGH').length;
  const pn = summaries.filter(s => s.ai_priority === 'patch_now').length;
  if (c === 0 && h === 0) return 'Quiet 24h — no high+critical CVEs published.';
  const parts: string[] = [];
  if (c > 0) parts.push(`${c} critical`);
  if (h > 0) parts.push(`${h} high`);
  let out = `${parts.join(' / ')} CVE${(c + h) === 1 ? '' : 's'} in last 24h`;
  if (pn > 0) out += ` — ${pn} flagged patch-now`;
  return out + '.';
}

// === Subscriptions ===

interface Sub {
  email?: string;
  webhook?: string;
  tier: 'free' | 'pro' | 'team';
  filter?: { min_score?: number; classes?: string[]; tags?: string[] };
  created_at: string;
  auth_value?: string; // for paid tiers
}

async function handleSubscribe(req: Request, env: Env): Promise<Response> {
  if (req.method !== 'POST') return new Response('POST only', { status: 405 });
  const body = await req.json().catch(() => null) as Partial<Sub> | null;
  if (!body || (!body.email && !body.webhook)) {
    return Response.json({ error: 'email or webhook required' }, { status: 400 });
  }
  const ident = body.email ?? body.webhook ?? '';
  const sub: Sub = {
    email: body.email,
    webhook: body.webhook,
    tier: body.tier === 'pro' || body.tier === 'team' ? body.tier : 'free',
    filter: body.filter ?? { min_score: 7.0 },
    created_at: new Date().toISOString(),
  };
  // Paid tier: get a live quote from the shared payrail rail and return a 402
  // carrying the on-chain address + memo (quote_id). The buyer pays, then POSTs
  // the tx hash to /api/confirm to unlock. No more "wired-but-unset" 503.
  if (sub.tier !== 'free') {
    let q: PayrailQuote;
    try {
      q = await payrailQuote(env, sub.tier);
    } catch (err) {
      return Response.json({ error: 'rail_unavailable', detail: String(err) }, { status: 502 });
    }
    await env.VP_SUBS.put(
      `pending:${q.quote_id}`,
      JSON.stringify({ ...sub, ident, quote_id: q.quote_id }),
      { expirationTtl: 60 * 60 * 24 * 7 },
    );
    return Response.json({
      status: 'payment_required',
      tier: sub.tier,
      quote_id: q.quote_id,
      pay_to: q.pay_to,
      checkout: q.checkout,
      instructions: q.instructions,
      expires_in_seconds: q.expires_in_seconds,
      confirm_url: '/api/confirm',
    }, { status: 402 });
  }
  await env.VP_SUBS.put(`sub:${hash(ident)}`, JSON.stringify(sub));
  return Response.json({ ok: true, tier: sub.tier, ident_hash: hash(ident).slice(0, 8) });
}

function hash(s: string): string {
  // FNV-1a 32-bit, deterministic identifier (not cryptographic)
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}

// A buyer who paid posts { quote_id, tx_hash }. We forward it to payrail
// /receipt — the receipt's payer_ref == tx_hash is the TIER-1 artifact — then
// flip the pending sub to active and unlock the paid tier.
async function handleConfirm(req: Request, env: Env): Promise<Response> {
  if (req.method !== 'POST') return new Response('POST only', { status: 405 });
  const body = await req.json().catch(() => null) as { quote_id?: string; tx_hash?: string } | null;
  if (!body?.quote_id || !body?.tx_hash) {
    return Response.json({ error: 'quote_id and tx_hash required' }, { status: 400 });
  }
  const pendingRaw = await env.VP_SUBS.get(`pending:${body.quote_id}`);
  if (!pendingRaw) return Response.json({ error: 'quote_not_found_or_expired' }, { status: 404 });
  const pending = JSON.parse(pendingRaw) as Sub & { ident: string; quote_id: string };
  const tier = (pending.tier === 'team' ? 'team' : 'pro') as 'pro' | 'team';

  const payload = JSON.stringify({
    quote_id: body.quote_id,
    ship: 'vulnpulse',
    sku: `vulnpulse:${tier}`,
    amount: TIER_PRICE[tier],
    currency: 'USDC',
    rail: 'crypto',
    tx_hash: body.tx_hash,
  });
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (env.SHIP_HMAC_SECRET) headers['x-payrail-signature'] = await hmacHex(env.SHIP_HMAC_SECRET, payload);

  const rr = await payrailFetch(env, '/receipt', { method: 'POST', headers, body: payload });
  if (!rr.ok) {
    return Response.json(
      { error: 'receipt_rejected', status: rr.status, detail: await rr.text().catch(() => '') },
      { status: 502 },
    );
  }
  const receiptResp = await rr.json().catch(() => ({})) as { ok?: boolean; receipt?: unknown };

  const active: Sub = {
    email: pending.email,
    webhook: pending.webhook,
    tier,
    filter: pending.filter,
    created_at: pending.created_at,
    auth_value: body.quote_id,
  };
  await env.VP_SUBS.put(`sub:${hash(pending.ident)}`, JSON.stringify(active));
  await env.VP_SUBS.delete(`pending:${body.quote_id}`);
  return Response.json({ ok: true, tier, receipt: receiptResp.receipt }, { status: 201 });
}

// Poll payment status by proxying payrail's public receipt lookup.
async function handlePayStatus(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const quoteId = url.searchParams.get('quote_id');
  if (!quoteId) return Response.json({ error: 'quote_id required' }, { status: 400 });
  const r = await payrailFetch(env, `/receipt/${encodeURIComponent(quoteId)}`);
  if (r.status === 404) return Response.json({ paid: false, quote_id: quoteId });
  if (!r.ok) return Response.json({ error: 'status_unavailable', status: r.status }, { status: 502 });
  return Response.json({ paid: true, receipt: await r.json() });
}

// === HTTP ===

async function handleLatest(_req: Request, env: Env): Promise<Response> {
  const v = await env.VP_DIGEST.get(LATEST_KEY);
  if (!v) {
    return Response.json({
      message: 'no digest yet — first cron run produces it within 6 hours',
      hint: 'POST /api/run-now to trigger collection (rate-limited)',
    }, { status: 202 });
  }
  return new Response(v, { headers: { 'Content-Type': 'application/json' } });
}

async function handleHistory(_req: Request, env: Env): Promise<Response> {
  const list = await env.VP_DIGEST.list({ prefix: DIGEST_KEY_PREFIX, limit: 30 });
  const out: Digest[] = [];
  for (const k of list.keys) {
    if (k.name === LATEST_KEY) continue;
    const v = await env.VP_DIGEST.get(k.name);
    if (v) try { out.push(JSON.parse(v) as Digest); } catch { /* skip */ }
  }
  return Response.json({
    count: out.length,
    digests: out.sort((a, b) => b.date_label.localeCompare(a.date_label)),
  });
}

async function handleCritical(_req: Request, env: Env): Promise<Response> {
  const v = await env.VP_DIGEST.get(LATEST_KEY);
  if (!v) return Response.json({ critical: [] }, { status: 202 });
  const d = JSON.parse(v) as Digest;
  return Response.json({
    generated_at: d.generated_at,
    critical: d.highlights.filter(h => h.severity === 'CRITICAL'),
  });
}

async function handlePatchNow(_req: Request, env: Env): Promise<Response> {
  const v = await env.VP_DIGEST.get(LATEST_KEY);
  if (!v) return Response.json({ patch_now: [] }, { status: 202 });
  const d = JSON.parse(v) as Digest;
  return Response.json({
    generated_at: d.generated_at,
    patch_now: d.highlights.filter(h => h.ai_priority === 'patch_now'),
  });
}

async function handleCVE(req: Request, env: Env): Promise<Response> {
  const url = new URL(req.url);
  const id = url.pathname.split('/').pop() ?? '';
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) {
    return Response.json({ error: 'invalid CVE id' }, { status: 400 });
  }
  const v = await env.VP_CVES.get(`${CVE_KEY_PREFIX}${id}`);
  if (!v) return Response.json({ error: 'not_found_in_24h_window' }, { status: 404 });
  return new Response(v, { headers: { 'Content-Type': 'application/json' } });
}

async function handleRunNow(req: Request, env: Env): Promise<Response> {
  // Rate-limit: per-IP, max 1 manual run per hour.
  const ip = req.headers.get('cf-connecting-ip') ?? 'unknown';
  const rkey = `${RATE_LIMIT_KEY_PREFIX}runnow:${ip}`;
  const last = await env.VP_CVES.get(rkey);
  if (last && Date.now() - Number(last) < 60 * 60 * 1000) {
    return Response.json({ error: 'rate_limited', retry_after_seconds: 3600 }, { status: 429 });
  }
  await env.VP_CVES.put(rkey, String(Date.now()), { expirationTtl: 3600 });
  const d = await runCron(env);
  return Response.json(d);
}

async function handleStatus(_req: Request, env: Env): Promise<Response> {
  const list = await env.VP_CVES.list({ prefix: CVE_KEY_PREFIX, limit: 1 });
  const sample = list.keys[0]?.name?.replace(CVE_KEY_PREFIX, '') ?? null;
  const subList = await env.VP_SUBS.list({ prefix: 'sub:', limit: 1 });
  return Response.json({
    name: 'VulnPulse',
    has_latest_digest: (await env.VP_DIGEST.get(LATEST_KEY)) != null,
    sample_cve: sample,
    has_subscribers: subList.keys.length > 0,
    revenue_rails: {
      crypto_active: !!env.TREASURY_WALLET,
      sponsors: 'github.com/sponsors/4444J99',
      stripe_active: !!env.STRIPE_PUBLIC,
      bmc_active: !!env.BMC_HANDLE,
    },
  });
}

async function handleRails(_req: Request, env: Env): Promise<Response> {
  // Public revenue-rail discovery — clients can offer multiple pay options to users.
  return Response.json({
    crypto: env.TREASURY_WALLET ?? null,
    sponsors_url: 'https://github.com/sponsors/4444J99',
    stripe_active: !!env.STRIPE_PUBLIC,
    bmc_url: env.BMC_HANDLE ? `https://www.buymeacoffee.com/${env.BMC_HANDLE}` : null,
  });
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    const p = url.pathname;
    if (p === '/api/digest/latest') return handleLatest(req, env);
    if (p === '/api/digest/history') return handleHistory(req, env);
    if (p === '/api/critical') return handleCritical(req, env);
    if (p === '/api/patch-now') return handlePatchNow(req, env);
    if (p.startsWith('/api/cve/')) return handleCVE(req, env);
    if (p === '/api/subscribe') return handleSubscribe(req, env);
    if (p === '/api/confirm') return handleConfirm(req, env);
    if (p === '/api/pay-status') return handlePayStatus(req, env);
    if (p === '/api/run-now' && req.method === 'POST') return handleRunNow(req, env);
    if (p === '/api/status') return handleStatus(req, env);
    if (p === '/api/rails') return handleRails(req, env);
    return env.ASSETS.fetch(req);
  },

  async scheduled(_ev: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(runCron(env).then(() => undefined));
  },
};
