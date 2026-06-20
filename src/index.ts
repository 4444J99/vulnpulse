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

// ── Structured Logging ──────────────────────────────────────────────────────

type LogLevel = 'info' | 'warn' | 'error' | 'debug';

interface LogEntry {
  level: LogLevel;
  ts: string;
  rid: string;
  msg: string;
  [k: string]: unknown;
}

function genRid(): string {
  const c = crypto.getRandomValues(new Uint8Array(6));
  const ts = Date.now().toString(36).slice(-6);
  return ts + '-' + [...c].map(b => b.toString(36).padStart(2, '0')).join('');
}

function structuredLog(rid: string, level: LogLevel, msg: string, meta?: Record<string, unknown>): void {
  const entry: LogEntry = { level, ts: new Date().toISOString(), rid, msg, ...meta };
  const line = JSON.stringify(entry);
  if (level === 'error') console.error(line);
  else if (level === 'warn') console.warn(line);
  else console.log(line);
}

// ── Input Validation Helpers ────────────────────────────────────────────────

const HTTP_BODY_MAX = 16_384;

function validEmail(s: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) && s.length <= 254;
}

function validUrl(s: string): boolean {
  try {
    const u = new URL(s);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch { return false; }
}

function validWebhookUrl(s: string): boolean {
  return validUrl(s);
}

function requireContentType(req: Request, expected: string): boolean {
  const ct = req.headers.get('content-type') ?? '';
  return ct.startsWith(expected);
}

function requireBody(req: Request, _rid: string): Promise<unknown> {
  const cl = req.headers.get('content-length');
  if (cl && Number(cl) > HTTP_BODY_MAX) {
    throw new HttpError(413, 'payload_too_large', `Request body exceeds ${HTTP_BODY_MAX} bytes`);
  }
  return req.json().catch(() => {
    throw new HttpError(400, 'invalid_json', 'Request body must be valid JSON');
  });
}

// ── Error Types ─────────────────────────────────────────────────────────────

class HttpError extends Error {
  constructor(
    public status: number,
    public code: string,
    msg?: string,
    public detail?: unknown,
  ) {
    super(msg ?? code);
    this.name = 'HttpError';
  }
}

function errorBody(status: number, code: string, msg?: string, extra?: Record<string, unknown>) {
  return Response.json({ error: code, ...(msg ? { message: msg } : {}), ...extra }, { status });
}

function errorBodyWithHeaders(status: number, code: string, headers: Record<string, string>, msg?: string, extra?: Record<string, unknown>) {
  return Response.json({ error: code, ...(msg ? { message: msg } : {}), ...extra }, { status, headers });
}

// ── Env ─────────────────────────────────────────────────────────────────────

interface Env {
  AI: any;
  ASSETS: Fetcher;
  VP_CVES: KVNamespace;
  VP_DIGEST: KVNamespace;
  VP_SUBS: KVNamespace;
  USER_AGENT: string;
  TREASURY_WALLET?: string;
  STRIPE_PUBLIC?: string;
  STRIPE_SECRET_KEY?: string;
  STRIPE_WEBHOOK_SECRET?: string;
  STRIPE_PRO_PRICE_ID?: string;
  STRIPE_TEAM_PRICE_ID?: string;
  STRIPE_SUCCESS_URL?: string;
  STRIPE_CANCEL_URL?: string;
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

// === subscription gate ===
// Every CVE-intelligence read resolves to a tier (via API key, else anonymous
// free) and is rate-limited per tier per UTC day. Free additionally gets a
// *limited* digest (highlights capped) and *delayed* raw CVE detail (records
// modified <24h ago are paywalled). Pro/Team unlock full + real-time.
type Tier = 'free' | 'pro' | 'team';
type PaidTier = Exclude<Tier, 'free'>;
const API_KEY_PREFIX = 'key:';
const TIER_DAILY_API_LIMIT: Record<Tier, number> = { free: 50, pro: 5000, team: 50000 };
const FREE_DELAY_MS = 24 * 60 * 60 * 1000; // free sees raw CVE detail 24h late
const FREE_HIGHLIGHT_CAP = 5; // free digest endpoints return at most this many CVEs
const ACTIVE_SUBSCRIPTION_STATUSES = new Set(['active', 'trialing']);

// === payrail (shared fleet money rail) ===
// vulnpulse plugs into the live payrail Worker instead of re-implementing
// "wallet unset / no checkout". payrail returns where to send money + a memo
// (quote_id); the buyer pays on-chain, then /api/confirm records the receipt.
const PAYRAIL_DEFAULT = 'https://payrail.ivixivi.workers.dev';
const TIER_PRICE: Record<'pro' | 'team', string> = { pro: '29', team: '99' };
const STRIPE_API = 'https://api.stripe.com/v1';

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
async function hmacHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// === Stripe Checkout + subscription licenses ===

interface StripeCheckoutSession {
  id: string;
  url?: string | null;
  mode?: string;
  status?: string | null;
  payment_status?: string | null;
  client_reference_id?: string | null;
  customer?: string | { id?: string } | null;
  customer_email?: string | null;
  subscription?: string | { id?: string; status?: string; metadata?: Record<string, string> } | null;
  metadata?: Record<string, string> | null;
}

interface StripeSubscription {
  id: string;
  status?: string;
  customer?: string | { id?: string } | null;
  metadata?: Record<string, string> | null;
}

interface StripeEvent {
  id: string;
  type: string;
  data: { object: any };
}

interface StripeLicenseIndex {
  api_key: string;
  tier: PaidTier;
  ident_hash: string;
  status: string;
  stripe_session_id: string;
  stripe_customer_id?: string;
  stripe_subscription_id?: string;
  updated_at: string;
}

function stripePriceId(env: Env, tier: PaidTier): string | undefined {
  return tier === 'pro' ? env.STRIPE_PRO_PRICE_ID : env.STRIPE_TEAM_PRICE_ID;
}

function stripeCheckoutConfigured(env: Env, tier?: PaidTier): boolean {
  if (!env.STRIPE_SECRET_KEY) return false;
  if (tier) return !!stripePriceId(env, tier);
  return !!env.STRIPE_PRO_PRICE_ID || !!env.STRIPE_TEAM_PRICE_ID;
}

function normalizePaidTier(v: unknown): PaidTier | null {
  return v === 'pro' || v === 'team' ? v : null;
}

function stripeObjectId(v: unknown): string | undefined {
  if (typeof v === 'string') return v;
  if (v && typeof v === 'object' && typeof (v as { id?: unknown }).id === 'string') return (v as { id: string }).id;
  return undefined;
}

function stripeSubscriptionStatus(v: unknown): string | undefined {
  if (v && typeof v === 'object' && typeof (v as { status?: unknown }).status === 'string') return (v as { status: string }).status;
  return undefined;
}

function stripeSuccessUrl(req: Request, env: Env): string {
  if (env.STRIPE_SUCCESS_URL) return env.STRIPE_SUCCESS_URL;
  const origin = new URL(req.url).origin;
  return `${origin}/?checkout=success&session_id={CHECKOUT_SESSION_ID}`;
}

function stripeCancelUrl(req: Request, env: Env): string {
  if (env.STRIPE_CANCEL_URL) return env.STRIPE_CANCEL_URL;
  return `${new URL(req.url).origin}/#pricing`;
}

async function stripeRequest<T>(env: Env, path: string, init?: RequestInit): Promise<T> {
  if (!env.STRIPE_SECRET_KEY) throw new HttpError(503, 'stripe_not_configured');
  const headers = new Headers(init?.headers);
  headers.set('authorization', `Bearer ${env.STRIPE_SECRET_KEY}`);
  const r = await fetch(`${STRIPE_API}${path}`, { ...init, headers });
  const text = await r.text();
  const parsed = text ? tryParseJson(text) : {};
  if (!r.ok) {
    const detail = parsed ?? text;
    throw new HttpError(502, 'stripe_request_failed', `Stripe request failed (${r.status})`, detail);
  }
  return parsed as T;
}

async function stripeCreateCheckoutSession(req: Request, env: Env, sub: Sub, ident: string): Promise<StripeCheckoutSession> {
  const tier = normalizePaidTier(sub.tier);
  if (!tier) throw new HttpError(400, 'validation_error', 'paid tier required');
  const priceId = stripePriceId(env, tier);
  if (!env.STRIPE_SECRET_KEY || !priceId) throw new HttpError(503, 'stripe_not_configured');

  const identHash = hash(ident);
  const params = new URLSearchParams();
  params.set('mode', 'subscription');
  params.set('client_reference_id', identHash);
  params.set('customer_email', ident);
  params.set('line_items[0][price]', priceId);
  params.set('line_items[0][quantity]', '1');
  params.set('allow_promotion_codes', 'true');
  params.set('success_url', stripeSuccessUrl(req, env));
  params.set('cancel_url', stripeCancelUrl(req, env));
  params.set('metadata[product]', 'vulnpulse');
  params.set('metadata[tier]', tier);
  params.set('metadata[ident_hash]', identHash);
  params.set('metadata[email]', ident);
  params.set('subscription_data[metadata][product]', 'vulnpulse');
  params.set('subscription_data[metadata][tier]', tier);
  params.set('subscription_data[metadata][ident_hash]', identHash);

  return stripeRequest<StripeCheckoutSession>(env, '/checkout/sessions', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
}

async function stripeRetrieveCheckoutSession(env: Env, sessionId: string): Promise<StripeCheckoutSession> {
  if (!/^cs_(test|live)_[A-Za-z0-9_]+$/.test(sessionId)) {
    throw new HttpError(400, 'validation_error', 'invalid Stripe Checkout session id');
  }
  const qs = new URLSearchParams();
  qs.append('expand[]', 'subscription');
  return stripeRequest<StripeCheckoutSession>(env, `/checkout/sessions/${encodeURIComponent(sessionId)}?${qs.toString()}`);
}

function stripeSessionComplete(session: StripeCheckoutSession): boolean {
  const paid = session.payment_status === 'paid' || session.payment_status === 'no_payment_required';
  return session.status === 'complete' && paid;
}

function timingSafeEqualHex(a: string, b: string): boolean {
  if (!/^[0-9a-f]+$/i.test(a) || !/^[0-9a-f]+$/i.test(b)) return false;
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i += 1) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

async function verifyStripeSignature(rawBody: string, signatureHeader: string, secret: string): Promise<boolean> {
  const parts = signatureHeader.split(',').map(p => p.trim());
  const timestamp = parts.find(p => p.startsWith('t='))?.slice(2);
  const signatures = parts.filter(p => p.startsWith('v1=')).map(p => p.slice(3));
  if (!timestamp || signatures.length === 0 || !/^\d+$/.test(timestamp)) return false;
  const age = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
  if (age > 5 * 60) return false;
  const expected = await hmacHex(secret, `${timestamp}.${rawBody}`);
  return signatures.some(sig => timingSafeEqualHex(sig, expected));
}

// === NVD fetch ===

async function fetchNVDRecent(env: Env, rid: string, hoursBack = 24): Promise<RawCVE[]> {
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
    structuredLog(rid, 'error', 'nvd_fetch_failed', { severity: 'HIGH', status: r.status, detail: await r.text().catch(() => '') });
  }
  const high = r.ok ? parseNVDResponse(await r.json()) : [];

  u.searchParams.set('cvssV3Severity', 'CRITICAL');
  const r2 = await fetch(u.toString(), {
    headers: { 'User-Agent': env.USER_AGENT, 'Accept': 'application/json' },
  });
  if (!r2.ok) {
    structuredLog(rid, 'error', 'nvd_fetch_failed', { severity: 'CRITICAL', status: r2.status, detail: await r2.text().catch(() => '') });
  }
  const crit = r2.ok ? parseNVDResponse(await r2.json()) : [];

  const merged = [...crit, ...high];
  const dedup = new Map<string, RawCVE>();
  for (const c of merged) dedup.set(c.id, c);
  return [...dedup.values()].sort((a, b) => b.cvss_score - a.cvss_score);
}

export function parseNVDResponse(data: any): RawCVE[] {
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

export function severityFromScore(s: number): RawCVE['severity'] {
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

export function tryParseJson(s: unknown): any | null {
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

async function summarizeCVE(cve: RawCVE, env: Env, rid: string): Promise<SummarizedCVE> {
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
    structuredLog(rid, 'error', 'ai_summarize_failed', { cve_id: cve.id, error: String(err) });
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

async function runCron(env: Env, rid?: string): Promise<Digest> {
  if (!rid) rid = genRid();
  structuredLog(rid, 'info', 'cron_started');
  const raw = await fetchNVDRecent(env, rid, 24);
  structuredLog(rid, 'info', 'nvd_fetched', { total: raw.length, window_hours: 24 });

  // Cap summarization to top N by score to stay within Workers-AI quota.
  // Skip puts for CVEs already in KV (the 24h rolling window overlaps prior
  // crons). Workers KV gets are 100k/day free vs puts at 1k/day, so the
  // pre-check is cheap insurance against the limit even if cron cadence
  // changes back to multiple-per-day.
  const targets = raw.slice(0, SUMMARY_CAP);
  const summaries: SummarizedCVE[] = [];
  for (const cve of targets) {
    const s = await summarizeCVE(cve, env, rid);
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
  structuredLog(rid, 'info', 'cron_completed', {
    date_label: digest.date_label,
    total_cves: digest.total_cves,
    critical: critical.length,
    patch_now: patchNow.length,
  });
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
  tier: Tier;
  filter?: { min_score?: number; classes?: string[]; tags?: string[] };
  created_at: string;
  auth_value?: string; // for paid tiers
  api_key?: string;    // issued at subscribe (free) / confirm (paid)
  provider?: 'stripe' | 'payrail' | 'manual';
  subscription_status?: string;
  stripe_customer_id?: string;
  stripe_subscription_id?: string;
  stripe_session_id?: string;
}

async function startPaidCheckout(req: Request, env: Env, rid: string, sub: Sub, ident: string): Promise<Response> {
  const tier = normalizePaidTier(sub.tier);
  if (!tier) return errorBody(400, 'validation_error', 'tier must be pro or team');

  if (stripeCheckoutConfigured(env, tier)) {
    let session: StripeCheckoutSession;
    try {
      session = await stripeCreateCheckoutSession(req, env, { ...sub, tier }, ident);
    } catch (err) {
      structuredLog(rid, 'error', 'stripe_checkout_failed', { tier, error: String(err) });
      if (err instanceof HttpError) return errorBody(err.status, err.code, err.message, err.detail ? { detail: err.detail } : undefined);
      return errorBody(502, 'stripe_checkout_failed', String(err));
    }
    if (!session.id || !session.url) {
      structuredLog(rid, 'error', 'stripe_checkout_missing_url', { tier, session_id: session.id });
      return errorBody(502, 'stripe_checkout_failed', 'Stripe did not return a checkout URL');
    }
    await env.VP_SUBS.put(
      `pending:stripe:${session.id}`,
      JSON.stringify({
        ...sub,
        tier,
        ident,
        provider: 'stripe',
        stripe_session_id: session.id,
        stripe_customer_id: stripeObjectId(session.customer),
      }),
      { expirationTtl: 60 * 60 * 24 * 7 },
    );
    return Response.json({
      status: 'payment_required',
      provider: 'stripe',
      tier,
      checkout: session.url,
      checkout_url: session.url,
      session_id: session.id,
      claim_url: '/api/checkout/claim',
      instructions: 'Complete Stripe Checkout, then return here to claim your paid API key.',
    }, { status: 402 });
  }

  // Paid fallback: live USDC quote via payrail.
  let q: PayrailQuote;
  try {
    q = await payrailQuote(env, tier);
  } catch (err) {
    structuredLog(rid, 'error', 'payrail_quote_failed', { tier, error: String(err) });
    return errorBody(502, 'rail_unavailable', String(err));
  }
  await env.VP_SUBS.put(
    `pending:${q.quote_id}`,
    JSON.stringify({ ...sub, tier, ident, quote_id: q.quote_id, provider: 'payrail' }),
    { expirationTtl: 60 * 60 * 24 * 7 },
  );
  return Response.json({
    status: 'payment_required',
    provider: 'payrail',
    tier,
    quote_id: q.quote_id,
    pay_to: q.pay_to,
    checkout: q.checkout,
    instructions: q.instructions,
    expires_in_seconds: q.expires_in_seconds,
    confirm_url: '/api/confirm',
  }, { status: 402 });
}

async function handleSubscribe(req: Request, env: Env, rid: string): Promise<Response> {
  if (req.method !== 'POST') return errorBody(405, 'method_not_allowed', 'POST only');
  if (!requireContentType(req, 'application/json')) return errorBody(415, 'unsupported_media_type', 'content-type must be application/json');
  structuredLog(rid, 'info', 'subscribe_request');
  const body = await requireBody(req, rid) as Partial<Sub> | null;
  if (!body || (!body.email && !body.webhook)) {
    return errorBody(400, 'validation_error', 'email or webhook required');
  }
  if (body.email && !validEmail(body.email)) {
    return errorBody(400, 'validation_error', 'invalid email format');
  }
  if (body.webhook && !validWebhookUrl(body.webhook)) {
    return errorBody(400, 'validation_error', 'invalid webhook URL');
  }
  const ident = body.email ?? body.webhook ?? '';
  const sub: Sub = {
    email: body.email,
    webhook: body.webhook,
    tier: body.tier === 'pro' || body.tier === 'team' ? body.tier : 'free',
    filter: body.filter ?? { min_score: 7.0 },
    created_at: new Date().toISOString(),
  };
  // Paid tier: prefer Stripe Checkout when configured; otherwise use the
  // shared payrail quote/receipt rail.
  if (sub.tier !== 'free') {
    return startPaidCheckout(req, env, rid, sub, ident);
  }
  const apiKey = await issueApiKey(env, 'free', hash(ident));
  sub.api_key = apiKey;
  await env.VP_SUBS.put(`sub:${hash(ident)}`, JSON.stringify(sub));
  return Response.json({
    ok: true,
    tier: sub.tier,
    ident_hash: hash(ident).slice(0, 8),
    api_key: apiKey,
    api_key_usage: 'send as "Authorization: Bearer <key>" or ?api_key=. Free tier: 50 req/day, raw CVE detail delayed 24h.',
  });
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
async function handleConfirm(req: Request, env: Env, rid: string): Promise<Response> {
  if (req.method !== 'POST') return errorBody(405, 'method_not_allowed', 'POST only');
  if (!requireContentType(req, 'application/json')) return errorBody(415, 'unsupported_media_type', 'content-type must be application/json');
  structuredLog(rid, 'info', 'confirm_request');
  const body = await requireBody(req, rid) as { quote_id?: string; tx_hash?: string } | null;
  if (!body?.quote_id || !body?.tx_hash || typeof body.quote_id !== 'string' || typeof body.tx_hash !== 'string') {
    return errorBody(400, 'validation_error', 'quote_id and tx_hash required (strings)');
  }
  const pendingRaw = await env.VP_SUBS.get(`pending:${body.quote_id}`);
  if (!pendingRaw) return errorBody(404, 'quote_not_found_or_expired');
  structuredLog(rid, 'info', 'confirm_pending_found', { quote_id: body.quote_id });
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
    structuredLog(rid, 'error', 'receipt_rejected', { quote_id: body.quote_id, status: rr.status });
    return errorBody(502, 'receipt_rejected', undefined, { detail: await rr.text().catch(() => '') });
  }
  const receiptResp = await rr.json().catch(() => ({})) as { ok?: boolean; receipt?: unknown };

  const apiKey = await issueApiKey(env, tier, hash(pending.ident), { provider: 'payrail', status: 'active' });
  const active: Sub = {
    email: pending.email,
    webhook: pending.webhook,
    tier,
    filter: pending.filter,
    created_at: pending.created_at,
    auth_value: body.quote_id,
    api_key: apiKey,
    provider: 'payrail',
    subscription_status: 'active',
  };
  await env.VP_SUBS.put(`sub:${hash(pending.ident)}`, JSON.stringify(active));
  await env.VP_SUBS.delete(`pending:${body.quote_id}`);
  return Response.json({
    ok: true,
    tier,
    api_key: apiKey,
    api_key_usage: 'send as "Authorization: Bearer <key>". Real-time access + ' + TIER_DAILY_API_LIMIT[tier] + ' req/day.',
    receipt: receiptResp.receipt,
  }, { status: 201 });
}

// Poll payment status by proxying payrail's public receipt lookup.
async function handlePayStatus(req: Request, env: Env, rid: string): Promise<Response> {
  const url = new URL(req.url);
  const quoteId = url.searchParams.get('quote_id');
  if (!quoteId) return errorBody(400, 'validation_error', 'quote_id required');
  structuredLog(rid, 'info', 'pay_status_request', { quote_id: quoteId });
  const r = await payrailFetch(env, `/receipt/${encodeURIComponent(quoteId)}`);
  if (r.status === 404) return Response.json({ paid: false, quote_id: quoteId });
  if (!r.ok) {
    structuredLog(rid, 'error', 'payrail_receipt_failed', { quote_id: quoteId, status: r.status });
    return errorBody(502, 'status_unavailable');
  }
  return Response.json({ paid: true, receipt: await r.json() });
}

// === subscription gate (API key + tiers) ===

interface ApiKeyRecord {
  tier: Tier;
  ident_hash: string;
  created_at: string;
  status?: string;
  provider?: 'stripe' | 'payrail' | 'manual';
  stripe_customer_id?: string;
  stripe_subscription_id?: string;
  stripe_session_id?: string;
  updated_at?: string;
}

// Tier-prefixed opaque token: vpf_/vpp_/vpt_ + 24 random bytes hex. The prefix
// is cosmetic (helps a human spot the tier); authority comes from the KV lookup.
function genApiKey(tier: Tier): string {
  const bytes = crypto.getRandomValues(new Uint8Array(24));
  const hex = [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
  const prefix = tier === 'pro' ? 'vpp' : tier === 'team' ? 'vpt' : 'vpf';
  return `${prefix}_${hex}`;
}

async function issueApiKey(env: Env, tier: Tier, identHash: string, extra: Partial<ApiKeyRecord> = {}): Promise<string> {
  const key = genApiKey(tier);
  const now = new Date().toISOString();
  const rec: ApiKeyRecord = { tier, ident_hash: identHash, created_at: now, status: 'active', ...extra };
  await env.VP_SUBS.put(`${API_KEY_PREFIX}${key}`, JSON.stringify(rec));
  return key;
}

function apiKeyRecordActive(rec: ApiKeyRecord): boolean {
  if (rec.tier === 'free') return true;
  return !rec.status || ACTIVE_SUBSCRIPTION_STATUSES.has(rec.status);
}

async function putStripeLicenseIndexes(env: Env, index: StripeLicenseIndex): Promise<void> {
  await env.VP_SUBS.put(`stripe_session:${index.stripe_session_id}`, JSON.stringify(index));
  if (index.stripe_subscription_id) {
    await env.VP_SUBS.put(`stripe_sub:${index.stripe_subscription_id}`, JSON.stringify(index));
  }
}

async function updateApiKeyStatus(env: Env, apiKey: string, status: string): Promise<ApiKeyRecord | null> {
  const raw = await env.VP_SUBS.get(`${API_KEY_PREFIX}${apiKey}`);
  if (!raw) return null;
  let rec: ApiKeyRecord;
  try { rec = JSON.parse(raw) as ApiKeyRecord; } catch { return null; }
  rec.status = status;
  rec.updated_at = new Date().toISOString();
  await env.VP_SUBS.put(`${API_KEY_PREFIX}${apiKey}`, JSON.stringify(rec));
  return rec;
}

async function updateStripeSubscriptionStatus(env: Env, subscriptionId: string, status: string, rid: string): Promise<boolean> {
  const indexRaw = await env.VP_SUBS.get(`stripe_sub:${subscriptionId}`);
  if (!indexRaw) {
    structuredLog(rid, 'info', 'stripe_subscription_status_ignored', { subscription_id: subscriptionId, status });
    return false;
  }
  let index: StripeLicenseIndex;
  try { index = JSON.parse(indexRaw) as StripeLicenseIndex; } catch { return false; }
  index.status = status;
  index.updated_at = new Date().toISOString();
  await putStripeLicenseIndexes(env, index);
  const rec = await updateApiKeyStatus(env, index.api_key, status);
  if (rec) {
    const subRaw = await env.VP_SUBS.get(`sub:${rec.ident_hash}`);
    if (subRaw) {
      try {
        const sub = JSON.parse(subRaw) as Sub;
        sub.subscription_status = status;
        sub.stripe_subscription_id = subscriptionId;
        await env.VP_SUBS.put(`sub:${rec.ident_hash}`, JSON.stringify(sub));
      } catch { /* keep the key record as source of truth */ }
    }
  }
  structuredLog(rid, 'info', 'stripe_subscription_status_updated', { subscription_id: subscriptionId, status });
  return true;
}

async function activateStripeLicense(env: Env, session: StripeCheckoutSession, rid: string): Promise<{ api_key: string; tier: PaidTier; status: string; created: boolean }> {
  if (!session.id) throw new HttpError(400, 'validation_error', 'missing Stripe session id');
  const metadata = session.metadata ?? {};
  if (metadata.product && metadata.product !== 'vulnpulse') throw new HttpError(400, 'validation_error', 'Stripe session is not for VulnPulse');

  const existingSessionRaw = await env.VP_SUBS.get(`stripe_session:${session.id}`);
  if (existingSessionRaw) {
    try {
      const existing = JSON.parse(existingSessionRaw) as StripeLicenseIndex;
      await updateApiKeyStatus(env, existing.api_key, 'active');
      existing.status = 'active';
      existing.updated_at = new Date().toISOString();
      await putStripeLicenseIndexes(env, existing);
      return { api_key: existing.api_key, tier: existing.tier, status: existing.status, created: false };
    } catch { /* rebuild from session below */ }
  }

  const pendingRaw = await env.VP_SUBS.get(`pending:stripe:${session.id}`);
  const pending = pendingRaw ? JSON.parse(pendingRaw) as Sub & { ident?: string } : null;
  const tier = normalizePaidTier(pending?.tier ?? metadata.tier);
  if (!tier) throw new HttpError(400, 'validation_error', 'missing paid tier metadata');

  const ident = pending?.ident ?? session.customer_email ?? metadata.email ?? '';
  const identHash = pending?.ident ? hash(pending.ident) : metadata.ident_hash ?? session.client_reference_id ?? (ident ? hash(ident) : '');
  if (!identHash) throw new HttpError(400, 'validation_error', 'missing subscriber identity metadata');

  const stripeCustomerId = stripeObjectId(session.customer);
  const stripeSubscriptionId = stripeObjectId(session.subscription);
  const status = stripeSubscriptionStatus(session.subscription) ?? 'active';

  let apiKey: string | undefined;
  if (stripeSubscriptionId) {
    const existingSubRaw = await env.VP_SUBS.get(`stripe_sub:${stripeSubscriptionId}`);
    if (existingSubRaw) {
      try { apiKey = (JSON.parse(existingSubRaw) as StripeLicenseIndex).api_key; } catch { /* issue below */ }
    }
  }
  if (!apiKey) {
    apiKey = await issueApiKey(env, tier, identHash, {
      provider: 'stripe',
      status,
      stripe_customer_id: stripeCustomerId,
      stripe_subscription_id: stripeSubscriptionId,
      stripe_session_id: session.id,
    });
  } else {
    await updateApiKeyStatus(env, apiKey, status);
  }

  const active: Sub = {
    email: pending?.email ?? session.customer_email ?? metadata.email,
    webhook: pending?.webhook,
    tier,
    filter: pending?.filter,
    created_at: pending?.created_at ?? new Date().toISOString(),
    auth_value: stripeSubscriptionId ?? session.id,
    api_key: apiKey,
    provider: 'stripe',
    subscription_status: status,
    stripe_customer_id: stripeCustomerId,
    stripe_subscription_id: stripeSubscriptionId,
    stripe_session_id: session.id,
  };
  await env.VP_SUBS.put(`sub:${identHash}`, JSON.stringify(active));
  await putStripeLicenseIndexes(env, {
    api_key: apiKey,
    tier,
    ident_hash: identHash,
    status,
    stripe_session_id: session.id,
    stripe_customer_id: stripeCustomerId,
    stripe_subscription_id: stripeSubscriptionId,
    updated_at: new Date().toISOString(),
  });
  await env.VP_SUBS.delete(`pending:stripe:${session.id}`);
  structuredLog(rid, 'info', 'stripe_license_activated', { tier, session_id: session.id, subscription_id: stripeSubscriptionId });
  return { api_key: apiKey, tier, status, created: true };
}

async function handleCheckout(req: Request, env: Env, rid: string): Promise<Response> {
  if (req.method !== 'POST') return errorBody(405, 'method_not_allowed', 'POST only');
  if (!requireContentType(req, 'application/json')) return errorBody(415, 'unsupported_media_type', 'content-type must be application/json');
  const body = await requireBody(req, rid) as Partial<Sub> | null;
  const tier = normalizePaidTier(body?.tier);
  if (!tier) return errorBody(400, 'validation_error', 'tier must be pro or team');
  if (!body?.email || !validEmail(body.email)) return errorBody(400, 'validation_error', 'valid email required for checkout');
  const sub: Sub = {
    email: body.email,
    webhook: body.webhook,
    tier,
    filter: body.filter ?? { min_score: 7.0 },
    created_at: new Date().toISOString(),
  };
  return startPaidCheckout(req, env, rid, sub, body.email);
}

async function handleStripeClaim(req: Request, env: Env, rid: string): Promise<Response> {
  let sessionId: string | null = null;
  if (req.method === 'GET') {
    sessionId = new URL(req.url).searchParams.get('session_id');
  } else if (req.method === 'POST') {
    if (!requireContentType(req, 'application/json')) return errorBody(415, 'unsupported_media_type', 'content-type must be application/json');
    const body = await requireBody(req, rid) as { session_id?: string } | null;
    sessionId = body?.session_id ?? null;
  } else {
    return errorBody(405, 'method_not_allowed', 'GET or POST only');
  }
  if (!sessionId) return errorBody(400, 'validation_error', 'session_id required');
  const session = await stripeRetrieveCheckoutSession(env, sessionId);
  if (!stripeSessionComplete(session)) {
    return errorBody(402, 'payment_pending', 'Stripe Checkout session is not complete yet', {
      provider: 'stripe',
      session_id: session.id,
      status: session.status,
      payment_status: session.payment_status,
    });
  }
  const activated = await activateStripeLicense(env, session, rid);
  return Response.json({
    ok: true,
    provider: 'stripe',
    tier: activated.tier,
    subscription_status: activated.status,
    api_key: activated.api_key,
    api_key_usage: 'send as "Authorization: Bearer <key>". Real-time access + ' + TIER_DAILY_API_LIMIT[activated.tier] + ' req/day while your subscription is active.',
  }, { status: activated.created ? 201 : 200 });
}

async function handleStripeWebhook(req: Request, env: Env, rid: string): Promise<Response> {
  if (req.method !== 'POST') return errorBody(405, 'method_not_allowed', 'POST only');
  if (!env.STRIPE_WEBHOOK_SECRET) return errorBody(503, 'stripe_webhook_not_configured');
  const raw = await req.text();
  const signature = req.headers.get('stripe-signature');
  if (!signature || !(await verifyStripeSignature(raw, signature, env.STRIPE_WEBHOOK_SECRET))) {
    structuredLog(rid, 'warn', 'stripe_webhook_invalid_signature');
    return errorBody(400, 'invalid_signature');
  }
  let event: StripeEvent;
  try { event = JSON.parse(raw) as StripeEvent; } catch {
    return errorBody(400, 'invalid_json');
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object as StripeCheckoutSession;
    const metadata = session.metadata ?? {};
    if (metadata.product === 'vulnpulse' && (!session.payment_status || stripeSessionComplete(session))) {
      await activateStripeLicense(env, session, rid);
    }
  } else if (event.type === 'customer.subscription.updated' || event.type === 'customer.subscription.deleted') {
    const subscription = event.data.object as StripeSubscription;
    const status = event.type === 'customer.subscription.deleted' ? 'canceled' : subscription.status ?? 'unknown';
    if (subscription.id) await updateStripeSubscriptionStatus(env, subscription.id, status, rid);
  } else if (event.type === 'invoice.payment_succeeded' || event.type === 'invoice.payment_failed') {
    const invoice = event.data.object as { subscription?: string | { id?: string } };
    const subscriptionId = stripeObjectId(invoice.subscription);
    if (subscriptionId) await updateStripeSubscriptionStatus(env, subscriptionId, event.type === 'invoice.payment_succeeded' ? 'active' : 'past_due', rid);
  }

  return Response.json({ received: true });
}

// Accept the key from Authorization: Bearer, X-API-Key, or ?api_key= (in that
// order) so it works from curl, fetch, and a browser address bar alike.
function readApiKey(req: Request): string | null {
  const auth = req.headers.get('authorization');
  if (auth && /^bearer\s+/i.test(auth)) return auth.replace(/^bearer\s+/i, '').trim();
  const x = req.headers.get('x-api-key');
  if (x) return x.trim();
  const q = new URL(req.url).searchParams.get('api_key');
  return q ? q.trim() : null;
}

interface Access {
  tier: Tier;
  rate_id: string;
  limit: number;
  remaining: number;
}

function secondsUntilUtcMidnight(): number {
  const now = new Date();
  const next = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return Math.max(1, Math.ceil((next - now.getTime()) / 1000));
}

function rateHeaders(a: Access): Record<string, string> {
  return {
    'X-RateLimit-Limit': String(a.limit),
    'X-RateLimit-Remaining': String(Math.max(0, a.remaining)),
    'X-VulnPulse-Tier': a.tier,
  };
}

// Resolve tier from the key (401 on a supplied-but-unknown key), then meter one
// request against the tier's UTC-daily budget. Returns either an early error
// Response (401/429) or the granted Access. Counter lives in VP_CVES under the
// existing rl: prefix; one get + one put per gated request (acceptable at this
// product's volume — KV's 1k put/day free cap is the operative ceiling).
async function gateRequest(req: Request, env: Env, rid: string): Promise<{ access: Access } | { error: Response }> {
  const key = readApiKey(req);
  let tier: Tier = 'free';
  let rateId: string;
  if (key) {
    const raw = await env.VP_SUBS.get(`${API_KEY_PREFIX}${key}`);
    if (!raw) {
      structuredLog(rid, 'warn', 'gate_invalid_key', { key_prefix: key.slice(0, 8) });
      return { error: errorBody(401, 'invalid_api_key', 'subscribe at /api/subscribe to get one') };
    }
    let rec: ApiKeyRecord;
    try { rec = JSON.parse(raw) as ApiKeyRecord; } catch {
      return { error: errorBody(401, 'invalid_api_key') };
    }
    tier = rec.tier === 'pro' || rec.tier === 'team' ? rec.tier : 'free';
    if (!apiKeyRecordActive(rec)) {
      structuredLog(rid, 'warn', 'gate_inactive_subscription', { tier, status: rec.status, provider: rec.provider });
      return {
        error: errorBody(402, 'subscription_inactive', 'paid subscription is not active', {
          tier,
          status: rec.status ?? 'inactive',
          provider: rec.provider ?? 'unknown',
          upgrade: '/api/pricing',
        }),
      };
    }
    rateId = `key:${hash(key)}`;
  } else {
    // anonymous → free, metered per source IP so one client can't drain another's
    const ip = req.headers.get('cf-connecting-ip') ?? 'unknown';
    rateId = `ip:${hash(ip)}`;
  }

  const limit = TIER_DAILY_API_LIMIT[tier];
  const day = new Date().toISOString().slice(0, 10);
  const rkey = `${RATE_LIMIT_KEY_PREFIX}api:${rateId}:${day}`;
  const used = Number(await env.VP_CVES.get(rkey)) || 0;
  if (used >= limit) {
    const a: Access = { tier, rate_id: rateId, limit, remaining: 0 };
    structuredLog(rid, 'warn', 'gate_rate_limited', { tier, rate_id: rateId, used, limit });
    return { error: errorBodyWithHeaders(429, 'rate_limited', { ...rateHeaders(a), 'Retry-After': String(secondsUntilUtcMidnight()) }, undefined, { tier, limit, retry_after_seconds: secondsUntilUtcMidnight(), upgrade: '/api/pricing' }) };
  }
  await env.VP_CVES.put(rkey, String(used + 1), { expirationTtl: 60 * 60 * 26 });
  return { access: { tier, rate_id: rateId, limit, remaining: limit - (used + 1) } };
}

// Free callers get a limited view: highlights are capped and a `gated` block
// tells them what they're missing + how to lift it. Paid tiers pass through.
function shapeDigestForTier(d: Digest, access: Access): Record<string, unknown> {
  if (access.tier !== 'free') return d as unknown as Record<string, unknown>;
  return {
    ...d,
    highlights: d.highlights.slice(0, FREE_HIGHLIGHT_CAP),
    gated: {
      tier: 'free',
      highlights_shown: Math.min(FREE_HIGHLIGHT_CAP, d.highlights.length),
      highlights_total: d.highlights.length,
      raw_cve_detail: 'delayed 24h on /api/cve/* — Pro/Team is real-time',
      upgrade: '/api/pricing',
    },
  };
}

// Free cap for the list-style endpoints (critical / patch-now).
function capForTier<T>(items: T[], access: Access): { items: T[]; truncated: boolean } {
  if (access.tier !== 'free' || items.length <= FREE_HIGHLIGHT_CAP) return { items, truncated: false };
  return { items: items.slice(0, FREE_HIGHLIGHT_CAP), truncated: true };
}

// === HTTP ===

async function handleLatest(_req: Request, env: Env, access: Access, _rid: string): Promise<Response> {
  const v = await env.VP_DIGEST.get(LATEST_KEY);
  if (!v) {
    return Response.json({
      message: 'no digest yet — first cron run produces it within 6 hours',
      hint: 'POST /api/run-now to trigger collection (rate-limited)',
    }, { status: 202, headers: rateHeaders(access) });
  }
  const digest = JSON.parse(v) as Digest;
  return Response.json(shapeDigestForTier(digest, access), { headers: rateHeaders(access) });
}

async function handleHistory(_req: Request, env: Env, access: Access, _rid: string): Promise<Response> {
  const list = await env.VP_DIGEST.list({ prefix: DIGEST_KEY_PREFIX, limit: 30 });
  const out: Digest[] = [];
  for (const k of list.keys) {
    if (k.name === LATEST_KEY) continue;
    const v = await env.VP_DIGEST.get(k.name);
    if (v) try { out.push(JSON.parse(v) as Digest); } catch { /* skip */ }
  }
  out.sort((a, b) => b.date_label.localeCompare(a.date_label));
  const digests = access.tier === 'free' ? out.map(d => shapeDigestForTier(d, access)) : out;
  return Response.json({ count: out.length, digests }, { headers: rateHeaders(access) });
}

async function handleCritical(_req: Request, env: Env, access: Access, _rid: string): Promise<Response> {
  const v = await env.VP_DIGEST.get(LATEST_KEY);
  if (!v) return Response.json({ critical: [] }, { status: 202, headers: rateHeaders(access) });
  const d = JSON.parse(v) as Digest;
  const { items, truncated } = capForTier(d.highlights.filter(h => h.severity === 'CRITICAL'), access);
  return Response.json({
    generated_at: d.generated_at,
    critical: items,
    ...(truncated ? { gated: { tier: 'free', limit: FREE_HIGHLIGHT_CAP, upgrade: '/api/pricing' } } : {}),
  }, { headers: rateHeaders(access) });
}

async function handlePatchNow(_req: Request, env: Env, access: Access, _rid: string): Promise<Response> {
  const v = await env.VP_DIGEST.get(LATEST_KEY);
  if (!v) return Response.json({ patch_now: [] }, { status: 202, headers: rateHeaders(access) });
  const d = JSON.parse(v) as Digest;
  const { items, truncated } = capForTier(d.highlights.filter(h => h.ai_priority === 'patch_now'), access);
  return Response.json({
    generated_at: d.generated_at,
    patch_now: items,
    ...(truncated ? { gated: { tier: 'free', limit: FREE_HIGHLIGHT_CAP, upgrade: '/api/pricing' } } : {}),
  }, { headers: rateHeaders(access) });
}

async function handleCVE(req: Request, env: Env, access: Access, rid: string): Promise<Response> {
  const url = new URL(req.url);
  const id = url.pathname.split('/').pop() ?? '';
  if (!/^CVE-\d{4}-\d{4,}$/.test(id)) {
    structuredLog(rid, 'warn', 'cve_invalid_id', { id });
    return errorBodyWithHeaders(400, 'validation_error', rateHeaders(access), 'invalid CVE id format (expected CVE-YYYY-NNNN)');
  }
  const v = await env.VP_CVES.get(`${CVE_KEY_PREFIX}${id}`);
  if (!v) {
    structuredLog(rid, 'info', 'cve_not_found', { id });
    return errorBodyWithHeaders(404, 'not_found', rateHeaders(access), 'CVE not found in current 24h window');
  }
  const cve = JSON.parse(v) as SummarizedCVE;
  // Free tier sees raw CVE detail on a 24h delay: a record modified in the last
  // 24h is real-time intel and is reserved for paid tiers.
  if (access.tier === 'free') {
    const modAt = Date.parse(cve.modified || cve.published || '');
    if (!Number.isNaN(modAt) && Date.now() - modAt < FREE_DELAY_MS) {
      return errorBodyWithHeaders(402, 'gated', rateHeaders(access), undefined, {
        reason: 'realtime_cve_detail',
        detail: 'Free tier sees CVE detail 24h after last modification. This record is newer.',
        available_at: new Date(modAt + FREE_DELAY_MS).toISOString(),
        upgrade: '/api/pricing',
      });
    }
  }
  return Response.json(cve, { headers: rateHeaders(access) });
}

async function handleRunNow(req: Request, env: Env, rid: string): Promise<Response> {
  if (req.method !== 'POST') return errorBody(405, 'method_not_allowed', 'POST only');
  // Rate-limit: per-IP, max 1 manual run per hour.
  const ip = req.headers.get('cf-connecting-ip') ?? 'unknown';
  const rkey = `${RATE_LIMIT_KEY_PREFIX}runnow:${ip}`;
  const last = await env.VP_CVES.get(rkey);
  if (last && Date.now() - Number(last) < 60 * 60 * 1000) {
    structuredLog(rid, 'warn', 'runnow_rate_limited', { ip_hash: hash(ip) });
    return errorBody(429, 'rate_limited', undefined, { retry_after_seconds: 3600 });
  }
  await env.VP_CVES.put(rkey, String(Date.now()), { expirationTtl: 3600 });
  structuredLog(rid, 'info', 'runnow_triggered', { ip_hash: hash(ip) });
  const d = await runCron(env, rid);
  return Response.json(d);
}

async function handleStatus(_req: Request, env: Env, _rid: string): Promise<Response> {
  const list = await env.VP_CVES.list({ prefix: CVE_KEY_PREFIX, limit: 1 });
  const sample = list.keys[0]?.name?.replace(CVE_KEY_PREFIX, '') ?? null;
  const subList = await env.VP_SUBS.list({ prefix: 'sub:', limit: 1 });
  return Response.json({
    name: 'VulnPulse',
    has_latest_digest: (await env.VP_DIGEST.get(LATEST_KEY)) != null,
    sample_cve: sample,
    has_subscribers: subList.keys.length > 0,
    subscription_gate: {
      enabled: true,
      tiers: TIER_DAILY_API_LIMIT,
      free_highlight_cap: FREE_HIGHLIGHT_CAP,
      free_cve_delay_hours: FREE_DELAY_MS / (60 * 60 * 1000),
      pricing: '/api/pricing',
    },
    revenue_rails: {
      crypto_active: !!env.TREASURY_WALLET,
      sponsors: 'github.com/sponsors/4444J99',
      stripe_active: stripeCheckoutConfigured(env),
      bmc_active: !!env.BMC_HANDLE,
    },
  });
}

async function handleRails(_req: Request, env: Env, _rid: string): Promise<Response> {
  // Public revenue-rail discovery — clients can offer multiple pay options to users.
  return Response.json({
    crypto: env.TREASURY_WALLET ?? null,
    sponsors_url: 'https://github.com/sponsors/4444J99',
    stripe_active: stripeCheckoutConfigured(env),
    stripe_checkout: stripeCheckoutConfigured(env) ? '/api/checkout' : null,
    stripe_claim: stripeCheckoutConfigured(env) ? '/api/checkout/claim' : null,
    bmc_url: env.BMC_HANDLE ? `https://www.buymeacoffee.com/${env.BMC_HANDLE}` : null,
  });
}

// Machine-readable pricing/tier matrix — the source of truth the README and
// PRICING.md describe in prose. Clients can render their own upgrade UI from it.
async function handlePricing(_req: Request, env: Env, _rid: string): Promise<Response> {
  return Response.json({
    currency: 'USD',
    billing: 'monthly',
    auth: {
      header: 'Authorization: Bearer <api_key>',
      alternatives: ['X-API-Key: <api_key>', '?api_key=<api_key>'],
      issued_by: 'POST /api/subscribe (free) or POST /api/checkout + /api/checkout/claim (paid Stripe); POST /api/confirm for payrail fallback',
      anonymous: 'no key → free tier, metered per IP',
    },
    tiers: [
      {
        id: 'free', price: 0, daily_api_limit: TIER_DAILY_API_LIMIT.free,
        digest_highlights: FREE_HIGHLIGHT_CAP, raw_cve_delay_hours: 24, realtime_webhook: false,
        includes: ['daily digest', 'email digest', `public API (${TIER_DAILY_API_LIMIT.free}/day)`, '24h-delayed raw CVE detail'],
      },
      {
        id: 'pro', price: Number(TIER_PRICE.pro), daily_api_limit: TIER_DAILY_API_LIMIT.pro,
        digest_highlights: 'full', raw_cve_delay_hours: 0, realtime_webhook: true,
        includes: ['real-time webhook on patch_now', 'custom filters', `API (${TIER_DAILY_API_LIMIT.pro}/day)`, 'real-time raw CVE detail'],
      },
      {
        id: 'team', price: Number(TIER_PRICE.team), daily_api_limit: TIER_DAILY_API_LIMIT.team,
        digest_highlights: 'full', raw_cve_delay_hours: 0, realtime_webhook: true,
        includes: ['everything in Pro', '5 webhooks (Slack/Teams/PagerDuty)', `API (${TIER_DAILY_API_LIMIT.team}/day)`, '5-min SLA from NVD publish'],
      },
    ],
    pay: '/api/rails',
    checkout: {
      stripe_active: stripeCheckoutConfigured(env),
      start: '/api/checkout',
      claim: '/api/checkout/claim',
      webhook: '/api/webhooks/stripe',
      payrail_confirm: '/api/confirm',
    },
  });
}

// Report the caller's resolved tier + today's quota usage. Does NOT count
// against the budget (read-only introspection), so dashboards can poll it.
async function handleMe(req: Request, env: Env, rid: string): Promise<Response> {
  const key = readApiKey(req);
  let tier: Tier = 'free';
  let rec: ApiKeyRecord | null = null;
  let rateId: string;
  if (key) {
    const raw = await env.VP_SUBS.get(`${API_KEY_PREFIX}${key}`);
    if (!raw) {
      structuredLog(rid, 'warn', 'me_invalid_key', { key_prefix: key.slice(0, 8) });
      return errorBody(401, 'invalid_api_key');
    }
    try {
      rec = JSON.parse(raw) as ApiKeyRecord;
      tier = rec.tier === 'pro' || rec.tier === 'team' ? rec.tier : 'free';
    } catch { /* default free */ }
    rateId = `key:${hash(key)}`;
  } else {
    const ip = req.headers.get('cf-connecting-ip') ?? 'unknown';
    rateId = `ip:${hash(ip)}`;
  }
  const limit = TIER_DAILY_API_LIMIT[tier];
  const day = new Date().toISOString().slice(0, 10);
  const used = Number(await env.VP_CVES.get(`${RATE_LIMIT_KEY_PREFIX}api:${rateId}:${day}`)) || 0;
  return Response.json({
    tier,
    authenticated: !!key,
    active: rec ? apiKeyRecordActive(rec) : true,
    subscription_status: rec?.status ?? (tier === 'free' ? 'free' : 'unknown'),
    provider: rec?.provider,
    daily_limit: limit,
    used_today: used,
    remaining_today: Math.max(0, limit - used),
    resets_in_seconds: secondsUntilUtcMidnight(),
  });
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const rid = genRid();
    const url = new URL(req.url);
    const p = url.pathname;
    const method = req.method;

    structuredLog(rid, 'info', 'request_start', { method, path: p, ua: req.headers.get('user-agent')?.slice(0, 80) });

    try {
      // Ungated: subscription/payment control plane + public discovery.
      if (p === '/api/subscribe') return await handleSubscribe(req, env, rid);
      if (p === '/api/checkout') return await handleCheckout(req, env, rid);
      if (p === '/api/checkout/claim') return await handleStripeClaim(req, env, rid);
      if (p === '/api/webhooks/stripe' || p === '/api/webhook/stripe') return await handleStripeWebhook(req, env, rid);
      if (p === '/api/confirm') return await handleConfirm(req, env, rid);
      if (p === '/api/pay-status') return await handlePayStatus(req, env, rid);
      if (p === '/api/run-now' && method === 'POST') return await handleRunNow(req, env, rid);
      if (p === '/api/status') return await handleStatus(req, env, rid);
      if (p === '/api/rails') return await handleRails(req, env, rid);
      if (p === '/api/pricing') return await handlePricing(req, env, rid);
      if (p === '/api/me') return await handleMe(req, env, rid);

      // Gated CVE-intelligence reads: resolve tier + meter the request once, then
      // dispatch. The gate returns an early 401/429 when the key is bad or the
      // tier's daily budget is spent.
      const isGated = p === '/api/digest/latest' || p === '/api/digest/history'
        || p === '/api/critical' || p === '/api/patch-now' || p.startsWith('/api/cve/');
      if (isGated) {
        const g = await gateRequest(req, env, rid);
        if ('error' in g) return g.error;
        const a = g.access;
        if (p === '/api/digest/latest') return await handleLatest(req, env, a, rid);
        if (p === '/api/digest/history') return await handleHistory(req, env, a, rid);
        if (p === '/api/critical') return await handleCritical(req, env, a, rid);
        if (p === '/api/patch-now') return await handlePatchNow(req, env, a, rid);
        if (p.startsWith('/api/cve/')) return await handleCVE(req, env, a, rid);
      }
      return await env.ASSETS.fetch(req);
    } catch (err) {
      if (err instanceof HttpError) {
        structuredLog(rid, 'warn', 'request_http_error', { method, path: p, status: err.status, code: err.code, error: err.message });
        return errorBody(err.status, err.code, err.message, err.detail ? { detail: err.detail } : undefined);
      }
      structuredLog(rid, 'error', 'request_unhandled', { method, path: p, error: String(err) });
      return errorBody(500, 'internal_error', 'An unexpected error occurred');
    }
  },

  async scheduled(_ev: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    const rid = genRid();
    ctx.waitUntil(runCron(env, rid).then(() => structuredLog(rid, 'info', 'cron_scheduled_completed')));
  },
};
