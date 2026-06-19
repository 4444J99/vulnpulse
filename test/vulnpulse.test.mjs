import test from 'node:test';
import assert from 'node:assert/strict';

import worker from '../src/index.ts';

const LATEST_KEY = 'digest:latest';

class MemoryKV {
  constructor(entries = {}) {
    this.store = new Map(Object.entries(entries));
    this.puts = [];
    this.deletes = [];
  }

  async get(key) {
    return this.store.has(key) ? this.store.get(key) : null;
  }

  async put(key, value, options) {
    const stringValue = String(value);
    this.store.set(key, stringValue);
    this.puts.push({ key, value: stringValue, options });
  }

  async delete(key) {
    this.store.delete(key);
    this.deletes.push(key);
  }

  async list(options = {}) {
    const prefix = options.prefix ?? '';
    const limit = options.limit ?? 1000;
    const keys = [...this.store.keys()]
      .filter((name) => name.startsWith(prefix))
      .sort()
      .slice(0, limit)
      .map((name) => ({ name }));
    return { keys, list_complete: true };
  }
}

function hash(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i += 1) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}

function req(path, init = {}) {
  return new Request(`https://vulnpulse.test${path}`, init);
}

async function readJson(response) {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch (err) {
    assert.fail(`Expected JSON response, got: ${text}`);
  }
}

function cve(id, overrides = {}) {
  return {
    id,
    published: '2026-06-18T00:00:00.000Z',
    modified: '2026-06-18T12:00:00.000Z',
    cvss_score: 9.8,
    severity: 'CRITICAL',
    vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    description: `${id} description`,
    references: [`https://example.test/${id}`],
    cwe_ids: ['CWE-79'],
    ai_impact: 'Attackers can reach the vulnerable service remotely.',
    ai_mitigation: 'Patch the affected package.',
    ai_exploitability: 'poc_likely',
    ai_priority: 'patch_now',
    ai_tags: ['rce', 'web'],
    ai_class: 'web-app',
    ...overrides,
  };
}

function digestFixture(highlightCount = 7) {
  const highlights = Array.from({ length: highlightCount }, (_, index) => {
    const n = index + 1;
    return cve(`CVE-2026-${String(1000 + n)}`, {
      cvss_score: n % 2 === 0 ? 8.8 : 9.8,
      severity: n % 2 === 0 ? 'HIGH' : 'CRITICAL',
      ai_priority: n <= 6 ? 'patch_now' : 'patch_soon',
    });
  });
  return {
    generated_at: '2026-06-19T00:00:00.000Z',
    date_label: '2026-06-19',
    total_cves: highlights.length,
    critical_count: highlights.filter((h) => h.severity === 'CRITICAL').length,
    high_count: highlights.filter((h) => h.severity === 'HIGH').length,
    one_line: `${highlights.length} test CVEs.`,
    highlights,
    by_class: { 'web-app': highlights.length },
    patch_now_ids: highlights.filter((h) => h.ai_priority === 'patch_now').map((h) => h.id),
  };
}

function createAssets(status = 203, body = 'asset fallback') {
  return {
    requests: [],
    async fetch(request) {
      this.requests.push(request);
      return new Response(body, { status, headers: { 'x-assets': 'hit' } });
    },
  };
}

function createAI(run) {
  const ai = {
    calls: [],
    async run(model, payload) {
      ai.calls.push({ model, payload });
      if (run) return run(model, payload);
      return {
        response: JSON.stringify({
          ai_impact: 'Impact summary.',
          ai_mitigation: 'Mitigation summary.',
          ai_exploitability: 'unknown',
          ai_priority: 'monitor',
          ai_tags: ['web'],
          ai_class: 'web-app',
        }),
      };
    },
  };
  return ai;
}

function createPayrail() {
  const calls = [];
  return {
    calls,
    async fetch(request) {
      const body = await request.clone().text();
      calls.push({
        method: request.method,
        url: new URL(request.url),
        headers: request.headers,
        body,
      });
      const url = new URL(request.url);
      if (url.pathname === '/pay') {
        return Response.json({
          quote_id: 'quote_pro_123',
          pay_to: {
            rail: 'crypto',
            chain: 'base',
            asset: 'USDC',
            address: '0xabc',
            amount: url.searchParams.get('amount'),
          },
          checkout: null,
          instructions: 'Send USDC and include the quote id.',
          expires_in_seconds: 900,
        });
      }
      if (url.pathname === '/receipt') {
        return Response.json({ ok: true, receipt: { id: 'receipt_123' } });
      }
      if (url.pathname === '/receipt/quote_pro_123') {
        return Response.json({ id: 'receipt_123' });
      }
      return Response.json({ error: 'not_found' }, { status: 404 });
    },
  };
}

function createEnv(options = {}) {
  const env = {
    AI: createAI(options.aiRun),
    ASSETS: options.assets ?? createAssets(),
    VP_CVES: new MemoryKV(options.cves),
    VP_DIGEST: new MemoryKV(options.digests),
    VP_SUBS: new MemoryKV(options.subs),
    USER_AGENT: 'vulnpulse-test-agent',
    TREASURY_WALLET: options.treasuryWallet,
    STRIPE_PUBLIC: options.stripePublic,
    BMC_HANDLE: options.bmcHandle,
    SHIP_HMAC_SECRET: options.shipHmacSecret,
  };
  if (options.payrail) env.PAYRAIL = options.payrail;
  return env;
}

function keyRecord(tier = 'team') {
  return JSON.stringify({ tier, ident_hash: `${tier}-ident`, created_at: '2026-06-19T00:00:00.000Z' });
}

function nvdVuln({ id, score, description = `${id} description`, cwes = ['CWE-79'], refs = [], metric = 'cvssMetricV31' }) {
  return {
    cve: {
      id,
      published: '2026-06-18T00:00:00.000Z',
      lastModified: '2026-06-18T12:00:00.000Z',
      descriptions: [
        { lang: 'es', value: 'descripcion ignorada' },
        { lang: 'en', value: description },
      ],
      metrics: {
        [metric]: [
          {
            cvssData: {
              baseScore: score,
              vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            },
          },
        ],
      },
      weaknesses: cwes.map((value) => ({ description: [{ lang: 'en', value }] })),
      references: refs.map((url) => ({ url })),
    },
  };
}

test('free and paid latest digest responses are tier-shaped and metered', async () => {
  const digest = digestFixture(7);
  const env = createEnv({
    digests: { [LATEST_KEY]: JSON.stringify(digest) },
    subs: { 'key:vpt_test_key': keyRecord('team') },
  });

  const freeResponse = await worker.fetch(
    req('/api/digest/latest', { headers: { 'cf-connecting-ip': '203.0.113.10' } }),
    env,
  );
  const freeBody = await readJson(freeResponse);

  assert.equal(freeResponse.status, 200);
  assert.equal(freeResponse.headers.get('X-VulnPulse-Tier'), 'free');
  assert.equal(freeResponse.headers.get('X-RateLimit-Limit'), '50');
  assert.equal(freeResponse.headers.get('X-RateLimit-Remaining'), '49');
  assert.equal(freeBody.highlights.length, 5);
  assert.equal(freeBody.gated.tier, 'free');
  assert.equal(freeBody.gated.highlights_shown, 5);
  assert.equal(freeBody.gated.highlights_total, 7);
  assert.equal(freeBody.gated.raw_cve_detail, 'delayed 24h on /api/cve/* \u2014 Pro/Team is real-time');
  assert.equal(freeBody.gated.upgrade, '/api/pricing');

  const paidResponse = await worker.fetch(
    req('/api/digest/latest', { headers: { authorization: 'Bearer vpt_test_key' } }),
    env,
  );
  const paidBody = await readJson(paidResponse);

  assert.equal(paidResponse.status, 200);
  assert.equal(paidResponse.headers.get('X-VulnPulse-Tier'), 'team');
  assert.equal(paidResponse.headers.get('X-RateLimit-Limit'), '50000');
  assert.equal(paidBody.highlights.length, 7);
  assert.equal(paidBody.gated, undefined);
});

test('gated endpoints reject bad keys and enforce the daily quota', async () => {
  const ip = '198.51.100.25';
  const today = new Date().toISOString().slice(0, 10);
  const env = createEnv({
    cves: { [`rl:api:ip:${hash(ip)}:${today}`]: '50' },
  });

  const invalidKey = await worker.fetch(
    req('/api/digest/latest', { headers: { authorization: 'Bearer missing_key' } }),
    env,
  );
  assert.equal(invalidKey.status, 401);
  assert.deepEqual(await readJson(invalidKey), {
    error: 'invalid_api_key',
    hint: 'subscribe at /api/subscribe to get one',
  });

  const limited = await worker.fetch(
    req('/api/digest/latest', { headers: { 'cf-connecting-ip': ip } }),
    env,
  );
  const limitedBody = await readJson(limited);

  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get('X-VulnPulse-Tier'), 'free');
  assert.equal(limited.headers.get('X-RateLimit-Remaining'), '0');
  assert.equal(limitedBody.error, 'rate_limited');
  assert.equal(limitedBody.limit, 50);
  assert.ok(Number(limited.headers.get('Retry-After')) > 0);
});

test('CVE detail applies the free 24 hour delay while paid keys get real-time data', async () => {
  const recent = cve('CVE-2026-2001', { modified: new Date().toISOString() });
  const stale = cve('CVE-2026-2002', { modified: new Date(Date.now() - 25 * 60 * 60 * 1000).toISOString() });
  const env = createEnv({
    cves: {
      'cve:CVE-2026-2001': JSON.stringify(recent),
      'cve:CVE-2026-2002': JSON.stringify(stale),
    },
    subs: { 'key:vpp_test_key': keyRecord('pro') },
  });

  const gated = await worker.fetch(
    req('/api/cve/CVE-2026-2001', { headers: { 'cf-connecting-ip': '203.0.113.20' } }),
    env,
  );
  const gatedBody = await readJson(gated);

  assert.equal(gated.status, 402);
  assert.equal(gatedBody.error, 'gated');
  assert.equal(gatedBody.reason, 'realtime_cve_detail');
  assert.match(gatedBody.available_at, /^20\d\d-/);

  const staleResponse = await worker.fetch(
    req('/api/cve/CVE-2026-2002', { headers: { 'cf-connecting-ip': '203.0.113.20' } }),
    env,
  );
  assert.equal(staleResponse.status, 200);
  assert.equal((await readJson(staleResponse)).id, 'CVE-2026-2002');

  const paidResponse = await worker.fetch(
    req('/api/cve/CVE-2026-2001', { headers: { 'x-api-key': 'vpp_test_key' } }),
    env,
  );
  assert.equal(paidResponse.status, 200);
  assert.equal((await readJson(paidResponse)).id, 'CVE-2026-2001');
});

test('subscription and payment confirmation issue API keys and persist state', async () => {
  const payrail = createPayrail();
  const env = createEnv({ payrail });

  const freeResponse = await worker.fetch(
    req('/api/subscribe', {
      method: 'POST',
      body: JSON.stringify({ email: 'analyst@example.test' }),
      headers: { 'content-type': 'application/json' },
    }),
    env,
  );
  const freeBody = await readJson(freeResponse);

  assert.equal(freeResponse.status, 200);
  assert.equal(freeBody.tier, 'free');
  assert.match(freeBody.api_key, /^vpf_[a-f0-9]{48}$/);
  assert.ok(await env.VP_SUBS.get(`key:${freeBody.api_key}`));
  assert.ok(await env.VP_SUBS.get(`sub:${hash('analyst@example.test')}`));

  const paidResponse = await worker.fetch(
    req('/api/subscribe', {
      method: 'POST',
      body: JSON.stringify({ email: 'soc@example.test', tier: 'pro' }),
      headers: { 'content-type': 'application/json' },
    }),
    env,
  );
  const paidBody = await readJson(paidResponse);

  assert.equal(paidResponse.status, 402);
  assert.equal(paidBody.status, 'payment_required');
  assert.equal(paidBody.tier, 'pro');
  assert.equal(paidBody.quote_id, 'quote_pro_123');
  assert.equal(payrail.calls[0].url.pathname, '/pay');
  assert.equal(payrail.calls[0].url.searchParams.get('sku'), 'vulnpulse:pro');
  assert.ok(await env.VP_SUBS.get('pending:quote_pro_123'));

  const confirmResponse = await worker.fetch(
    req('/api/confirm', {
      method: 'POST',
      body: JSON.stringify({ quote_id: 'quote_pro_123', tx_hash: '0xdeadbeef' }),
      headers: { 'content-type': 'application/json' },
    }),
    env,
  );
  const confirmBody = await readJson(confirmResponse);

  assert.equal(confirmResponse.status, 201);
  assert.equal(confirmBody.tier, 'pro');
  assert.match(confirmBody.api_key, /^vpp_[a-f0-9]{48}$/);
  assert.equal(await env.VP_SUBS.get('pending:quote_pro_123'), null);
  assert.ok(await env.VP_SUBS.get(`key:${confirmBody.api_key}`));
  assert.equal(payrail.calls[1].url.pathname, '/receipt');
  assert.match(payrail.calls[1].body, /0xdeadbeef/);
});

test('run-now fetches NVD, summarizes high and critical CVEs, and stores the digest', async () => {
  const originalFetch = globalThis.fetch;
  const fetchCalls = [];
  const references = Array.from({ length: 10 }, (_, index) => `https://advisory.example/${index}`);

  globalThis.fetch = async (url, init) => {
    const parsed = new URL(String(url));
    fetchCalls.push({ url: parsed, init });
    assert.equal(parsed.hostname, 'services.nvd.nist.gov');
    assert.equal(init.headers['User-Agent'], 'vulnpulse-test-agent');
    assert.equal(parsed.searchParams.get('resultsPerPage'), '50');

    if (parsed.searchParams.get('cvssV3Severity') === 'CRITICAL') {
      return Response.json({
        vulnerabilities: [
          nvdVuln({ id: 'CVE-2026-3001', score: 9.8, cwes: ['CWE-89'], refs: references }),
          nvdVuln({ id: 'CVE-2026-3003', score: 6.9 }),
        ],
      });
    }

    return Response.json({
      vulnerabilities: [
        nvdVuln({ id: 'CVE-2026-3002', score: 8.8, description: 'A'.repeat(1305), refs: references }),
        nvdVuln({ id: 'CVE-2026-3004', score: 5.0 }),
        { cve: { id: 'CVE-2026-3005', metrics: {} } },
      ],
    });
  };

  const env = createEnv({
    aiRun: async (_model, payload) => {
      const prompt = payload.messages.at(-1).content;
      const isCritical = prompt.includes('CVE-2026-3001');
      return {
        response: `prefix ${JSON.stringify({
          ai_impact: isCritical ? 'Remote unauthenticated compromise.' : 'Remote service disruption.',
          ai_mitigation: 'Apply the vendor patch.',
          ai_exploitability: 'poc_likely',
          ai_priority: isCritical ? 'patch_now' : 'patch_soon',
          ai_tags: ['rce', 'web', 'triage'],
          ai_class: 'web-app',
        })} suffix`,
      };
    },
  });

  try {
    const response = await worker.fetch(
      req('/api/run-now', { method: 'POST', headers: { 'cf-connecting-ip': '192.0.2.55' } }),
      env,
    );
    const body = await readJson(response);

    assert.equal(response.status, 200);
    assert.equal(fetchCalls.length, 2);
    assert.deepEqual(fetchCalls.map((call) => call.url.searchParams.get('cvssV3Severity')).sort(), ['CRITICAL', 'HIGH']);
    assert.equal(env.AI.calls.length, 2);
    assert.equal(body.total_cves, 2);
    assert.equal(body.critical_count, 1);
    assert.equal(body.high_count, 1);
    assert.deepEqual(body.patch_now_ids, ['CVE-2026-3001']);
    assert.deepEqual(body.by_class, { 'web-app': 2 });
    assert.equal(body.one_line, '1 critical / 1 high CVEs in last 24h \u2014 1 flagged patch-now.');

    const storedDigest = JSON.parse(await env.VP_DIGEST.get(LATEST_KEY));
    assert.equal(storedDigest.total_cves, 2);
    assert.equal(await env.VP_CVES.get('cve:CVE-2026-3004'), null);
    assert.equal(await env.VP_CVES.get('cve:CVE-2026-3005'), null);

    const storedHigh = JSON.parse(await env.VP_CVES.get('cve:CVE-2026-3002'));
    assert.equal(storedHigh.description.length, 1200);
    assert.equal(storedHigh.references.length, 8);
    assert.equal(storedHigh.ai_priority, 'patch_soon');

    const secondRun = await worker.fetch(
      req('/api/run-now', { method: 'POST', headers: { 'cf-connecting-ip': '192.0.2.55' } }),
      env,
    );
    assert.equal(secondRun.status, 429);
    assert.deepEqual(await readJson(secondRun), { error: 'rate_limited', retry_after_seconds: 3600 });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('scheduled events queue a cron run with waitUntil', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ vulnerabilities: [] });
  const env = createEnv();
  const waitUntilCalls = [];
  const ctx = {
    waitUntil(promise) {
      waitUntilCalls.push(promise);
    },
  };

  try {
    await worker.scheduled({}, env, ctx);
    assert.equal(waitUntilCalls.length, 1);
    await waitUntilCalls[0];

    const latest = JSON.parse(await env.VP_DIGEST.get(LATEST_KEY));
    assert.equal(latest.total_cves, 0);
    assert.equal(latest.one_line, 'Quiet 24h \u2014 no high+critical CVEs published.');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('ungated discovery endpoints and asset fallback stay available', async () => {
  const assets = createAssets(200, 'asset page');
  const env = createEnv({
    assets,
    cves: { 'cve:CVE-2026-4001': JSON.stringify(cve('CVE-2026-4001')) },
    digests: { [LATEST_KEY]: JSON.stringify(digestFixture(1)) },
    subs: { 'sub:abc': JSON.stringify({ tier: 'free' }) },
    treasuryWallet: '0xwallet',
    stripePublic: 'pk_test',
    bmcHandle: 'vulnpulse',
  });

  const pricing = await worker.fetch(req('/api/pricing'), env);
  assert.equal(pricing.status, 200);
  assert.equal((await readJson(pricing)).tiers.length, 3);

  const rails = await worker.fetch(req('/api/rails'), env);
  assert.deepEqual(await readJson(rails), {
    crypto: '0xwallet',
    sponsors_url: 'https://github.com/sponsors/4444J99',
    stripe_active: true,
    bmc_url: 'https://www.buymeacoffee.com/vulnpulse',
  });

  const status = await worker.fetch(req('/api/status'), env);
  const statusBody = await readJson(status);
  assert.equal(statusBody.name, 'VulnPulse');
  assert.equal(statusBody.has_latest_digest, true);
  assert.equal(statusBody.sample_cve, 'CVE-2026-4001');
  assert.equal(statusBody.has_subscribers, true);

  const fallback = await worker.fetch(req('/not-an-api-route'), env);
  assert.equal(fallback.status, 200);
  assert.equal(fallback.headers.get('x-assets'), 'hit');
  assert.equal(assets.requests.length, 1);
});
