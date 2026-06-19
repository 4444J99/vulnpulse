import { describe, expect, it } from 'vitest';
import { parseNVDResponse, severityFromScore, tryParseJson } from '../src/index';

describe('severityFromScore', () => {
  it('maps CVSS bands to NVD severities', () => {
    expect(severityFromScore(9.8)).toBe('CRITICAL');
    expect(severityFromScore(9.0)).toBe('CRITICAL');
    expect(severityFromScore(7.5)).toBe('HIGH');
    expect(severityFromScore(7.0)).toBe('HIGH');
    expect(severityFromScore(4.0)).toBe('MEDIUM');
    expect(severityFromScore(0.1)).toBe('LOW');
    expect(severityFromScore(0)).toBe('NONE');
  });
});

describe('tryParseJson', () => {
  it('returns objects unchanged', () => {
    const obj = { a: 1 };
    expect(tryParseJson(obj)).toBe(obj);
  });

  it('parses fenced JSON blocks', () => {
    expect(tryParseJson('```json\n{"ok":true}\n```')).toEqual({ ok: true });
  });

  it('extracts JSON embedded in surrounding prose', () => {
    expect(tryParseJson('here you go: {"x": 2} thanks')).toEqual({ x: 2 });
  });

  it('returns null for nullish / unparseable input', () => {
    expect(tryParseJson(null)).toBeNull();
    expect(tryParseJson('not json at all')).toBeNull();
  });
});

describe('parseNVDResponse', () => {
  const makeVuln = (id: string, baseScore: number) => ({
    cve: {
      id,
      published: '2026-01-01T00:00:00.000',
      lastModified: '2026-01-02T00:00:00.000',
      descriptions: [{ lang: 'en', value: 'A remote attacker can do bad things.' }],
      metrics: {
        cvssMetricV31: [
          { cvssData: { baseScore, baseSeverity: 'HIGH', vectorString: 'CVSS:3.1/AV:N' } },
        ],
      },
      weaknesses: [{ description: [{ value: 'CWE-79' }] }],
      references: [{ url: 'https://example.com/advisory' }],
    },
  });

  it('keeps only CVSS >= 7.0 entries and shapes them', () => {
    const out = parseNVDResponse({
      vulnerabilities: [makeVuln('CVE-2026-0001', 9.1), makeVuln('CVE-2026-0002', 5.0)],
    });
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({
      id: 'CVE-2026-0001',
      cvss_score: 9.1,
      severity: 'HIGH',
      cwe_ids: ['CWE-79'],
      references: ['https://example.com/advisory'],
    });
  });

  it('tolerates empty / malformed payloads', () => {
    expect(parseNVDResponse({})).toEqual([]);
    expect(parseNVDResponse(null)).toEqual([]);
    expect(parseNVDResponse({ vulnerabilities: [{ cve: { id: '' } }] })).toEqual([]);
  });
});
