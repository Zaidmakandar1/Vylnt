/**
 * NVD Client — queries the National Vulnerability Database for CVEs
 * associated with detected third-party JavaScript libraries.
 * Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
 */

import type { Finding } from "../types/index.js";

function uuidv4(): string {
  return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, (c) => {
    const n = parseInt(c, 10);
    return (n ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (n / 4)))).toString(16);
  });
}

export interface DetectedLibrary {
  name: string;
  version: string | null;
  sourceUrl: string;
}

export interface CveEntry {
  cveId: string;
  cvssScore: number;
  description: string;
  detailUrl: string;
}

export interface NvdCache {
  get(key: string): { entries: CveEntry[]; timestamp: number } | undefined;
  set(key: string, value: { entries: CveEntry[]; timestamp: number }): void;
}

interface NvdCveItem {
  cve: {
    id: string;
    descriptions: Array<{ lang: string; value: string }>;
    metrics?: {
      cvssMetricV31?: Array<{ cvssData: { baseScore: number } }>;
      cvssMetricV30?: Array<{ cvssData: { baseScore: number } }>;
      cvssMetricV2?: Array<{ cvssData: { baseScore: number } }>;
    };
  };
}

interface NvdApiResponse {
  vulnerabilities?: NvdCveItem[];
}

function cvssToSeverity(score: number): Finding["severity"] {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

function extractCvssScore(item: NvdCveItem): number {
  const m = item.cve.metrics;
  if (!m) return 0;
  return (
    m.cvssMetricV31?.[0]?.cvssData?.baseScore ??
    m.cvssMetricV30?.[0]?.cvssData?.baseScore ??
    m.cvssMetricV2?.[0]?.cvssData?.baseScore ??
    0
  );
}

function extractDescription(item: NvdCveItem): string {
  return item.cve.descriptions.find((d) => d.lang === "en")?.value ?? item.cve.descriptions[0]?.value ?? "";
}

function cveEntriesToFindings(entries: CveEntry[], library: DetectedLibrary): Finding[] {
  return entries.map((entry) => ({
    findingId: uuidv4(),
    type: "cve" as const,
    severity: cvssToSeverity(entry.cvssScore),
    description: `${library.name}@${library.version} — ${entry.cveId}: ${entry.description}`,
    affectedResource: library.sourceUrl,
    details: { cveId: entry.cveId, cvssScore: entry.cvssScore, detailUrl: entry.detailUrl },
  }));
}

export class NvdClient {
  private readonly cache: NvdCache;
  private readonly fetchFn: typeof fetch;
  private readonly cacheMaxAgeMs: number;

  constructor(cache: NvdCache, fetchFn: typeof fetch = fetch, cacheMaxAgeMs = 24 * 60 * 60 * 1000) {
    this.cache = cache;
    this.fetchFn = fetchFn;
    this.cacheMaxAgeMs = cacheMaxAgeMs;
  }

  async checkLibrary(library: DetectedLibrary): Promise<Finding[]> {
    if (library.version === null) {
      return [{
        findingId: uuidv4(),
        type: "note",
        severity: "informational",
        description: `${library.name} was detected but version-based CVE lookup was skipped`,
        affectedResource: library.sourceUrl,
      }];
    }

    const cacheKey = `${library.name}@${library.version}`;
    const now = Date.now();
    const cached = this.cache.get(cacheKey);

    if (cached && now - cached.timestamp < this.cacheMaxAgeMs) {
      return cveEntriesToFindings(cached.entries, library);
    }

    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(library.name)}&versionStart=${encodeURIComponent(library.version)}`;

    let response: Response;
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      try {
        response = await this.fetchFn(url, { signal: controller.signal });
      } finally {
        clearTimeout(timeoutId);
      }
    } catch {
      if (cached) return cveEntriesToFindings(cached.entries, library);
      return [{
        findingId: uuidv4(),
        type: "note",
        severity: "informational",
        description: `NVD API unavailable; live CVE data could not be retrieved for ${cacheKey}`,
        affectedResource: library.sourceUrl,
      }];
    }

    if (!response.ok) {
      if (cached) return cveEntriesToFindings(cached.entries, library);
      return [{
        findingId: uuidv4(),
        type: "note",
        severity: "informational",
        description: `NVD API unavailable; live CVE data could not be retrieved for ${cacheKey}`,
        affectedResource: library.sourceUrl,
      }];
    }

    const data: NvdApiResponse = await response.json();
    const entries: CveEntry[] = (data.vulnerabilities ?? []).map((item) => ({
      cveId: item.cve.id,
      cvssScore: extractCvssScore(item),
      description: extractDescription(item),
      detailUrl: `https://nvd.nist.gov/vuln/detail/${item.cve.id}`,
    }));

    this.cache.set(cacheKey, { entries, timestamp: now });
    return cveEntriesToFindings(entries, library);
  }
}

interface LibraryPattern {
  name: string;
  urlPattern: RegExp;
  contentPattern?: RegExp;
  urlVersionRegex?: RegExp;
  contentVersionRegex?: RegExp;
}

const LIBRARY_PATTERNS: LibraryPattern[] = [
  {
    name: "jquery",
    urlPattern: /jquery/i,
    contentPattern: /jQuery\s+v(\d+\.\d+(?:\.\d+)*)/,
    urlVersionRegex: /jquery[.-](\d+\.\d+(?:\.\d+)*)(?:[.-]|$)/i,
    contentVersionRegex: /jQuery\s+v(\d+\.\d+(?:\.\d+)*)/,
  },
  { name: "react", urlPattern: /react/i, urlVersionRegex: /react[.-](\d+\.\d+(?:\.\d+)*)(?:[.-]|$)/i },
  { name: "vue", urlPattern: /\bvue\b/i, urlVersionRegex: /vue[.-](\d+\.\d+(?:\.\d+)*)(?:[.-]|$)/i },
  { name: "angular", urlPattern: /angular/i, urlVersionRegex: /angular[.-](\d+\.\d+(?:\.\d+)*)(?:[.-]|$)/i },
  { name: "bootstrap", urlPattern: /bootstrap/i, urlVersionRegex: /bootstrap[.-](\d+\.\d+(?:\.\d+)*)(?:[.-]|$)/i },
];

export function detectLibraries(scripts: Array<{ sourceUrl: string; content: string }>): DetectedLibrary[] {
  const seen = new Map<string, DetectedLibrary>();
  for (const script of scripts) {
    for (const pattern of LIBRARY_PATTERNS) {
      if (seen.has(pattern.name)) continue;
      const urlMatches = pattern.urlPattern.test(script.sourceUrl);
      const contentMatches = pattern.contentPattern ? pattern.contentPattern.test(script.content) : false;
      if (!urlMatches && !contentMatches) continue;

      let version: string | null = null;
      if (urlMatches && pattern.urlVersionRegex) {
        const m = script.sourceUrl.match(pattern.urlVersionRegex);
        if (m) version = m[1];
      }
      if (version === null && pattern.contentVersionRegex) {
        const m = script.content.match(pattern.contentVersionRegex);
        if (m) version = m[1];
      }
      seen.set(pattern.name, { name: pattern.name, version, sourceUrl: script.sourceUrl });
    }
  }
  return Array.from(seen.values());
}
