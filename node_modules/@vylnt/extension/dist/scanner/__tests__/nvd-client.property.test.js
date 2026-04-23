/**
 * Property-based tests for scanner/nvd-client.ts
 *
 * Property 7: CVE finding completeness — Validates: Requirements 5.2
 * Property 8: NVD cache hit prevents redundant API calls — Validates: Requirements 5.3
 *
 * Feature: vylnt-devguard, Property 7: CVE finding completeness
 * Feature: vylnt-devguard, Property 8: NVD cache hit prevents redundant API calls
 */
import { describe, it } from "vitest";
import * as fc from "fast-check";
import { NvdClient } from "../nvd-client.js";
function makeCache() {
    const store = new Map();
    return { get: (k) => store.get(k), set: (k, v) => { store.set(k, v); } };
}
function buildNvdResponse(entries) {
    return JSON.stringify({
        vulnerabilities: entries.map((e) => ({
            cve: {
                id: e.cveId,
                descriptions: [{ lang: "en", value: e.description }],
                metrics: { cvssMetricV31: [{ cvssData: { baseScore: e.cvssScore } }] },
            },
        })),
    });
}
const cveEntryArb = fc.record({
    cveId: fc.tuple(fc.integer({ min: 1999, max: 2030 }), fc.integer({ min: 1, max: 99999 }))
        .map(([y, n]) => `CVE-${y}-${String(n).padStart(4, "0")}`),
    cvssScore: fc.float({ min: 0, max: 10, noNaN: true }).map((n) => Math.round(n * 10) / 10),
    description: fc.string({ minLength: 1, maxLength: 100 }),
    detailUrl: fc.constant("https://nvd.nist.gov/vuln/detail/CVE-2024-0001"),
});
const detectedLibraryArb = fc.record({
    name: fc.constantFrom("jquery", "react", "vue", "angular", "bootstrap"),
    version: fc.tuple(fc.integer({ min: 1, max: 9 }), fc.integer({ min: 0, max: 20 }), fc.integer({ min: 0, max: 20 }))
        .map(([a, b, c]) => `${a}.${b}.${c}`),
    sourceUrl: fc.constant("https://cdn.example.com/lib.js"),
});
describe("Property 7: CVE finding completeness", () => {
    it("produces a finding for each CVE with all required fields", async () => {
        await fc.assert(fc.asyncProperty(detectedLibraryArb, fc.array(cveEntryArb, { minLength: 1, maxLength: 5 }), async (library, cveEntries) => {
            const unique = Array.from(new Map(cveEntries.map((e) => [e.cveId, e])).values());
            const mockFetch = async () => new Response(buildNvdResponse(unique), { status: 200 });
            const findings = await new NvdClient(makeCache(), mockFetch).checkLibrary(library);
            if (findings.length !== unique.length)
                return false;
            for (const f of findings) {
                if (!f.findingId || f.type !== "cve" || !f.severity || !f.description || !f.affectedResource)
                    return false;
                if (!f.details || typeof f.details.cveId !== "string" || typeof f.details.cvssScore !== "number" || typeof f.details.detailUrl !== "string")
                    return false;
            }
            return true;
        }), { numRuns: 100 });
    });
    it("CVSS score maps to correct severity bucket", async () => {
        await fc.assert(fc.asyncProperty(detectedLibraryArb, fc.float({ min: 0, max: 10, noNaN: true }).map((n) => Math.round(n * 10) / 10), async (library, score) => {
            const entry = { cveId: "CVE-2024-0001", cvssScore: score, description: "test", detailUrl: "https://nvd.nist.gov/vuln/detail/CVE-2024-0001" };
            const mockFetch = async () => new Response(buildNvdResponse([entry]), { status: 200 });
            const findings = await new NvdClient(makeCache(), mockFetch).checkLibrary(library);
            if (findings.length !== 1)
                return false;
            const sev = findings[0].severity;
            if (score >= 9.0)
                return sev === "critical";
            if (score >= 7.0)
                return sev === "high";
            if (score >= 4.0)
                return sev === "medium";
            return sev === "low";
        }), { numRuns: 200 });
    });
});
describe("Property 8: NVD cache hit prevents redundant API calls", () => {
    it("second query within 24h uses cache and makes zero new API calls", async () => {
        await fc.assert(fc.asyncProperty(detectedLibraryArb, fc.array(cveEntryArb, { minLength: 0, maxLength: 5 }), async (library, cveEntries) => {
            let callCount = 0;
            const mockFetch = async () => { callCount++; return new Response(buildNvdResponse(cveEntries), { status: 200 }); };
            const client = new NvdClient(makeCache(), mockFetch);
            await client.checkLibrary(library);
            const before = callCount;
            await client.checkLibrary(library);
            return before === 1 && callCount === 1;
        }), { numRuns: 100 });
    });
    it("expired cache triggers a new API call", async () => {
        await fc.assert(fc.asyncProperty(detectedLibraryArb, async (library) => {
            let callCount = 0;
            const mockFetch = async () => { callCount++; return new Response(buildNvdResponse([]), { status: 200 }); };
            const client = new NvdClient(makeCache(), mockFetch, 0);
            await client.checkLibrary(library);
            await client.checkLibrary(library);
            return callCount === 2;
        }), { numRuns: 50 });
    });
});
//# sourceMappingURL=nvd-client.property.test.js.map