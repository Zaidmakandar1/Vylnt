// Feature: vylnt-devguard, Property 10: Scan Report structural invariants
/**
 * Property-based tests for Scan Report structural invariants.
 * Validates: Requirements 7.1, 7.2, 7.3, 7.4
 */
import { describe, it, expect, vi } from "vitest";
import * as fc from "fast-check";
import { buildReport } from "../builder.js";
// ─── Arbitraries ──────────────────────────────────────────────────────────────
const arbSeverity = fc.constantFrom("critical", "high", "medium", "low", "informational");
const arbFindingType = fc.constantFrom("missing_header", "misconfigured_header", "insecure_cookie", "mixed_content", "cve", "note");
const arbNonDomFinding = fc.record({
    findingId: fc.uuid(),
    type: arbFindingType,
    severity: arbSeverity,
    description: fc.string({ minLength: 1, maxLength: 200 }),
    affectedResource: fc.webUrl(),
});
const arbBrowserInfo = fc.record({
    name: fc.constantFrom("Chrome", "Firefox", "Edge"),
    version: fc.tuple(fc.integer({ min: 100, max: 130 }), fc.integer({ min: 0, max: 9 })).map(([maj, min]) => `${maj}.${min}`),
    extensionVersion: fc.constantFrom("0.1.0", "0.2.0", "1.0.0"),
});
const arbScannedUrl = fc.webUrl();
// Fetch that always fails (ML filter unavailable) — keeps tests deterministic
function unavailableFetch() {
    return vi.fn(async () => { throw new Error("unavailable"); });
}
// ─── Properties ───────────────────────────────────────────────────────────────
describe("Property 10: Scan Report structural invariants", () => {
    it("every report has a UUID v4 sessionId", async () => {
        await fc.assert(fc.asyncProperty(arbBrowserInfo, arbScannedUrl, fc.array(arbNonDomFinding, { maxLength: 10 }), async (browserInfo, scannedUrl, nonDomFindings) => {
            const report = await buildReport({
                scannedUrl,
                browserInfo,
                nonDomFindings,
                domFindings: [],
                fetchFn: unavailableFetch(),
            });
            expect(report.sessionId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
        }), { numRuns: 100 });
    });
    it("every report has a non-empty schemaVersion", async () => {
        await fc.assert(fc.asyncProperty(arbBrowserInfo, arbScannedUrl, fc.array(arbNonDomFinding, { maxLength: 10 }), async (browserInfo, scannedUrl, nonDomFindings) => {
            const report = await buildReport({
                scannedUrl,
                browserInfo,
                nonDomFindings,
                domFindings: [],
                fetchFn: unavailableFetch(),
            });
            expect(report.schemaVersion.length).toBeGreaterThan(0);
        }), { numRuns: 100 });
    });
    it("riskScore is always in [0, 100]", async () => {
        await fc.assert(fc.asyncProperty(arbBrowserInfo, arbScannedUrl, fc.array(arbNonDomFinding, { maxLength: 20 }), async (browserInfo, scannedUrl, nonDomFindings) => {
            const report = await buildReport({
                scannedUrl,
                browserInfo,
                nonDomFindings,
                domFindings: [],
                fetchFn: unavailableFetch(),
            });
            expect(report.riskScore).toBeGreaterThanOrEqual(0);
            expect(report.riskScore).toBeLessThanOrEqual(100);
        }), { numRuns: 100 });
    });
    it("every report contains all required fields", async () => {
        await fc.assert(fc.asyncProperty(arbBrowserInfo, arbScannedUrl, fc.array(arbNonDomFinding, { maxLength: 10 }), async (browserInfo, scannedUrl, nonDomFindings) => {
            const report = await buildReport({
                scannedUrl,
                browserInfo,
                nonDomFindings,
                domFindings: [],
                fetchFn: unavailableFetch(),
            });
            expect(report).toHaveProperty("sessionId");
            expect(report).toHaveProperty("timestamp");
            expect(report).toHaveProperty("scannedUrl");
            expect(report).toHaveProperty("browserInfo");
            expect(report).toHaveProperty("findings");
            expect(report).toHaveProperty("riskScore");
            expect(report).toHaveProperty("mlFilterStatus");
        }), { numRuns: 100 });
    });
    it("sessionIds are unique across independently generated reports", async () => {
        await fc.assert(fc.asyncProperty(arbBrowserInfo, arbScannedUrl, async (browserInfo, scannedUrl) => {
            const opts = {
                scannedUrl,
                browserInfo,
                nonDomFindings: [],
                domFindings: [],
                fetchFn: unavailableFetch(),
            };
            const [r1, r2] = await Promise.all([buildReport(opts), buildReport(opts)]);
            expect(r1.sessionId).not.toBe(r2.sessionId);
        }), { numRuns: 50 });
    });
});
//# sourceMappingURL=builder.property.test.js.map