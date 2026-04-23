/**
 * Unit tests for report/builder.ts
 * Requirements: 6.1, 6.2, 6.3, 6.5, 7.1, 7.2, 7.3, 7.4
 */
import { describe, it, expect, vi } from "vitest";
import { buildReport, computeRiskScore } from "../builder.js";
// ─── Helpers ──────────────────────────────────────────────────────────────────
const BROWSER_INFO = {
    name: "Chrome",
    version: "120.0",
    extensionVersion: "0.1.0",
};
function makeDomFinding(id) {
    return {
        findingId: id,
        type: "dom_pattern",
        severity: "medium",
        description: "eval() detected",
        affectedResource: "https://example.com/app.js",
        details: { patternType: "eval" },
    };
}
function makeHeaderFinding(id) {
    return {
        findingId: id,
        type: "missing_header",
        severity: "high",
        description: "Missing CSP",
        affectedResource: "https://example.com",
    };
}
function mockFetch(responses) {
    return vi.fn(async (_url, init) => {
        const body = JSON.parse(init?.body ?? "{}");
        const findingId = body.finding_id;
        const resp = responses[findingId];
        if (!resp)
            throw new Error("unexpected finding_id");
        return new Response(JSON.stringify({ finding_id: findingId, ...resp }), { status: 200, headers: { "Content-Type": "application/json" } });
    });
}
function unavailableFetch() {
    return vi.fn(async () => {
        throw new Error("connection refused");
    });
}
// ─── Tests ────────────────────────────────────────────────────────────────────
describe("buildReport — ML Filter integration", () => {
    it("excludes DOM findings classified as safe", async () => {
        const domFinding = makeDomFinding("finding-1");
        const report = await buildReport({
            scannedUrl: "https://example.com",
            browserInfo: BROWSER_INFO,
            nonDomFindings: [],
            domFindings: [domFinding],
            fetchFn: mockFetch({ "finding-1": { classification: "safe", confidence: 0.95 } }),
        });
        expect(report.findings).toHaveLength(0);
        expect(report.mlFilterStatus).toBe("applied");
    });
    it("includes DOM findings classified as anomalous with mlConfidence", async () => {
        const domFinding = makeDomFinding("finding-2");
        const report = await buildReport({
            scannedUrl: "https://example.com",
            browserInfo: BROWSER_INFO,
            nonDomFindings: [],
            domFindings: [domFinding],
            fetchFn: mockFetch({ "finding-2": { classification: "anomalous", confidence: 0.87 } }),
        });
        expect(report.findings).toHaveLength(1);
        expect(report.findings[0].mlConfidence).toBe(0.87);
        expect(report.mlFilterStatus).toBe("applied");
    });
    it("includes all DOM findings unfiltered when ML Filter is unavailable", async () => {
        const domFinding1 = makeDomFinding("finding-3");
        const domFinding2 = makeDomFinding("finding-4");
        const report = await buildReport({
            scannedUrl: "https://example.com",
            browserInfo: BROWSER_INFO,
            nonDomFindings: [],
            domFindings: [domFinding1, domFinding2],
            fetchFn: unavailableFetch(),
        });
        expect(report.findings).toHaveLength(2);
        expect(report.mlFilterStatus).toBe("unavailable");
    });
    it("sets mlFilterStatus to not_applicable when there are no DOM findings", async () => {
        const report = await buildReport({
            scannedUrl: "https://example.com",
            browserInfo: BROWSER_INFO,
            nonDomFindings: [makeHeaderFinding("h-1")],
            domFindings: [],
            fetchFn: unavailableFetch(),
        });
        expect(report.mlFilterStatus).toBe("not_applicable");
    });
    it("includes non-DOM findings regardless of ML Filter status", async () => {
        const headerFinding = makeHeaderFinding("h-2");
        const domFinding = makeDomFinding("finding-5");
        const report = await buildReport({
            scannedUrl: "https://example.com",
            browserInfo: BROWSER_INFO,
            nonDomFindings: [headerFinding],
            domFindings: [domFinding],
            fetchFn: mockFetch({ "finding-5": { classification: "safe", confidence: 0.99 } }),
        });
        // DOM finding filtered out, header finding kept
        expect(report.findings).toHaveLength(1);
        expect(report.findings[0].type).toBe("missing_header");
    });
});
describe("computeRiskScore", () => {
    it("returns 0 for empty findings", () => {
        expect(computeRiskScore([])).toBe(0);
    });
    it("computes weighted sum correctly", () => {
        const findings = [
            { ...makeDomFinding("a"), severity: "critical" }, // 40
            { ...makeDomFinding("b"), severity: "high" }, // 15
            { ...makeDomFinding("c"), severity: "medium" }, // 5
            { ...makeDomFinding("d"), severity: "low" }, // 2
            { ...makeDomFinding("e"), severity: "informational" }, // 0.5
        ];
        expect(computeRiskScore(findings)).toBe(62.5);
    });
    it("caps risk score at 100", () => {
        // 3 critical findings = 120 → capped at 100
        const findings = Array.from({ length: 3 }, (_, i) => ({
            ...makeDomFinding(`crit-${i}`),
            severity: "critical",
        }));
        expect(computeRiskScore(findings)).toBe(100);
    });
    it("handles multiple findings of the same severity", () => {
        const findings = [
            { ...makeDomFinding("m1"), severity: "medium" }, // 5
            { ...makeDomFinding("m2"), severity: "medium" }, // 5
        ];
        expect(computeRiskScore(findings)).toBe(10);
    });
});
describe("buildReport — structural fields", () => {
    it("produces a report with all required fields", async () => {
        const report = await buildReport({
            scannedUrl: "https://example.com",
            browserInfo: BROWSER_INFO,
            nonDomFindings: [],
            domFindings: [],
            fetchFn: unavailableFetch(),
        });
        expect(report.schemaVersion).toBe("1.0");
        expect(report.sessionId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);
        expect(report.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/);
        expect(report.scannedUrl).toBe("https://example.com");
        expect(report.browserInfo).toEqual(BROWSER_INFO);
        expect(Array.isArray(report.findings)).toBe(true);
        expect(typeof report.riskScore).toBe("number");
        expect(report.riskScore).toBeGreaterThanOrEqual(0);
        expect(report.riskScore).toBeLessThanOrEqual(100);
        expect(report.mlFilterStatus).toBeDefined();
    });
    it("generates a unique sessionId per report", async () => {
        const opts = {
            scannedUrl: "https://example.com",
            browserInfo: BROWSER_INFO,
            nonDomFindings: [],
            domFindings: [],
            fetchFn: unavailableFetch(),
        };
        const [r1, r2] = await Promise.all([buildReport(opts), buildReport(opts)]);
        expect(r1.sessionId).not.toBe(r2.sessionId);
    });
});
//# sourceMappingURL=builder.test.js.map