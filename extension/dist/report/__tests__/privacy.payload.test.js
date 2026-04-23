/**
 * Property-based tests for transmitted payload privacy invariant.
 *
 * // Feature: vylnt-devguard, Property 22: Transmitted payload privacy invariant
 * Validates: Requirements 13.4
 */
import { describe, it, expect, vi } from "vitest";
import * as fc from "fast-check";
import { submitReport } from "../submitter.js";
// ─── Arbitraries ─────────────────────────────────────────────────────────────
const severityArb = fc.constantFrom("critical", "high", "medium", "low", "informational");
const findingTypeArb = fc.constantFrom("missing_header", "misconfigured_header", "insecure_cookie", "mixed_content", "dom_pattern", "cve", "note");
const findingArb = fc.record({
    findingId: fc.uuid(),
    type: findingTypeArb,
    severity: severityArb,
    description: fc.string({ minLength: 1, maxLength: 100 }),
    affectedResource: fc.webUrl(),
});
const scanReportArb = fc.record({
    schemaVersion: fc.constant("1.0"),
    sessionId: fc.uuid(),
    timestamp: fc.date().map((d) => d.toISOString()),
    scannedUrl: fc.webUrl(),
    browserInfo: fc.record({
        name: fc.constantFrom("Chrome", "Firefox", "Edge"),
        version: fc.string({ minLength: 1, maxLength: 20 }),
        extensionVersion: fc.string({ minLength: 1, maxLength: 10 }),
    }),
    findings: fc.array(findingArb, { minLength: 0, maxLength: 10 }),
    riskScore: fc.float({ min: 0, max: 100, noNaN: true }),
    mlFilterStatus: fc.constantFrom("applied", "unavailable", "not_applicable"),
});
// ─── Forbidden payload fields ─────────────────────────────────────────────────
/**
 * Fields that must NEVER appear in the transmitted payload.
 * These represent page content, DOM tree, and form data.
 */
const FORBIDDEN_KEYS = [
    "pageContent",
    "domTree",
    "htmlContent",
    "formData",
    "inputValues",
    "rawHtml",
    "bodyText",
    "documentContent",
    "innerHTML",
    "outerHTML",
    "textContent",
    "userInput",
    "formFields",
    "cookies", // raw cookie values (not findings about cookies)
    "localStorage",
    "sessionStorage",
];
function containsForbiddenKey(obj, depth = 0) {
    if (depth > 10 || obj === null || typeof obj !== "object")
        return false;
    for (const key of Object.keys(obj)) {
        if (FORBIDDEN_KEYS.includes(key))
            return true;
        if (containsForbiddenKey(obj[key], depth + 1))
            return true;
    }
    return false;
}
// ─── Property 22: Transmitted payload privacy invariant ──────────────────────
describe("Property 22: Transmitted payload privacy invariant", () => {
    it("transmitted payload contains only ScanReport fields — no page content, DOM tree, or form data", async () => {
        await fc.assert(fc.asyncProperty(scanReportArb, async (report) => {
            let capturedBody = null;
            const fetchMock = vi.fn().mockImplementation(async (_url, init) => {
                capturedBody = JSON.parse(init.body);
                return new Response(null, { status: 201 });
            });
            const storageMock = {
                get: vi.fn().mockResolvedValue({ pendingReports: [] }),
                set: vi.fn().mockResolvedValue(undefined),
            };
            await submitReport(report, {
                fetchFn: fetchMock,
                storage: storageMock,
            });
            expect(fetchMock).toHaveBeenCalledOnce();
            expect(capturedBody).not.toBeNull();
            // The payload must not contain any forbidden keys
            expect(containsForbiddenKey(capturedBody)).toBe(false);
            // The payload must contain the scanned URL
            expect(capturedBody.scannedUrl).toBe(report.scannedUrl);
            // The payload must contain findings metadata (array)
            expect(Array.isArray(capturedBody.findings)).toBe(true);
            // The payload must be a valid ScanReport structure (required fields present)
            const payload = capturedBody;
            expect(payload.schemaVersion).toBe("1.0");
            expect(typeof payload.sessionId).toBe("string");
            expect(typeof payload.timestamp).toBe("string");
            expect(typeof payload.riskScore).toBe("number");
            expect(typeof payload.mlFilterStatus).toBe("string");
        }), { numRuns: 100 });
    });
    it("payload does not grow beyond ScanReport fields even with many findings", async () => {
        await fc.assert(fc.asyncProperty(fc.array(findingArb, { minLength: 1, maxLength: 50 }), async (findings) => {
            const report = {
                schemaVersion: "1.0",
                sessionId: "00000000-0000-4000-8000-000000000001",
                timestamp: new Date().toISOString(),
                scannedUrl: "https://example.com",
                browserInfo: { name: "Chrome", version: "120", extensionVersion: "0.1.0" },
                findings,
                riskScore: 0,
                mlFilterStatus: "not_applicable",
            };
            let capturedBody = null;
            const fetchMock = vi.fn().mockImplementation(async (_url, init) => {
                capturedBody = JSON.parse(init.body);
                return new Response(null, { status: 201 });
            });
            await submitReport(report, {
                fetchFn: fetchMock,
                storage: {
                    get: vi.fn().mockResolvedValue({ pendingReports: [] }),
                    set: vi.fn().mockResolvedValue(undefined),
                },
            });
            // Each finding in the payload must only have ScanReport Finding fields
            const payload = capturedBody;
            for (const finding of payload.findings) {
                expect(containsForbiddenKey(finding)).toBe(false);
                // Required finding fields
                expect(typeof finding.findingId).toBe("string");
                expect(typeof finding.type).toBe("string");
                expect(typeof finding.severity).toBe("string");
                expect(typeof finding.description).toBe("string");
                expect(typeof finding.affectedResource).toBe("string");
            }
        }), { numRuns: 100 });
    });
});
//# sourceMappingURL=privacy.payload.test.js.map