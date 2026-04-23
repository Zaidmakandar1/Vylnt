/**
 * Property-based tests for scanner/headers.ts
 *
 * Property 1: Header finding completeness
 *   Validates: Requirements 1.1, 1.2, 1.3
 *
 * Property 2: Scanner error resilience
 *   Validates: Requirements 1.5
 *
 * Feature: vylnt-devguard, Property 1: Header finding completeness
 * Feature: vylnt-devguard, Property 2: Scanner error resilience
 */
import { describe, it, vi } from "vitest";
import * as fc from "fast-check";
import { inspectHeaders } from "../headers.js";
// ─── Constants ───────────────────────────────────────────────────────────────
const REQUIRED_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
];
/** Valid values for each required header that pass validation */
const VALID_VALUES = {
    "content-security-policy": "default-src 'self'",
    "strict-transport-security": "max-age=31536000",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
};
// ─── Arbitraries ─────────────────────────────────────────────────────────────
/** Generates a subset of required header names to omit (at least one) */
const missingHeadersArb = fc
    .subarray(REQUIRED_HEADERS, { minLength: 1 })
    .map((arr) => new Set(arr));
/** Generates a URL string */
const urlArb = fc.webUrl();
/** Generates a header array with some required headers missing */
const headersWithMissingArb = missingHeadersArb.map((missing) => {
    const headers = [];
    for (const name of REQUIRED_HEADERS) {
        if (!missing.has(name)) {
            headers.push({ name, value: VALID_VALUES[name] });
        }
    }
    return { headers, missing };
});
// ─── Property 1: Header finding completeness ─────────────────────────────────
describe("Property 1: Header finding completeness", () => {
    it("produces a finding for each missing required security header", () => {
        fc.assert(fc.property(urlArb, headersWithMissingArb, (url, { headers, missing }) => {
            const findings = inspectHeaders(url, headers);
            // Every missing header must have a corresponding finding
            for (const headerName of missing) {
                const hasFinding = findings.some((f) => f.type === "missing_header" &&
                    f.description.toLowerCase().includes(headerName) &&
                    f.affectedResource === url);
                if (!hasFinding)
                    return false;
            }
            // No extra missing_header findings for headers that were provided
            const missingFindings = findings.filter((f) => f.type === "missing_header");
            if (missingFindings.length !== missing.size)
                return false;
            return true;
        }), { numRuns: 200 });
    });
    it("each finding contains header name, severity, and affected URL", () => {
        fc.assert(fc.property(urlArb, headersWithMissingArb, (url, { headers, missing }) => {
            const findings = inspectHeaders(url, headers);
            const missingFindings = findings.filter((f) => f.type === "missing_header");
            for (const f of missingFindings) {
                if (!f.findingId)
                    return false;
                if (!f.severity)
                    return false;
                if (f.affectedResource !== url)
                    return false;
                if (!f.description)
                    return false;
            }
            return true;
        }), { numRuns: 200 });
    });
    it("CSP and HSTS missing findings have severity 'high'", () => {
        fc.assert(fc.property(urlArb, (url) => {
            // Only provide the three medium-severity headers
            const headers = [
                { name: "x-frame-options", value: "DENY" },
                { name: "x-content-type-options", value: "nosniff" },
                { name: "referrer-policy", value: "no-referrer" },
            ];
            const findings = inspectHeaders(url, headers);
            const cspFinding = findings.find((f) => f.description.includes("content-security-policy"));
            const hstsFinding = findings.find((f) => f.description.includes("strict-transport-security"));
            return cspFinding?.severity === "high" && hstsFinding?.severity === "high";
        }), { numRuns: 100 });
    });
});
// ─── Property 2: Scanner error resilience ────────────────────────────────────
describe("Property 2: Scanner error resilience", () => {
    it("never throws for any arbitrary header array input", () => {
        vi.spyOn(console, "error").mockImplementation(() => { });
        // Generate arbitrary arrays of objects with arbitrary string keys/values
        const arbitraryHeaderArb = fc.array(fc.record({
            name: fc.oneof(fc.string(), fc.constant(undefined)),
            value: fc.oneof(fc.string(), fc.constant(undefined)),
        }), { maxLength: 20 });
        fc.assert(fc.property(urlArb, arbitraryHeaderArb, (url, headers) => {
            let threw = false;
            try {
                inspectHeaders(url, headers);
            }
            catch {
                threw = true;
            }
            return !threw;
        }), { numRuns: 500 });
    });
    it("returns an array (possibly empty) for null/undefined inputs without throwing", () => {
        vi.spyOn(console, "error").mockImplementation(() => { });
        const nullishArb = fc.oneof(fc.constant(null), fc.constant(undefined), fc.constant([]), fc.constant([null]), fc.constant([{ name: null, value: null }]), fc.constant([{ name: 42, value: {} }]));
        fc.assert(fc.property(urlArb, nullishArb, (url, headers) => {
            let result;
            let threw = false;
            try {
                result = inspectHeaders(url, headers);
            }
            catch {
                threw = true;
            }
            return !threw && Array.isArray(result);
        }), { numRuns: 200 });
    });
    it("returns empty array when an internal error occurs", () => {
        vi.spyOn(console, "error").mockImplementation(() => { });
        fc.assert(fc.property(urlArb, (url) => {
            // Pass a Proxy that throws on property access to simulate unexpected errors
            const badInput = new Proxy([], {
                get(_target, prop) {
                    if (prop === Symbol.iterator || prop === "length") {
                        throw new Error("simulated internal error");
                    }
                    return undefined;
                },
            });
            const result = inspectHeaders(url, badInput);
            return Array.isArray(result) && result.length === 0;
        }), { numRuns: 50 });
    });
});
//# sourceMappingURL=headers.property.test.js.map