/**
 * Property-based tests for scanner/cookies.ts
 *
 * Property 3: Cookie finding completeness
 *   For any cookie missing one or more of the Secure, HttpOnly, or SameSite attributes
 *   (or having SameSite=None without Secure), the scanner SHALL produce a finding
 *   containing the cookie name and the specific missing or misconfigured attribute(s).
 *
 * Feature: vylnt-devguard, Property 3: Cookie finding completeness
 * Validates: Requirements 2.1, 2.2, 2.3, 2.4
 */
import { describe, it } from "vitest";
import * as fc from "fast-check";
import { inspectCookies } from "../cookies.js";
// ─── Arbitraries ─────────────────────────────────────────────────────────────
/** Generates a simple cookie name (alphanumeric, no special chars) */
const cookieNameArb = fc
    .stringMatching(/^[a-zA-Z][a-zA-Z0-9_]{0,15}$/)
    .filter((s) => s.length > 0);
/** Generates a simple cookie value */
const cookieValueArb = fc.stringMatching(/^[a-zA-Z0-9]{0,20}$/);
/** Generates a SameSite value */
const sameSiteArb = fc.oneof(fc.constant("Strict"), fc.constant("Lax"), fc.constant("None"), fc.constant(undefined));
/** Generates a cookie attribute combination */
const cookieAttrsArb = fc.record({
    secure: fc.boolean(),
    httpOnly: fc.boolean(),
    sameSite: sameSiteArb,
});
/** Builds a raw Set-Cookie header string from parts */
function buildCookieHeader(name, value, attrs) {
    let header = `${name}=${value}`;
    if (attrs.httpOnly)
        header += "; HttpOnly";
    if (attrs.secure)
        header += "; Secure";
    if (attrs.sameSite !== undefined)
        header += `; SameSite=${attrs.sameSite}`;
    return header;
}
// ─── Property 3: Cookie finding completeness ─────────────────────────────────
describe("Property 3: Cookie finding completeness", () => {
    it("produces a finding for missing HttpOnly attribute", () => {
        fc.assert(fc.property(fc.webUrl({ withQueryParameters: false, withFragments: false }), cookieNameArb, cookieValueArb, cookieAttrsArb, (url, name, value, attrs) => {
            const header = buildCookieHeader(name, value, { ...attrs, httpOnly: false });
            const findings = inspectCookies(url, [header]);
            const hasHttpOnlyFinding = findings.some((f) => f.type === "insecure_cookie" &&
                f.description.includes(name) &&
                f.description.toLowerCase().includes("httponly"));
            return hasHttpOnlyFinding;
        }), { numRuns: 200 });
    });
    it("produces a finding for missing Secure attribute on HTTPS page", () => {
        fc.assert(fc.property(cookieNameArb, cookieValueArb, cookieAttrsArb, (name, value, attrs) => {
            const httpsUrl = `https://example.com/path`;
            const header = buildCookieHeader(name, value, { ...attrs, secure: false });
            const findings = inspectCookies(httpsUrl, [header]);
            const hasSecureFinding = findings.some((f) => f.type === "insecure_cookie" &&
                f.description.includes(name) &&
                f.description.toLowerCase().includes("secure"));
            return hasSecureFinding;
        }), { numRuns: 200 });
    });
    it("does NOT produce a Secure finding on HTTP pages", () => {
        fc.assert(fc.property(cookieNameArb, cookieValueArb, cookieAttrsArb, (name, value, attrs) => {
            const httpUrl = `http://example.com/path`;
            const header = buildCookieHeader(name, value, { ...attrs, secure: false });
            const findings = inspectCookies(httpUrl, [header]);
            // No finding should mention "secure" and "missing" in the context of HTTPS check
            const hasSecureCheckFinding = findings.some((f) => f.type === "insecure_cookie" &&
                f.description.toLowerCase().includes("https page") &&
                f.description.includes(name));
            return !hasSecureCheckFinding;
        }), { numRuns: 200 });
    });
    it("produces a high-severity finding for SameSite=None without Secure", () => {
        fc.assert(fc.property(fc.webUrl({ withQueryParameters: false, withFragments: false }), cookieNameArb, cookieValueArb, (url, name, value) => {
            // SameSite=None, no Secure
            const header = buildCookieHeader(name, value, {
                secure: false,
                httpOnly: true,
                sameSite: "None",
            });
            const findings = inspectCookies(url, [header]);
            const hasSameSiteNoneFinding = findings.some((f) => f.type === "insecure_cookie" &&
                f.severity === "high" &&
                f.details?.detectedSameSite === "None" &&
                f.details?.missingSameSite === "Secure");
            return hasSameSiteNoneFinding;
        }), { numRuns: 200 });
    });
    it("produces no SameSite=None finding when Secure is present", () => {
        fc.assert(fc.property(fc.webUrl({ withQueryParameters: false, withFragments: false }), cookieNameArb, cookieValueArb, (url, name, value) => {
            const header = buildCookieHeader(name, value, {
                secure: true,
                httpOnly: true,
                sameSite: "None",
            });
            const findings = inspectCookies(url, [header]);
            const hasSameSiteNoneFinding = findings.some((f) => f.severity === "high" && f.details?.detectedSameSite === "None");
            return !hasSameSiteNoneFinding;
        }), { numRuns: 200 });
    });
    it("produces zero findings for a fully-secured cookie on HTTPS", () => {
        fc.assert(fc.property(cookieNameArb, cookieValueArb, fc.oneof(fc.constant("Strict"), fc.constant("Lax")), (name, value, sameSite) => {
            const httpsUrl = "https://example.com/";
            const header = buildCookieHeader(name, value, {
                secure: true,
                httpOnly: true,
                sameSite,
            });
            const findings = inspectCookies(httpsUrl, [header]);
            return findings.length === 0;
        }), { numRuns: 200 });
    });
    it("each finding has a unique findingId (UUID-like) and required fields", () => {
        fc.assert(fc.property(fc.webUrl({ withQueryParameters: false, withFragments: false }), fc.array(fc.tuple(cookieNameArb, cookieValueArb, cookieAttrsArb).map(([n, v, a]) => buildCookieHeader(n, v, a)), { minLength: 1, maxLength: 5 }), (url, headers) => {
            const findings = inspectCookies(url, headers);
            const ids = findings.map((f) => f.findingId);
            const uniqueIds = new Set(ids);
            // All IDs must be unique
            if (ids.length !== uniqueIds.size)
                return false;
            // All findings must have required fields
            for (const f of findings) {
                if (!f.findingId)
                    return false;
                if (!f.type)
                    return false;
                if (!f.severity)
                    return false;
                if (!f.description)
                    return false;
                if (!f.affectedResource)
                    return false;
            }
            return true;
        }), { numRuns: 200 });
    });
    it("never throws for arbitrary cookie header inputs", () => {
        fc.assert(fc.property(fc.webUrl({ withQueryParameters: false, withFragments: false }), fc.array(fc.oneof(fc.string(), fc.constant(""), fc.constant(";; ;"))), (url, headers) => {
            let threw = false;
            try {
                inspectCookies(url, headers);
            }
            catch {
                threw = true;
            }
            return !threw;
        }), { numRuns: 300 });
    });
});
//# sourceMappingURL=cookies.property.test.js.map