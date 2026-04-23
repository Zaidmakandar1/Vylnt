/**
 * Unit tests for scanner/cookies.ts
 * Requirements: 2.1, 2.2, 2.3, 2.4, 2.5
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { inspectCookies, parseCookieHeader } from "../cookies.js";

const HTTPS_URL = "https://example.com/";
const HTTP_URL = "http://example.com/";

// ─── parseCookieHeader ────────────────────────────────────────────────────────

describe("parseCookieHeader", () => {
  it("parses name from a simple name=value cookie", () => {
    const result = parseCookieHeader("session=abc123");
    expect(result.name).toBe("session");
  });

  it("parses Secure flag attribute", () => {
    const result = parseCookieHeader("id=1; Secure");
    expect(result.attributes["secure"]).toBe(true);
  });

  it("parses HttpOnly flag attribute", () => {
    const result = parseCookieHeader("id=1; HttpOnly");
    expect(result.attributes["httponly"]).toBe(true);
  });

  it("parses SameSite value attribute", () => {
    const result = parseCookieHeader("id=1; SameSite=Strict");
    expect(result.attributes["samesite"]).toBe("Strict");
  });

  it("parses all attributes together", () => {
    const result = parseCookieHeader("session=xyz; Secure; HttpOnly; SameSite=Lax");
    expect(result.name).toBe("session");
    expect(result.attributes["secure"]).toBe(true);
    expect(result.attributes["httponly"]).toBe(true);
    expect(result.attributes["samesite"]).toBe("Lax");
  });

  it("handles attribute names case-insensitively", () => {
    const result = parseCookieHeader("tok=1; SECURE; HTTPONLY; SAMESITE=None");
    expect(result.attributes["secure"]).toBe(true);
    expect(result.attributes["httponly"]).toBe(true);
    expect(result.attributes["samesite"]).toBe("None");
  });
});

// ─── inspectCookies ───────────────────────────────────────────────────────────

describe("inspectCookies", () => {
  describe("fully-secured cookie → zero findings", () => {
    it("returns zero findings for a cookie with Secure, HttpOnly, SameSite=Strict on HTTPS", () => {
      const findings = inspectCookies(HTTPS_URL, [
        "session=abc; Secure; HttpOnly; SameSite=Strict",
      ]);
      expect(findings).toHaveLength(0);
    });

    it("returns zero findings for a cookie with Secure, HttpOnly, SameSite=Lax on HTTPS", () => {
      const findings = inspectCookies(HTTPS_URL, [
        "token=xyz; Secure; HttpOnly; SameSite=Lax",
      ]);
      expect(findings).toHaveLength(0);
    });
  });

  describe("missing Secure on HTTPS", () => {
    it("produces a finding when Secure is absent on HTTPS page", () => {
      const findings = inspectCookies(HTTPS_URL, ["session=abc; HttpOnly; SameSite=Strict"]);
      const secureFinding = findings.find(
        (f) => f.description.toLowerCase().includes("secure") && f.description.includes("session")
      );
      expect(secureFinding).toBeDefined();
      expect(secureFinding!.type).toBe("insecure_cookie");
      expect(secureFinding!.severity).toBe("medium");
    });

    it("finding description includes the cookie name", () => {
      const findings = inspectCookies(HTTPS_URL, ["myCookie=val; HttpOnly"]);
      const secureFinding = findings.find((f) => f.description.includes("myCookie"));
      expect(secureFinding).toBeDefined();
    });
  });

  describe("missing HttpOnly", () => {
    it("produces a finding when HttpOnly is absent", () => {
      const findings = inspectCookies(HTTPS_URL, ["session=abc; Secure; SameSite=Strict"]);
      const httpOnlyFinding = findings.find(
        (f) =>
          f.description.toLowerCase().includes("httponly") && f.description.includes("session")
      );
      expect(httpOnlyFinding).toBeDefined();
      expect(httpOnlyFinding!.type).toBe("insecure_cookie");
      expect(httpOnlyFinding!.severity).toBe("medium");
    });

    it("finding description includes the cookie name", () => {
      const findings = inspectCookies(HTTPS_URL, ["authToken=abc; Secure"]);
      const httpOnlyFinding = findings.find(
        (f) => f.description.toLowerCase().includes("httponly")
      );
      expect(httpOnlyFinding).toBeDefined();
      expect(httpOnlyFinding!.description).toContain("authToken");
    });
  });

  describe("SameSite=None without Secure", () => {
    it("produces a high-severity finding", () => {
      const findings = inspectCookies(HTTPS_URL, ["cross=abc; HttpOnly; SameSite=None"]);
      const sameSiteFinding = findings.find(
        (f) => f.severity === "high" && f.details?.detectedSameSite === "None"
      );
      expect(sameSiteFinding).toBeDefined();
      expect(sameSiteFinding!.type).toBe("insecure_cookie");
      expect(sameSiteFinding!.details?.missingSameSite).toBe("Secure");
    });

    it("does NOT produce a SameSite=None finding when Secure is present", () => {
      const findings = inspectCookies(HTTPS_URL, [
        "cross=abc; Secure; HttpOnly; SameSite=None",
      ]);
      const sameSiteFinding = findings.find(
        (f) => f.severity === "high" && f.details?.detectedSameSite === "None"
      );
      expect(sameSiteFinding).toBeUndefined();
    });
  });

  describe("HTTP page — Secure check skipped", () => {
    it("does not produce a Secure finding on HTTP page", () => {
      const findings = inspectCookies(HTTP_URL, ["session=abc; HttpOnly; SameSite=Strict"]);
      const secureFinding = findings.find(
        (f) =>
          f.description.toLowerCase().includes("https page") ||
          f.description.toLowerCase().includes("secure attribute on an https")
      );
      expect(secureFinding).toBeUndefined();
    });

    it("still produces HttpOnly finding on HTTP page", () => {
      const findings = inspectCookies(HTTP_URL, ["session=abc; SameSite=Strict"]);
      const httpOnlyFinding = findings.find((f) =>
        f.description.toLowerCase().includes("httponly")
      );
      expect(httpOnlyFinding).toBeDefined();
    });
  });

  describe("null/undefined/empty input → returns empty array without throwing", () => {
    beforeEach(() => {
      vi.spyOn(console, "error").mockImplementation(() => {});
    });

    it("returns empty array for null cookieHeaders", () => {
      // @ts-expect-error intentional bad input
      const findings = inspectCookies(HTTPS_URL, null);
      expect(Array.isArray(findings)).toBe(true);
      expect(findings).toHaveLength(0);
    });

    it("returns empty array for undefined cookieHeaders", () => {
      // @ts-expect-error intentional bad input
      const findings = inspectCookies(HTTPS_URL, undefined);
      expect(Array.isArray(findings)).toBe(true);
      expect(findings).toHaveLength(0);
    });

    it("returns empty array for empty array", () => {
      const findings = inspectCookies(HTTPS_URL, []);
      expect(findings).toHaveLength(0);
    });

    it("does not throw for empty string cookie header", () => {
      expect(() => inspectCookies(HTTPS_URL, [""])).not.toThrow();
    });
  });

  describe("finding structure", () => {
    it("each finding has a unique UUID v4 findingId", () => {
      const findings = inspectCookies(HTTPS_URL, [
        "a=1; SameSite=Strict",
        "b=2; SameSite=Strict",
      ]);
      const ids = findings.map((f) => f.findingId);
      const uniqueIds = new Set(ids);
      expect(ids.length).toBeGreaterThan(0);
      expect(uniqueIds.size).toBe(ids.length);
    });

    it("each finding has affectedResource set to the URL", () => {
      const findings = inspectCookies(HTTPS_URL, ["tok=1; SameSite=Strict"]);
      for (const f of findings) {
        expect(f.affectedResource).toBe(HTTPS_URL);
      }
    });

    it("each finding has type insecure_cookie", () => {
      const findings = inspectCookies(HTTPS_URL, ["tok=1"]);
      for (const f of findings) {
        expect(f.type).toBe("insecure_cookie");
      }
    });
  });

  describe("multiple cookies", () => {
    it("inspects all cookies in the array", () => {
      const findings = inspectCookies(HTTPS_URL, [
        "a=1; Secure; HttpOnly; SameSite=Strict",
        "b=2; SameSite=Strict", // missing Secure + HttpOnly
      ]);
      // Cookie "a" → 0 findings; cookie "b" → 2 findings (Secure + HttpOnly)
      expect(findings.length).toBeGreaterThanOrEqual(2);
      const cookieBFindings = findings.filter((f) => f.description.includes('"b"'));
      expect(cookieBFindings.length).toBeGreaterThanOrEqual(2);
    });
  });
});
