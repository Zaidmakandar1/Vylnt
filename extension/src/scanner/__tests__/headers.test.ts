/**
 * Unit tests for scanner/headers.ts
 * Requirements: 1.1, 1.2, 1.3, 1.5
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { inspectHeaders } from "../headers.js";
import type { Finding } from "../../types/index.js";

// ─── Helpers ─────────────────────────────────────────────────────────────────

type Header = chrome.webRequest.HttpHeader;

function makeHeaders(map: Record<string, string>): Header[] {
  return Object.entries(map).map(([name, value]) => ({ name, value }));
}

const ALL_SECURE_HEADERS: Record<string, string> = {
  "content-security-policy": "default-src 'self'",
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-frame-options": "DENY",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
};

const TEST_URL = "https://example.com/";

// ─── Tests ───────────────────────────────────────────────────────────────────

describe("inspectHeaders", () => {
  describe("all five headers present and correctly configured", () => {
    it("returns zero findings", () => {
      const findings = inspectHeaders(TEST_URL, makeHeaders(ALL_SECURE_HEADERS));
      expect(findings).toHaveLength(0);
    });
  });

  describe("missing headers", () => {
    const requiredHeaders = [
      "content-security-policy",
      "strict-transport-security",
      "x-frame-options",
      "x-content-type-options",
      "referrer-policy",
    ];

    for (const missing of requiredHeaders) {
      it(`returns one finding when ${missing} is absent`, () => {
        const headers = { ...ALL_SECURE_HEADERS };
        delete headers[missing];
        const findings = inspectHeaders(TEST_URL, makeHeaders(headers));
        expect(findings).toHaveLength(1);
        const f = findings[0];
        expect(f.type).toBe("missing_header");
        expect(f.affectedResource).toBe(TEST_URL);
        expect(f.description).toContain(missing);
        expect(f.findingId).toBeTruthy();
      });
    }

    it("CSP missing → severity high", () => {
      const headers = { ...ALL_SECURE_HEADERS };
      delete headers["content-security-policy"];
      const [f] = inspectHeaders(TEST_URL, makeHeaders(headers));
      expect(f.severity).toBe("high");
    });

    it("HSTS missing → severity high", () => {
      const headers = { ...ALL_SECURE_HEADERS };
      delete headers["strict-transport-security"];
      const [f] = inspectHeaders(TEST_URL, makeHeaders(headers));
      expect(f.severity).toBe("high");
    });

    it("X-Frame-Options missing → severity medium", () => {
      const headers = { ...ALL_SECURE_HEADERS };
      delete headers["x-frame-options"];
      const [f] = inspectHeaders(TEST_URL, makeHeaders(headers));
      expect(f.severity).toBe("medium");
    });

    it("X-Content-Type-Options missing → severity medium", () => {
      const headers = { ...ALL_SECURE_HEADERS };
      delete headers["x-content-type-options"];
      const [f] = inspectHeaders(TEST_URL, makeHeaders(headers));
      expect(f.severity).toBe("medium");
    });

    it("Referrer-Policy missing → severity medium", () => {
      const headers = { ...ALL_SECURE_HEADERS };
      delete headers["referrer-policy"];
      const [f] = inspectHeaders(TEST_URL, makeHeaders(headers));
      expect(f.severity).toBe("medium");
    });

    it("all five headers absent → five findings", () => {
      const findings = inspectHeaders(TEST_URL, []);
      expect(findings).toHaveLength(5);
      const types = findings.map((f) => f.type);
      expect(types.every((t) => t === "missing_header")).toBe(true);
    });
  });

  describe("misconfigured headers", () => {
    it("HSTS with max-age=0 → misconfigured_header finding with detectedValue and expectedValue", () => {
      const headers = makeHeaders({
        ...ALL_SECURE_HEADERS,
        "strict-transport-security": "max-age=0",
      });
      const findings = inspectHeaders(TEST_URL, headers);
      expect(findings).toHaveLength(1);
      const f = findings[0];
      expect(f.type).toBe("misconfigured_header");
      expect(f.details).toBeDefined();
      expect(f.details!.detectedValue).toBe("max-age=0");
      expect(typeof f.details!.expectedValue).toBe("string");
    });

    it("X-Frame-Options with invalid value → misconfigured_header with detectedValue and expectedValue", () => {
      const headers = makeHeaders({
        ...ALL_SECURE_HEADERS,
        "x-frame-options": "ALLOWALL",
      });
      const findings = inspectHeaders(TEST_URL, headers);
      expect(findings).toHaveLength(1);
      const f = findings[0];
      expect(f.type).toBe("misconfigured_header");
      expect(f.details!.detectedValue).toBe("ALLOWALL");
      expect(f.details!.expectedValue).toContain("DENY");
    });

    it("X-Content-Type-Options with wrong value → misconfigured_header", () => {
      const headers = makeHeaders({
        ...ALL_SECURE_HEADERS,
        "x-content-type-options": "sniff",
      });
      const findings = inspectHeaders(TEST_URL, headers);
      expect(findings).toHaveLength(1);
      expect(findings[0].type).toBe("misconfigured_header");
      expect(findings[0].details!.detectedValue).toBe("sniff");
      expect(findings[0].details!.expectedValue).toBe("nosniff");
    });

    it("Referrer-Policy with invalid value → misconfigured_header", () => {
      const headers = makeHeaders({
        ...ALL_SECURE_HEADERS,
        "referrer-policy": "everything",
      });
      const findings = inspectHeaders(TEST_URL, headers);
      expect(findings).toHaveLength(1);
      expect(findings[0].type).toBe("misconfigured_header");
      expect(findings[0].details!.detectedValue).toBe("everything");
    });

    it("CSP with empty value → misconfigured_header", () => {
      const headers = makeHeaders({
        ...ALL_SECURE_HEADERS,
        "content-security-policy": "   ",
      });
      const findings = inspectHeaders(TEST_URL, headers);
      expect(findings).toHaveLength(1);
      expect(findings[0].type).toBe("misconfigured_header");
    });
  });

  describe("error handling", () => {
    beforeEach(() => {
      vi.spyOn(console, "error").mockImplementation(() => {});
    });

    it("returns findings for all missing headers when responseHeaders is null (treated as no headers)", () => {
      // @ts-expect-error intentional bad input
      const findings = inspectHeaders(TEST_URL, null);
      // null is not an array, so all 5 required headers are treated as missing
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBe(5);
      expect(findings.every((f) => f.type === "missing_header")).toBe(true);
    });

    it("returns findings for all missing headers when responseHeaders is undefined (treated as no headers)", () => {
      // @ts-expect-error intentional bad input
      const findings = inspectHeaders(TEST_URL, undefined);
      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBe(5);
      expect(findings.every((f) => f.type === "missing_header")).toBe(true);
    });

    it("logs error with URL when an exception occurs internally", () => {
      // Force an exception by passing a header array that throws during iteration
      const badHeaders = new Proxy([], {
        get(target, prop) {
          if (prop === "length") throw new Error("boom");
          return Reflect.get(target, prop);
        },
      }) as unknown as chrome.webRequest.HttpHeader[];

      const findings = inspectHeaders(TEST_URL, badHeaders);
      expect(findings).toEqual([]);
      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining(TEST_URL),
        expect.any(Error)
      );
    });

    it("skips headers with missing name gracefully", () => {
      const headers = [
        { name: undefined as unknown as string, value: "something" },
        { name: "x-content-type-options", value: "nosniff" },
        ...makeHeaders({
          "content-security-policy": "default-src 'self'",
          "strict-transport-security": "max-age=31536000",
          "x-frame-options": "DENY",
          "referrer-policy": "no-referrer",
        }),
      ];
      // Should not throw; x-content-type-options is present so no finding for it
      expect(() => inspectHeaders(TEST_URL, headers)).not.toThrow();
    });
  });

  describe("header name case-insensitivity", () => {
    it("recognises headers regardless of casing", () => {
      const headers = makeHeaders({
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Frame-Options": "SAMEORIGIN",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
      });
      const findings = inspectHeaders(TEST_URL, headers);
      expect(findings).toHaveLength(0);
    });
  });
});
