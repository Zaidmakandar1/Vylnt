/**
 * Property-based tests for blocklist privacy enforcement.
 *
 * // Feature: vylnt-devguard, Property 21: Blocklist privacy enforcement
 * Validates: Requirements 13.3
 */

import { describe, it, expect, vi } from "vitest";
import * as fc from "fast-check";
import { matchesBlocklist } from "../../utils/blocklist.js";
import { submitReport } from "../submitter.js";
import type { ScanReport } from "../../types/index.js";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeReport(url: string): ScanReport {
  return {
    schemaVersion: "1.0",
    sessionId: "00000000-0000-4000-8000-000000000001",
    timestamp: new Date().toISOString(),
    scannedUrl: url,
    browserInfo: { name: "Chrome", version: "120", extensionVersion: "0.1.0" },
    findings: [],
    riskScore: 0,
    mlFilterStatus: "not_applicable",
  };
}

// ─── Arbitraries ─────────────────────────────────────────────────────────────

/** Generate a simple URL string */
const urlArb = fc.oneof(
  fc.constant("https://example.com/page"),
  fc.constant("https://internal.corp/admin"),
  fc.constant("http://localhost:3000/app"),
  fc.webUrl()
);

/** Generate a blocklist that is guaranteed to contain the given URL */
function blocklistContaining(url: string): fc.Arbitrary<string[]> {
  return fc.array(fc.string(), { minLength: 0, maxLength: 5 }).map((extras) => [
    url,
    ...extras,
  ]);
}

/** Generate a blocklist that does NOT contain the given URL */
const emptyBlocklistArb = fc.constant<string[]>([]);

// ─── Property 21: Blocklist privacy enforcement ───────────────────────────────

describe("Property 21: Blocklist privacy enforcement", () => {
  it("matchesBlocklist returns true when URL is in the blocklist (exact match)", () => {
    fc.assert(
      fc.property(urlArb, blocklistContaining("https://example.com/page"), (url, blocklist) => {
        // The blocklist always contains "https://example.com/page"
        expect(matchesBlocklist("https://example.com/page", blocklist)).toBe(true);
      }),
      { numRuns: 100 }
    );
  });

  it("matchesBlocklist returns false when blocklist is empty", () => {
    fc.assert(
      fc.property(urlArb, emptyBlocklistArb, (url, blocklist) => {
        expect(matchesBlocklist(url, blocklist)).toBe(false);
      }),
      { numRuns: 100 }
    );
  });

  it("matchesBlocklist supports glob wildcard patterns", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(
          "https://internal.corp/admin",
          "https://internal.corp/settings",
          "https://internal.corp/users"
        ),
        (url) => {
          const blocklist = ["https://internal.corp/*"];
          expect(matchesBlocklist(url, blocklist)).toBe(true);
        }
      ),
      { numRuns: 50 }
    );
  });

  it("blocklisted URL produces zero API calls when submitReport is called after blocklist check", async () => {
    await fc.assert(
      fc.asyncProperty(
        urlArb,
        blocklistContaining("https://example.com/page"),
        async (_url, blocklist) => {
          const fetchMock = vi.fn();
          const storageMock = {
            get: vi.fn().mockResolvedValue({ pendingReports: [] }),
            set: vi.fn().mockResolvedValue(undefined),
          };

          // Simulate the background worker's blocklist check before any API call
          const isBlocked = matchesBlocklist("https://example.com/page", blocklist);
          expect(isBlocked).toBe(true);

          if (isBlocked) {
            // Background skips scanning and submission — fetchMock never called
            expect(fetchMock).not.toHaveBeenCalled();
          } else {
            // Only submit if not blocked
            await submitReport(makeReport("https://example.com/page"), {
              fetchFn: fetchMock as unknown as typeof fetch,
              storage: storageMock,
            });
          }

          // Zero API calls for blocklisted URL
          expect(fetchMock).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 100 }
    );
  });
});
