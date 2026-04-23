// Feature: vylnt-devguard, Property 11: Scan Report serialization round-trip
/**
 * Property-based tests for Scan Report JSON serialization round-trip.
 * Validates: Requirements 7.5
 */

import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import type { ScanReport, Finding, BrowserInfo, Severity, FindingType, MLFilterStatus } from "../../types/index.js";

// ─── Arbitraries ──────────────────────────────────────────────────────────────

const arbSeverity: fc.Arbitrary<Severity> = fc.constantFrom(
  "critical",
  "high",
  "medium",
  "low",
  "informational"
);

const arbFindingType: fc.Arbitrary<FindingType> = fc.constantFrom(
  "missing_header",
  "misconfigured_header",
  "insecure_cookie",
  "mixed_content",
  "dom_pattern",
  "cve",
  "note"
);

const arbFinding: fc.Arbitrary<Finding> = fc.record({
  findingId: fc.uuid(),
  type: arbFindingType,
  severity: arbSeverity,
  description: fc.string({ minLength: 1, maxLength: 200 }),
  affectedResource: fc.webUrl(),
  mlConfidence: fc.option(fc.float({ min: 0, max: 1, noNaN: true }), { nil: undefined }),
});

const arbBrowserInfo: fc.Arbitrary<BrowserInfo> = fc.record({
  name: fc.constantFrom("Chrome", "Firefox", "Edge"),
  version: fc.tuple(fc.integer({ min: 100, max: 130 }), fc.integer({ min: 0, max: 9 }))
    .map(([maj, min]) => `${maj}.${min}`),
  extensionVersion: fc.constantFrom("0.1.0", "0.2.0", "1.0.0"),
});

const arbMLFilterStatus: fc.Arbitrary<MLFilterStatus> = fc.constantFrom(
  "applied",
  "unavailable",
  "not_applicable"
);

const arbScanReport: fc.Arbitrary<ScanReport> = fc.record({
  schemaVersion: fc.constant("1.0" as const),
  sessionId: fc.uuid(),
  timestamp: fc.date({ min: new Date("2020-01-01"), max: new Date("2030-01-01") })
    .map((d) => d.toISOString()),
  scannedUrl: fc.webUrl(),
  browserInfo: arbBrowserInfo,
  findings: fc.array(arbFinding, { maxLength: 20 }),
  riskScore: fc.float({ min: 0, max: 100, noNaN: true }),
  mlFilterStatus: arbMLFilterStatus,
});

// ─── Property ─────────────────────────────────────────────────────────────────

describe("Property 11: Scan Report serialization round-trip", () => {
  it("JSON.parse(JSON.stringify(report)) deeply equals the original report", () => {
    fc.assert(
      fc.property(arbScanReport, (report) => {
        const serialized = JSON.stringify(report);
        const deserialized = JSON.parse(serialized) as ScanReport;
        expect(deserialized).toEqual(report);
      }),
      { numRuns: 200 }
    );
  });

  it("serialized report is valid JSON", () => {
    fc.assert(
      fc.property(arbScanReport, (report) => {
        expect(() => JSON.parse(JSON.stringify(report))).not.toThrow();
      }),
      { numRuns: 200 }
    );
  });
});
