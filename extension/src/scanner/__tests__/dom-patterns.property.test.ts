/**
 * Property-based tests for scanner/dom-patterns.ts
 *
 * Property 5: DOM pattern finding completeness
 * Property 6: DOM pattern aggregation
 *
 * Validates: Requirements 4.1, 4.3
 */

import { describe, it } from "vitest";
import * as fc from "fast-check";
import { analyzeDOMPatterns, type ScriptInfo } from "../dom-patterns.js";

// ─── Arbitraries ──────────────────────────────────────────────────────────────

/** Generates a snippet that contains exactly one instance of a dangerous pattern. */
const dangerousSnippets: Record<string, string> = {
  eval:               "eval('x');",
  innerHTML:          "el.innerHTML = 'y';",
  "document.write":   "document.write('z');",
  setTimeout_string:  "setTimeout('fn()', 100);",
  setInterval_string: "setInterval('fn()', 100);",
};

const patternTypeArb = fc.constantFrom(
  "eval",
  "innerHTML",
  "document.write",
  "setTimeout_string",
  "setInterval_string"
);

/** Generates a script with at least one dangerous pattern of the given type. */
const scriptWithPatternArb = (patternType: string): fc.Arbitrary<ScriptInfo> =>
  fc.record({
    sourceUrl: fc.constantFrom("inline:0", "https://example.com/app.js"),
    content: fc.constant(dangerousSnippets[patternType]),
  });

/** Generates a script with no dangerous patterns. */
const safeScriptArb: fc.Arbitrary<ScriptInfo> = fc.record({
  sourceUrl: fc.constantFrom("inline:0", "https://example.com/safe.js"),
  content: fc.constantFrom("const x = 1;", "function foo() { return 42; }", ""),
});

// ─── Property 5: DOM pattern finding completeness ─────────────────────────────

describe("Property 5: DOM pattern finding completeness", () => {
  it("produces at least one finding for each script containing a dangerous pattern", () => {
    fc.assert(
      fc.property(patternTypeArb, (patternType) => {
        const script = { sourceUrl: "inline:0", content: dangerousSnippets[patternType] };
        const findings = analyzeDOMPatterns("https://example.com/", [script]);
        return findings.some(
          (f) =>
            f.type === "dom_pattern" &&
            (f.details as Record<string, unknown>).patternType === patternType
        );
      }),
      { numRuns: 200 }
    );
  });

  it("produces no dom_pattern findings for scripts with no dangerous patterns", () => {
    fc.assert(
      fc.property(fc.array(safeScriptArb, { minLength: 0, maxLength: 5 }), (scripts) => {
        // Filter out empty-content scripts that would trigger cross-origin note
        const nonEmpty = scripts.filter((s) => s.content.length > 0);
        const findings = analyzeDOMPatterns("https://example.com/", nonEmpty);
        return findings.filter((f) => f.type === "dom_pattern").length === 0;
      }),
      { numRuns: 200 }
    );
  });

  it("never throws for arbitrary script arrays", () => {
    const scriptArb: fc.Arbitrary<ScriptInfo> = fc.record({
      sourceUrl: fc.oneof(
        fc.constantFrom("inline:0", "inline:1"),
        fc.webUrl()
      ),
      content: fc.string(),
    });
    fc.assert(
      fc.property(
        fc.oneof(
          fc.array(scriptArb, { minLength: 0, maxLength: 5 }),
          fc.constant(null as unknown as ScriptInfo[]),
          fc.constant(undefined as unknown as ScriptInfo[])
        ),
        (scripts) => {
          let threw = false;
          try {
            analyzeDOMPatterns("https://example.com/", scripts);
          } catch {
            threw = true;
          }
          return !threw;
        }
      ),
      { numRuns: 200 }
    );
  });
});

// ─── Property 6: DOM pattern aggregation ─────────────────────────────────────

describe("Property 6: DOM pattern aggregation", () => {
  it("produces exactly one aggregated finding when > 20 instances of the same pattern exist", () => {
    fc.assert(
      fc.property(
        patternTypeArb,
        fc.integer({ min: 21, max: 50 }),
        (patternType, count) => {
          const snippet = dangerousSnippets[patternType];
          const content = (snippet + "\n").repeat(count);
          const scripts: ScriptInfo[] = [{ sourceUrl: "inline:0", content }];
          const findings = analyzeDOMPatterns("https://example.com/", scripts);
          const patternFindings = findings.filter(
            (f) =>
              f.type === "dom_pattern" &&
              (f.details as Record<string, unknown>).patternType === patternType
          );
          if (patternFindings.length !== 1) return false;
          const details = patternFindings[0].details as Record<string, unknown>;
          return details.aggregated === true && details.count === count;
        }
      ),
      { numRuns: 200 }
    );
  });

  it("does NOT aggregate when there are exactly 20 or fewer instances", () => {
    fc.assert(
      fc.property(
        patternTypeArb,
        fc.integer({ min: 1, max: 20 }),
        (patternType, count) => {
          const snippet = dangerousSnippets[patternType];
          const content = (snippet + "\n").repeat(count);
          const scripts: ScriptInfo[] = [{ sourceUrl: "inline:0", content }];
          const findings = analyzeDOMPatterns("https://example.com/", scripts);
          const patternFindings = findings.filter(
            (f) =>
              f.type === "dom_pattern" &&
              (f.details as Record<string, unknown>).patternType === patternType
          );
          // Should have exactly `count` individual findings, none aggregated
          return (
            patternFindings.length === count &&
            patternFindings.every((f) => !(f.details as Record<string, unknown>).aggregated)
          );
        }
      ),
      { numRuns: 200 }
    );
  });

  it("aggregates across multiple scripts for the same pattern type", () => {
    fc.assert(
      fc.property(
        patternTypeArb,
        fc.integer({ min: 11, max: 25 }),
        fc.integer({ min: 11, max: 25 }),
        (patternType, count1, count2) => {
          const snippet = dangerousSnippets[patternType];
          const scripts: ScriptInfo[] = [
            { sourceUrl: "inline:0", content: (snippet + "\n").repeat(count1) },
            { sourceUrl: "inline:1", content: (snippet + "\n").repeat(count2) },
          ];
          const findings = analyzeDOMPatterns("https://example.com/", scripts);
          const patternFindings = findings.filter(
            (f) =>
              f.type === "dom_pattern" &&
              (f.details as Record<string, unknown>).patternType === patternType
          );
          const total = count1 + count2;
          if (total > 20) {
            // Must be exactly one aggregated finding with correct total count
            if (patternFindings.length !== 1) return false;
            const details = patternFindings[0].details as Record<string, unknown>;
            return details.aggregated === true && details.count === total;
          }
          // ≤ 20 total → individual findings
          return patternFindings.length === total;
        }
      ),
      { numRuns: 200 }
    );
  });
});
