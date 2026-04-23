/**
 * Property-based tests for scanner/mixed-content.ts
 *
 * Property 4: Mixed content finding completeness
 * Feature: vylnt-devguard, Property 4: Mixed content finding completeness
 * Validates: Requirements 3.1, 3.2
 */

import { describe, it } from "vitest";
import * as fc from "fast-check";
import { detectMixedContent, type MixedContentDOMSnapshot } from "../mixed-content.js";

const httpUrlArb = fc
  .tuple(fc.stringMatching(/^[a-z0-9-]{3,10}$/), fc.stringMatching(/^[a-z0-9._-]{0,15}$/))
  .map(([host, path]) => `http://${host}.example.com/${path}`);

const httpsUrlArb = fc
  .tuple(fc.stringMatching(/^[a-z0-9-]{3,10}$/), fc.stringMatching(/^[a-z0-9._-]{0,15}$/))
  .map(([host, path]) => `https://${host}.example.com/${path}`);

const mixedUrlArb = fc.oneof(httpUrlArb, httpsUrlArb);

const domSnapshotArb = fc.record<MixedContentDOMSnapshot>({
  scripts: fc.array(mixedUrlArb, { minLength: 0, maxLength: 4 }),
  links: fc.array(mixedUrlArb, { minLength: 0, maxLength: 4 }),
  images: fc.array(mixedUrlArb, { minLength: 0, maxLength: 4 }),
  iframes: fc.array(mixedUrlArb, { minLength: 0, maxLength: 4 }),
  media: fc.array(mixedUrlArb, { minLength: 0, maxLength: 4 }),
  formActions: fc.array(mixedUrlArb, { minLength: 0, maxLength: 4 }),
});

describe("Property 4: Mixed content finding completeness", () => {
  it("produces a finding for every HTTP resource on an HTTPS page", () => {
    fc.assert(
      fc.property(domSnapshotArb, (snapshot) => {
        const findings = detectMixedContent("https://secure.example.com/", snapshot);
        const allHttpUrls = [
          ...snapshot.scripts, ...snapshot.links, ...snapshot.images,
          ...snapshot.iframes, ...snapshot.media, ...snapshot.formActions,
        ].filter((u) => u.toLowerCase().startsWith("http://"));

        for (const httpUrl of allHttpUrls) {
          if (!findings.some((f) => f.type === "mixed_content" && f.affectedResource === httpUrl)) return false;
        }
        return findings.filter((f) => f.type === "mixed_content").length === allHttpUrls.length;
      }),
      { numRuns: 200 }
    );
  });

  it("produces no mixed_content findings on HTTP pages", () => {
    fc.assert(
      fc.property(domSnapshotArb, (snapshot) => {
        const findings = detectMixedContent("http://insecure.example.com/", snapshot);
        return findings.filter((f) => f.type === "mixed_content").length === 0;
      }),
      { numRuns: 200 }
    );
  });

  it("produces exactly one note finding for HTTP pages", () => {
    fc.assert(
      fc.property(domSnapshotArb, (snapshot) => {
        const findings = detectMixedContent("http://insecure.example.com/", snapshot);
        const notes = findings.filter((f) => f.type === "note");
        return notes.length === 1 && notes[0].severity === "informational";
      }),
      { numRuns: 100 }
    );
  });

  it("assigns severity high to scripts and medium to all others", () => {
    fc.assert(
      fc.property(
        fc.array(httpUrlArb, { minLength: 1, maxLength: 3 }),
        fc.array(httpUrlArb, { minLength: 1, maxLength: 3 }),
        (scripts, links) => {
          const snapshot: MixedContentDOMSnapshot = {
            scripts, links, images: [], iframes: [], media: [], formActions: [],
          };
          const findings = detectMixedContent("https://secure.example.com/", snapshot);
          for (const f of findings) {
            if (f.type !== "mixed_content") continue;
            const rt = (f.details as { resourceType: string }).resourceType;
            if (rt === "script" && f.severity !== "high") return false;
            if (rt !== "script" && f.severity !== "medium") return false;
          }
          return true;
        }
      ),
      { numRuns: 100 }
    );
  });

  it("never throws for arbitrary snapshot inputs", () => {
    fc.assert(
      fc.property(
        fc.oneof(domSnapshotArb, fc.constant(null as unknown as MixedContentDOMSnapshot), fc.constant(undefined as unknown as MixedContentDOMSnapshot)),
        (snapshot) => {
          let threw = false;
          try { detectMixedContent("https://example.com/", snapshot); } catch { threw = true; }
          return !threw;
        }
      ),
      { numRuns: 200 }
    );
  });
});
