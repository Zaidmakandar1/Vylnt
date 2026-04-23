import { describe, expect, it } from "vitest";
import type { Finding } from "../../types/index.js";
import { filterDeveloperOwnedFindings, isDeveloperOwnedResource } from "../resource-scope.js";

function makeFinding(affectedResource: string): Finding {
  return {
    findingId: "finding-1",
    type: "missing_header",
    severity: "medium",
    description: "test",
    affectedResource,
  };
}

describe("resource scope", () => {
  it("treats inline and same-host resources as developer-owned", () => {
    expect(isDeveloperOwnedResource("https://example.com/page", "inline:0")).toBe(true);
    expect(isDeveloperOwnedResource("https://example.com/page", "https://example.com/app.js")).toBe(true);
    expect(isDeveloperOwnedResource("https://example.com/page", "/assets/app.js")).toBe(true);
  });

  it("excludes third-party hosts", () => {
    expect(isDeveloperOwnedResource("https://example.com/page", "https://cdn.jsdelivr.net/lib.js")).toBe(false);
    expect(isDeveloperOwnedResource("https://example.com/page", "https://www.googletagmanager.com/gtag/js")).toBe(false);
  });

  it("filters findings to developer-owned resources", () => {
    const findings: Finding[] = [
      makeFinding("https://example.com/app.js"),
      makeFinding("https://cdn.example.net/lib.js"),
      makeFinding("inline:1"),
    ];

    const filtered = filterDeveloperOwnedFindings("https://example.com/page", findings);

    expect(filtered).toHaveLength(2);
    expect(filtered.map((finding) => finding.affectedResource)).toEqual([
      "https://example.com/app.js",
      "inline:1",
    ]);
  });
});