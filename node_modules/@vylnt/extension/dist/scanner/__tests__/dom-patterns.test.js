/**
 * Unit tests for scanner/dom-patterns.ts
 * Requirements: 4.1, 4.2, 4.3, 4.4
 */
import { describe, it, expect } from "vitest";
import { analyzeDOMPatterns } from "../dom-patterns.js";
describe("analyzeDOMPatterns", () => {
    it("returns zero findings when no dangerous patterns are present", () => {
        const scripts = [
            { sourceUrl: "https://example.com/app.js", content: "const x = 1; console.log(x);" },
        ];
        expect(analyzeDOMPatterns("https://example.com/", scripts)).toHaveLength(0);
    });
    it("returns one finding for a single eval() call", () => {
        const scripts = [
            { sourceUrl: "https://example.com/app.js", content: "eval('alert(1)');" },
        ];
        const findings = analyzeDOMPatterns("https://example.com/", scripts);
        expect(findings).toHaveLength(1);
        expect(findings[0].type).toBe("dom_pattern");
        expect(findings[0].details.patternType).toBe("eval");
        expect(findings[0].affectedResource).toBe("https://example.com/app.js");
        expect(findings[0].details.lineNumber).toBe(1);
    });
    it("returns one aggregated finding for 21 innerHTML assignments", () => {
        const line = "el.innerHTML = '<b>x</b>';\n";
        const content = line.repeat(21);
        const scripts = [
            { sourceUrl: "https://example.com/app.js", content },
        ];
        const findings = analyzeDOMPatterns("https://example.com/", scripts);
        expect(findings).toHaveLength(1);
        expect(findings[0].details.patternType).toBe("innerHTML");
        expect(findings[0].details.count).toBe(21);
        expect(findings[0].details.aggregated).toBe(true);
    });
    it("returns a note finding for a cross-origin script (empty content, http URL)", () => {
        const scripts = [
            { sourceUrl: "https://cdn.other.com/lib.js", content: "" },
        ];
        const findings = analyzeDOMPatterns("https://example.com/", scripts);
        expect(findings).toHaveLength(1);
        expect(findings[0].type).toBe("note");
        expect(findings[0].severity).toBe("informational");
        expect(findings[0].description).toContain("https://cdn.other.com/lib.js");
        expect(findings[0].description).toContain("cross-origin policy");
    });
    it("returns a finding for setTimeout with string argument", () => {
        const scripts = [
            { sourceUrl: "inline:0", content: "setTimeout('doSomething()', 1000);" },
        ];
        const findings = analyzeDOMPatterns("https://example.com/", scripts);
        expect(findings).toHaveLength(1);
        expect(findings[0].details.patternType).toBe("setTimeout_string");
    });
    it("returns a finding for setInterval with string argument", () => {
        const scripts = [
            { sourceUrl: "inline:0", content: 'setInterval("tick()", 500);' },
        ];
        const findings = analyzeDOMPatterns("https://example.com/", scripts);
        expect(findings).toHaveLength(1);
        expect(findings[0].details.patternType).toBe("setInterval_string");
    });
    it("returns a finding for document.write()", () => {
        const scripts = [
            { sourceUrl: "inline:0", content: "document.write('<p>hello</p>');" },
        ];
        const findings = analyzeDOMPatterns("https://example.com/", scripts);
        expect(findings).toHaveLength(1);
        expect(findings[0].details.patternType).toBe("document.write");
    });
    it("returns empty array for null input without throwing", () => {
        expect(() => {
            const result = analyzeDOMPatterns("https://example.com/", null);
            expect(result).toEqual([]);
        }).not.toThrow();
    });
    it("returns empty array for undefined input without throwing", () => {
        expect(() => {
            const result = analyzeDOMPatterns("https://example.com/", undefined);
            expect(result).toEqual([]);
        }).not.toThrow();
    });
    it("assigns unique findingIds to all findings", () => {
        const scripts = [
            { sourceUrl: "inline:0", content: "eval('a'); eval('b'); document.write('x');" },
        ];
        const findings = analyzeDOMPatterns("https://example.com/", scripts);
        const ids = findings.map((f) => f.findingId);
        expect(new Set(ids).size).toBe(ids.length);
    });
    it("does not aggregate when exactly 20 instances are present", () => {
        const line = "el.innerHTML = 'x';\n";
        const content = line.repeat(20);
        const scripts = [
            { sourceUrl: "inline:0", content },
        ];
        const findings = analyzeDOMPatterns("https://example.com/", scripts);
        // 20 instances → individual findings, not aggregated
        expect(findings).toHaveLength(20);
        expect(findings.every((f) => !f.details.aggregated)).toBe(true);
    });
    it("records correct line numbers for multi-line scripts", () => {
        const content = "const x = 1;\nconst y = 2;\neval('bad');";
        const scripts = [
            { sourceUrl: "inline:0", content },
        ];
        const findings = analyzeDOMPatterns("https://example.com/", scripts);
        expect(findings).toHaveLength(1);
        expect(findings[0].details.lineNumber).toBe(3);
    });
    it("handles multiple scripts and aggregates across all of them", () => {
        // 11 evals in script 1, 11 evals in script 2 → 22 total → aggregated
        const makeScript = (url) => ({
            sourceUrl: url,
            content: "eval('x');\n".repeat(11),
        });
        const scripts = [makeScript("inline:0"), makeScript("inline:1")];
        const findings = analyzeDOMPatterns("https://example.com/", scripts);
        expect(findings).toHaveLength(1);
        expect(findings[0].details.count).toBe(22);
    });
});
//# sourceMappingURL=dom-patterns.test.js.map