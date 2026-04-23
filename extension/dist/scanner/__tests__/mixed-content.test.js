/**
 * Unit tests for scanner/mixed-content.ts
 * Requirements: 3.1, 3.2, 3.3, 3.4
 */
import { describe, it, expect } from "vitest";
import { detectMixedContent } from "../mixed-content.js";
const emptySnapshot = {
    scripts: [], links: [], images: [], iframes: [], media: [], formActions: [],
};
const allHttpsSnapshot = {
    scripts: ["https://cdn.example.com/app.js"],
    links: ["https://cdn.example.com/style.css"],
    images: ["https://cdn.example.com/logo.png"],
    iframes: ["https://embed.example.com/widget"],
    media: ["https://cdn.example.com/video.mp4"],
    formActions: ["https://api.example.com/submit"],
};
describe("detectMixedContent", () => {
    it("returns zero findings when HTTPS page has all HTTPS resources", () => {
        expect(detectMixedContent("https://secure.example.com/", allHttpsSnapshot)).toHaveLength(0);
    });
    it("returns zero findings for empty snapshot on HTTPS page", () => {
        expect(detectMixedContent("https://secure.example.com/", emptySnapshot)).toHaveLength(0);
    });
    it("returns a high-severity mixed_content finding for HTTP script on HTTPS page", () => {
        const snapshot = { ...emptySnapshot, scripts: ["http://cdn.example.com/tracker.js"] };
        const findings = detectMixedContent("https://secure.example.com/", snapshot);
        expect(findings).toHaveLength(1);
        expect(findings[0].type).toBe("mixed_content");
        expect(findings[0].severity).toBe("high");
        expect(findings[0].affectedResource).toBe("http://cdn.example.com/tracker.js");
        expect(findings[0].details).toEqual({ resourceType: "script" });
    });
    it("returns a medium-severity finding for HTTP stylesheet on HTTPS page", () => {
        const snapshot = { ...emptySnapshot, links: ["http://cdn.example.com/style.css"] };
        const findings = detectMixedContent("https://secure.example.com/", snapshot);
        expect(findings).toHaveLength(1);
        expect(findings[0].severity).toBe("medium");
        expect(findings[0].details).toEqual({ resourceType: "stylesheet" });
    });
    it("returns a mixed_content finding for HTTP form action on HTTPS page", () => {
        const snapshot = { ...emptySnapshot, formActions: ["http://api.example.com/submit"] };
        const findings = detectMixedContent("https://secure.example.com/", snapshot);
        expect(findings).toHaveLength(1);
        expect(findings[0].type).toBe("mixed_content");
        expect(findings[0].details).toEqual({ resourceType: "form_action" });
    });
    it("returns one finding per HTTP resource", () => {
        const snapshot = {
            scripts: ["http://cdn.example.com/a.js", "https://cdn.example.com/b.js"],
            links: ["http://cdn.example.com/style.css"],
            images: ["http://cdn.example.com/img.png"],
            iframes: [], media: [], formActions: [],
        };
        const findings = detectMixedContent("https://secure.example.com/", snapshot);
        expect(findings).toHaveLength(3);
        expect(findings.every((f) => f.type === "mixed_content")).toBe(true);
    });
    it("returns a single note finding for HTTP page and skips mixed content checks", () => {
        const snapshot = { ...emptySnapshot, scripts: ["http://cdn.example.com/tracker.js"] };
        const findings = detectMixedContent("http://insecure.example.com/", snapshot);
        expect(findings).toHaveLength(1);
        expect(findings[0].type).toBe("note");
        expect(findings[0].severity).toBe("informational");
        expect(findings[0].description).toContain("not served over HTTPS");
    });
    it("returns a note finding even when snapshot is empty on HTTP page", () => {
        const findings = detectMixedContent("http://insecure.example.com/", emptySnapshot);
        expect(findings).toHaveLength(1);
        expect(findings[0].type).toBe("note");
    });
    it("returns empty array for null snapshot without throwing", () => {
        expect(() => {
            const result = detectMixedContent("https://secure.example.com/", null);
            expect(result).toEqual([]);
        }).not.toThrow();
    });
    it("returns empty array for undefined snapshot without throwing", () => {
        expect(() => {
            const result = detectMixedContent("https://secure.example.com/", undefined);
            expect(result).toEqual([]);
        }).not.toThrow();
    });
    it("returns note finding for null pageUrl without throwing", () => {
        expect(() => {
            const result = detectMixedContent(null, emptySnapshot);
            expect(result).toHaveLength(1);
            expect(result[0].type).toBe("note");
        }).not.toThrow();
    });
    it("assigns unique findingIds to all findings", () => {
        const snapshot = {
            scripts: ["http://cdn.example.com/a.js"],
            links: ["http://cdn.example.com/b.css"],
            images: ["http://cdn.example.com/c.png"],
            iframes: ["http://cdn.example.com/d"],
            media: ["http://cdn.example.com/e.mp4"],
            formActions: ["http://api.example.com/f"],
        };
        const findings = detectMixedContent("https://secure.example.com/", snapshot);
        const ids = findings.map((f) => f.findingId);
        expect(new Set(ids).size).toBe(ids.length);
    });
    it("correctly labels all resource types in details", () => {
        const snapshot = {
            scripts: ["http://cdn.example.com/a.js"],
            links: ["http://cdn.example.com/b.css"],
            images: ["http://cdn.example.com/c.png"],
            iframes: ["http://cdn.example.com/d"],
            media: ["http://cdn.example.com/e.mp4"],
            formActions: ["http://api.example.com/f"],
        };
        const findings = detectMixedContent("https://secure.example.com/", snapshot);
        const types = findings.map((f) => f.details.resourceType);
        expect(types).toContain("script");
        expect(types).toContain("stylesheet");
        expect(types).toContain("image");
        expect(types).toContain("iframe");
        expect(types).toContain("media");
        expect(types).toContain("form_action");
    });
});
//# sourceMappingURL=mixed-content.test.js.map