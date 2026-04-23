/**
 * Unit tests for scanner/nvd-client.ts
 * Requirements: 5.1, 5.2, 5.3, 5.4, 5.5
 */
import { describe, it, expect, vi } from "vitest";
import { NvdClient, detectLibraries } from "../nvd-client.js";
function makeCache(initial) {
    const store = initial ?? new Map();
    return { get: (k) => store.get(k), set: (k, v) => { store.set(k, v); } };
}
function makeLibrary(overrides = {}) {
    return { name: "jquery", version: "3.6.0", sourceUrl: "https://cdn.example.com/jquery-3.6.0.min.js", ...overrides };
}
const MOCK_CVE_RESPONSE = {
    vulnerabilities: [
        { cve: { id: "CVE-2024-1234", descriptions: [{ lang: "en", value: "A critical XSS vulnerability" }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8 } }] } } },
        { cve: { id: "CVE-2023-5678", descriptions: [{ lang: "en", value: "A medium severity issue" }], metrics: { cvssMetricV31: [{ cvssData: { baseScore: 5.3 } }] } } },
    ],
};
function mockFetchOk(body = MOCK_CVE_RESPONSE) {
    return vi.fn().mockImplementation(async () => new Response(JSON.stringify(body), { status: 200 }));
}
describe("NvdClient.checkLibrary", () => {
    it("produces a finding for each CVE with all required fields", async () => {
        const findings = await new NvdClient(makeCache(), mockFetchOk()).checkLibrary(makeLibrary());
        expect(findings).toHaveLength(2);
        for (const f of findings) {
            expect(f.findingId).toBeTruthy();
            expect(f.type).toBe("cve");
            expect(f.severity).toBeTruthy();
            expect(f.description).toBeTruthy();
            expect(f.affectedResource).toBe("https://cdn.example.com/jquery-3.6.0.min.js");
            expect(typeof f.details.cveId).toBe("string");
            expect(typeof f.details.cvssScore).toBe("number");
            expect(typeof f.details.detailUrl).toBe("string");
        }
    });
    it("maps CVSS ≥ 9.0 to critical severity", async () => {
        const findings = await new NvdClient(makeCache(), mockFetchOk()).checkLibrary(makeLibrary());
        expect(findings.find((f) => f.details.cveId === "CVE-2024-1234")?.severity).toBe("critical");
    });
    it("maps CVSS 4.0–6.9 to medium severity", async () => {
        const findings = await new NvdClient(makeCache(), mockFetchOk()).checkLibrary(makeLibrary());
        expect(findings.find((f) => f.details.cveId === "CVE-2023-5678")?.severity).toBe("medium");
    });
    it("second call within 24h uses cache — fetch called only once", async () => {
        const fetchFn = mockFetchOk();
        const client = new NvdClient(makeCache(), fetchFn);
        await client.checkLibrary(makeLibrary());
        await client.checkLibrary(makeLibrary());
        expect(fetchFn).toHaveBeenCalledTimes(1);
    });
    it("expired cache triggers a new fetch", async () => {
        const fetchFn = mockFetchOk();
        const client = new NvdClient(makeCache(), fetchFn, 0);
        await client.checkLibrary(makeLibrary());
        await client.checkLibrary(makeLibrary());
        expect(fetchFn).toHaveBeenCalledTimes(2);
    });
    it("returns cached findings when fetch times out", async () => {
        const lib = makeLibrary();
        const cachedEntries = [{ cveId: "CVE-2022-9999", cvssScore: 7.5, description: "Cached", detailUrl: "https://nvd.nist.gov/vuln/detail/CVE-2022-9999" }];
        const store = new Map([[`${lib.name}@${lib.version}`, { entries: cachedEntries, timestamp: Date.now() - 60 * 60 * 1000 }]]);
        const timeoutFetch = vi.fn().mockRejectedValue(Object.assign(new Error("aborted"), { name: "AbortError" }));
        const findings = await new NvdClient(makeCache(store), timeoutFetch, 1).checkLibrary(lib);
        expect(findings).toHaveLength(1);
        expect(findings[0].details.cveId).toBe("CVE-2022-9999");
    });
    it("returns a note finding for null version and makes no API call", async () => {
        const fetchFn = mockFetchOk();
        const findings = await new NvdClient(makeCache(), fetchFn).checkLibrary(makeLibrary({ version: null }));
        expect(findings).toHaveLength(1);
        expect(findings[0].type).toBe("note");
        expect(findings[0].description).toContain("version-based CVE lookup was skipped");
        expect(fetchFn).not.toHaveBeenCalled();
    });
    it("returns a warning note when API times out and no cache", async () => {
        const timeoutFetch = vi.fn().mockRejectedValue(Object.assign(new Error("aborted"), { name: "AbortError" }));
        const findings = await new NvdClient(makeCache(), timeoutFetch).checkLibrary(makeLibrary());
        expect(findings).toHaveLength(1);
        expect(findings[0].type).toBe("note");
        expect(findings[0].description).toContain("NVD API unavailable");
    });
});
describe("detectLibraries", () => {
    it("detects jQuery from URL with version", () => {
        const libs = detectLibraries([{ sourceUrl: "https://cdn.example.com/jquery-3.6.0.min.js", content: "" }]);
        expect(libs[0]).toMatchObject({ name: "jquery", version: "3.6.0" });
    });
    it("detects jQuery version from content", () => {
        const libs = detectLibraries([{ sourceUrl: "https://cdn.example.com/jquery.min.js", content: "/*! jQuery v3.5.1 */" }]);
        expect(libs[0]).toMatchObject({ name: "jquery", version: "3.5.1" });
    });
    it("detects React, Vue, Angular, Bootstrap from URL", () => {
        const scripts = [
            { sourceUrl: "https://cdn.example.com/react-18.2.0.min.js", content: "" },
            { sourceUrl: "https://cdn.example.com/vue-3.3.0.min.js", content: "" },
            { sourceUrl: "https://cdn.example.com/angular-16.0.0.min.js", content: "" },
            { sourceUrl: "https://cdn.example.com/bootstrap-5.3.0.min.js", content: "" },
        ];
        const libs = detectLibraries(scripts);
        expect(libs.map((l) => l.name).sort()).toEqual(["angular", "bootstrap", "react", "vue"]);
    });
    it("returns null version when not extractable", () => {
        const libs = detectLibraries([{ sourceUrl: "https://cdn.example.com/jquery.js", content: "" }]);
        expect(libs[0].version).toBeNull();
    });
    it("deduplicates libraries by name", () => {
        const libs = detectLibraries([
            { sourceUrl: "https://cdn.example.com/jquery-3.6.0.min.js", content: "" },
            { sourceUrl: "https://cdn.example.com/jquery-3.5.0.min.js", content: "" },
        ]);
        expect(libs).toHaveLength(1);
    });
    it("returns empty array for unknown libraries", () => {
        expect(detectLibraries([{ sourceUrl: "https://cdn.example.com/app.bundle.js", content: "" }])).toHaveLength(0);
    });
});
//# sourceMappingURL=nvd-client.test.js.map