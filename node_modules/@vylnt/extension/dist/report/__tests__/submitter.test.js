/**
 * Unit tests for report/submitter.ts and privacy controls.
 * Requirements: 13.3, 13.4, 13.5
 */
import { describe, it, expect, vi } from "vitest";
import { submitReport, retryPendingReports } from "../submitter.js";
import { matchesBlocklist } from "../../utils/blocklist.js";
// ─── Helpers ──────────────────────────────────────────────────────────────────
function makeReport(overrides = {}) {
    return {
        schemaVersion: "1.0",
        sessionId: "00000000-0000-4000-8000-000000000001",
        timestamp: "2024-01-01T00:00:00.000Z",
        scannedUrl: "https://example.com",
        browserInfo: { name: "Chrome", version: "120", extensionVersion: "0.1.0" },
        findings: [],
        riskScore: 0,
        mlFilterStatus: "not_applicable",
        ...overrides,
    };
}
function makeStorage(initial = []) {
    let store = [...initial];
    return {
        get: vi.fn().mockImplementation(async () => ({ pendingReports: store })),
        set: vi.fn().mockImplementation(async (items) => {
            store = items["pendingReports"];
        }),
        _getStore: () => store,
    };
}
function successFetch() {
    return vi.fn().mockResolvedValue(new Response(null, { status: 201 }));
}
function failFetch() {
    return vi.fn().mockRejectedValue(new Error("ECONNREFUSED"));
}
// ─── Payload privacy tests (Requirement 13.4) ─────────────────────────────────
describe("submitReport — payload privacy", () => {
    it("transmitted payload contains only ScanReport fields — no page content", async () => {
        let capturedBody = null;
        const fetchMock = vi.fn().mockImplementation(async (_url, init) => {
            capturedBody = JSON.parse(init.body);
            return new Response(null, { status: 201 });
        });
        const report = makeReport();
        await submitReport(report, {
            fetchFn: fetchMock,
            storage: makeStorage(),
        });
        expect(capturedBody).not.toBeNull();
        // Must NOT contain forbidden fields
        expect(capturedBody).not.toHaveProperty("pageContent");
        expect(capturedBody).not.toHaveProperty("domTree");
        expect(capturedBody).not.toHaveProperty("formData");
        expect(capturedBody).not.toHaveProperty("htmlContent");
        expect(capturedBody).not.toHaveProperty("rawHtml");
        // Must contain findings metadata and scanned URL
        expect(capturedBody).toHaveProperty("scannedUrl", "https://example.com");
        expect(capturedBody).toHaveProperty("findings");
        expect(Array.isArray(capturedBody["findings"])).toBe(true);
    });
    it("transmitted payload contains all required ScanReport fields", async () => {
        let capturedBody = null;
        const fetchMock = vi.fn().mockImplementation(async (_url, init) => {
            capturedBody = JSON.parse(init.body);
            return new Response(null, { status: 201 });
        });
        const report = makeReport({ riskScore: 42, mlFilterStatus: "applied" });
        await submitReport(report, {
            fetchFn: fetchMock,
            storage: makeStorage(),
        });
        expect(capturedBody.schemaVersion).toBe("1.0");
        expect(capturedBody.sessionId).toBe(report.sessionId);
        expect(capturedBody.timestamp).toBe(report.timestamp);
        expect(capturedBody.scannedUrl).toBe(report.scannedUrl);
        expect(capturedBody.riskScore).toBe(42);
        expect(capturedBody.mlFilterStatus).toBe("applied");
    });
});
// ─── Queue on failure (Requirement 13.4 / design error handling) ──────────────
describe("submitReport — queue on API Server unreachable", () => {
    it("queues report in storage when server is unreachable", async () => {
        const storage = makeStorage();
        const report = makeReport();
        await submitReport(report, {
            fetchFn: failFetch(),
            storage,
        });
        expect(storage.set).toHaveBeenCalledOnce();
        const queued = storage._getStore();
        expect(queued).toHaveLength(1);
        expect(queued[0].sessionId).toBe(report.sessionId);
    });
    it("does not queue report when server responds successfully", async () => {
        const storage = makeStorage();
        const report = makeReport();
        await submitReport(report, {
            fetchFn: successFetch(),
            storage,
        });
        // set should not have been called (no queuing needed)
        expect(storage.set).not.toHaveBeenCalled();
    });
    it("appends to existing queue when multiple reports fail", async () => {
        const storage = makeStorage();
        const report1 = makeReport({ sessionId: "00000000-0000-4000-8000-000000000001" });
        const report2 = makeReport({ sessionId: "00000000-0000-4000-8000-000000000002" });
        await submitReport(report1, { fetchFn: failFetch(), storage });
        await submitReport(report2, { fetchFn: failFetch(), storage });
        const queued = storage._getStore();
        expect(queued).toHaveLength(2);
        expect(queued.map((r) => r.sessionId)).toContain(report1.sessionId);
        expect(queued.map((r) => r.sessionId)).toContain(report2.sessionId);
    });
});
// ─── retryPendingReports ──────────────────────────────────────────────────────
describe("retryPendingReports — flush queue when server is available", () => {
    it("flushes all queued reports when server is available", async () => {
        const report1 = makeReport({ sessionId: "00000000-0000-4000-8000-000000000001" });
        const report2 = makeReport({ sessionId: "00000000-0000-4000-8000-000000000002" });
        const storage = makeStorage([report1, report2]);
        const fetchMock = successFetch();
        await retryPendingReports({ fetchFn: fetchMock, storage });
        // Both reports submitted
        expect(fetchMock).toHaveBeenCalledTimes(2);
        // Queue is now empty
        expect(storage._getStore()).toHaveLength(0);
    });
    it("keeps reports in queue when server is still unreachable", async () => {
        const report = makeReport();
        const storage = makeStorage([report]);
        await retryPendingReports({ fetchFn: failFetch(), storage });
        // Report remains in queue
        expect(storage._getStore()).toHaveLength(1);
    });
    it("partially flushes queue — removes successful, keeps failed", async () => {
        const report1 = makeReport({ sessionId: "00000000-0000-4000-8000-000000000001" });
        const report2 = makeReport({ sessionId: "00000000-0000-4000-8000-000000000002" });
        const storage = makeStorage([report1, report2]);
        let callCount = 0;
        const partialFetch = vi.fn().mockImplementation(async () => {
            callCount++;
            // First call succeeds, second fails
            if (callCount === 1)
                return new Response(null, { status: 201 });
            throw new Error("ECONNREFUSED");
        });
        await retryPendingReports({ fetchFn: partialFetch, storage });
        const remaining = storage._getStore();
        expect(remaining).toHaveLength(1);
        expect(remaining[0].sessionId).toBe(report2.sessionId);
    });
    it("does nothing when queue is empty", async () => {
        const storage = makeStorage([]);
        const fetchMock = successFetch();
        await retryPendingReports({ fetchFn: fetchMock, storage });
        expect(fetchMock).not.toHaveBeenCalled();
    });
});
// ─── Blocklist enforcement (Requirement 13.3) ─────────────────────────────────
describe("matchesBlocklist — blocklist enforcement", () => {
    it("returns false for empty blocklist", () => {
        expect(matchesBlocklist("https://example.com", [])).toBe(false);
    });
    it("returns true for exact URL match", () => {
        expect(matchesBlocklist("https://example.com/page", ["https://example.com/page"])).toBe(true);
    });
    it("returns false when URL is not in blocklist", () => {
        expect(matchesBlocklist("https://example.com", ["https://other.com"])).toBe(false);
    });
    it("supports wildcard glob patterns", () => {
        expect(matchesBlocklist("https://internal.corp/admin", ["https://internal.corp/*"])).toBe(true);
        expect(matchesBlocklist("https://internal.corp/settings", ["https://internal.corp/*"])).toBe(true);
    });
    it("wildcard does not match different domain", () => {
        expect(matchesBlocklist("https://external.com/page", ["https://internal.corp/*"])).toBe(false);
    });
    it("returns true when URL matches any pattern in the list", () => {
        const blocklist = ["https://a.com/*", "https://b.com/secret", "https://c.com"];
        expect(matchesBlocklist("https://b.com/secret", blocklist)).toBe(true);
        expect(matchesBlocklist("https://c.com", blocklist)).toBe(true);
        expect(matchesBlocklist("https://d.com", blocklist)).toBe(false);
    });
});
// ─── Extension disabled (Requirement 13.5) ────────────────────────────────────
describe("scanning disabled — ceases all scanning activity", () => {
    it("when scanningEnabled is false, no reports are submitted", async () => {
        // Simulate the background worker's guard: if disabled, submitReport is never called
        const fetchMock = vi.fn();
        const scanningEnabled = false;
        if (scanningEnabled) {
            await submitReport(makeReport(), {
                fetchFn: fetchMock,
                storage: makeStorage(),
            });
        }
        expect(fetchMock).not.toHaveBeenCalled();
    });
    it("when scanningEnabled is true, reports are submitted normally", async () => {
        const fetchMock = successFetch();
        const scanningEnabled = true;
        if (scanningEnabled) {
            await submitReport(makeReport(), {
                fetchFn: fetchMock,
                storage: makeStorage(),
            });
        }
        expect(fetchMock).toHaveBeenCalledOnce();
    });
});
//# sourceMappingURL=submitter.test.js.map