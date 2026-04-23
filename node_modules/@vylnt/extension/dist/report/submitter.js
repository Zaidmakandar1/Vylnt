/**
 * Report submitter — POSTs ScanReport to the API Server.
 * On failure, queues the report in browser.storage.local for later retry.
 *
 * Privacy guarantee: only the ScanReport object is transmitted — it contains
 * only findings metadata and the scanned URL. No page content, DOM tree, or
 * form data is ever included (enforced by the ScanReport type itself).
 *
 * Requirements: 13.4
 */
// ─── Configuration ────────────────────────────────────────────────────────────
export const DEFAULT_API_ENDPOINT = "http://localhost:3000/api/v1/reports";
const PENDING_REPORTS_KEY = "pendingReports";
function defaultStorage() {
    return {
        get: (key) => new Promise((resolve, reject) => chrome.storage.local.get([key], (result) => {
            if (chrome.runtime.lastError)
                reject(chrome.runtime.lastError);
            else
                resolve(result);
        })),
        set: (items) => new Promise((resolve, reject) => chrome.storage.local.set(items, () => {
            if (chrome.runtime.lastError)
                reject(chrome.runtime.lastError);
            else
                resolve();
        })),
    };
}
// ─── Internal helpers ─────────────────────────────────────────────────────────
async function getPendingReports(storage) {
    const result = await storage.get(PENDING_REPORTS_KEY);
    const pending = result[PENDING_REPORTS_KEY];
    return Array.isArray(pending) ? pending : [];
}
async function setPendingReports(reports, storage) {
    await storage.set({ [PENDING_REPORTS_KEY]: reports });
}
async function queueReport(report, storage) {
    const pending = await getPendingReports(storage);
    pending.push(report);
    await setPendingReports(pending, storage);
}
/**
 * Attempt to POST a single ScanReport to the API Server.
 * Returns true on success, false if the server is unreachable or returns an error.
 *
 * Only the ScanReport JSON is transmitted — no page content, DOM tree, or form data.
 */
async function postReport(report, endpoint, fetchFn) {
    try {
        const response = await fetchFn(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            // The ScanReport type guarantees only findings metadata + scannedUrl are present.
            body: JSON.stringify(report),
        });
        return response.ok;
    }
    catch {
        // Network error — server unreachable
        return false;
    }
}
/**
 * Submit a ScanReport to the API Server.
 * If the server is unreachable, the report is queued in browser.storage.local
 * under the key "pendingReports" for later retry via retryPendingReports().
 */
export async function submitReport(report, options = {}) {
    const { endpoint = DEFAULT_API_ENDPOINT, fetchFn = fetch, storage = defaultStorage(), } = options;
    const success = await postReport(report, endpoint, fetchFn);
    if (!success) {
        await queueReport(report, storage);
    }
}
/**
 * Attempt to flush all queued (pending) reports to the API Server.
 * Reports that are successfully submitted are removed from the queue.
 * Reports that still fail remain in the queue for the next retry.
 */
export async function retryPendingReports(options = {}) {
    const { endpoint = DEFAULT_API_ENDPOINT, fetchFn = fetch, storage = defaultStorage(), } = options;
    const pending = await getPendingReports(storage);
    if (pending.length === 0)
        return;
    const remaining = [];
    for (const report of pending) {
        const success = await postReport(report, endpoint, fetchFn);
        if (!success) {
            remaining.push(report);
        }
    }
    await setPendingReports(remaining, storage);
}
//# sourceMappingURL=submitter.js.map