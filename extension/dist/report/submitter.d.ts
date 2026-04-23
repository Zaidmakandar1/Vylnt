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
import type { ScanReport } from "../types/index.js";
export declare const DEFAULT_API_ENDPOINT = "http://localhost:3000/api/v1/reports";
export interface StorageAdapter {
    get(key: string): Promise<Record<string, unknown>>;
    set(items: Record<string, unknown>): Promise<void>;
}
export interface SubmitOptions {
    endpoint?: string;
    fetchFn?: typeof fetch;
    storage?: StorageAdapter;
}
/**
 * Submit a ScanReport to the API Server.
 * If the server is unreachable, the report is queued in browser.storage.local
 * under the key "pendingReports" for later retry via retryPendingReports().
 */
export declare function submitReport(report: ScanReport, options?: SubmitOptions): Promise<void>;
/**
 * Attempt to flush all queued (pending) reports to the API Server.
 * Reports that are successfully submitted are removed from the queue.
 * Reports that still fail remain in the queue for the next retry.
 */
export declare function retryPendingReports(options?: SubmitOptions): Promise<void>;
//# sourceMappingURL=submitter.d.ts.map