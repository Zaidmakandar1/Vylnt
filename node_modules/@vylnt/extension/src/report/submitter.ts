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

// ─── Configuration ────────────────────────────────────────────────────────────

export const DEFAULT_API_ENDPOINT = "http://localhost:3000/api/v1/reports";

const PENDING_REPORTS_KEY = "pendingReports";

// ─── Storage helpers (thin wrappers for testability) ─────────────────────────

export interface StorageAdapter {
  get(key: string): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

function defaultStorage(): StorageAdapter {
  return {
    get: (key) =>
      new Promise((resolve, reject) =>
        chrome.storage.local.get([key], (result) => {
          if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
          else resolve(result as Record<string, unknown>);
        })
      ),
    set: (items) =>
      new Promise((resolve, reject) =>
        chrome.storage.local.set(items, () => {
          if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
          else resolve();
        })
      ),
  };
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

async function getPendingReports(storage: StorageAdapter): Promise<ScanReport[]> {
  const result = await storage.get(PENDING_REPORTS_KEY);
  const pending = result[PENDING_REPORTS_KEY];
  return Array.isArray(pending) ? (pending as ScanReport[]) : [];
}

async function setPendingReports(
  reports: ScanReport[],
  storage: StorageAdapter
): Promise<void> {
  await storage.set({ [PENDING_REPORTS_KEY]: reports });
}

async function queueReport(report: ScanReport, storage: StorageAdapter): Promise<void> {
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
async function postReport(
  report: ScanReport,
  endpoint: string,
  fetchFn: typeof fetch
): Promise<boolean> {
  try {
    const response = await fetchFn(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      // The ScanReport type guarantees only findings metadata + scannedUrl are present.
      body: JSON.stringify(report),
    });
    return response.ok;
  } catch {
    // Network error — server unreachable
    return false;
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

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
export async function submitReport(
  report: ScanReport,
  options: SubmitOptions = {}
): Promise<void> {
  const {
    endpoint = DEFAULT_API_ENDPOINT,
    fetchFn = fetch,
    storage = defaultStorage(),
  } = options;

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
export async function retryPendingReports(options: SubmitOptions = {}): Promise<void> {
  const {
    endpoint = DEFAULT_API_ENDPOINT,
    fetchFn = fetch,
    storage = defaultStorage(),
  } = options;

  const pending = await getPendingReports(storage);
  if (pending.length === 0) return;

  const remaining: ScanReport[] = [];
  for (const report of pending) {
    const success = await postReport(report, endpoint, fetchFn);
    if (!success) {
      remaining.push(report);
    }
  }

  await setPendingReports(remaining, storage);
}
