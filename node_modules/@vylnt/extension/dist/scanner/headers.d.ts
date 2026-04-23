/**
 * HTTP response header security scanner.
 * Inspects security headers and produces Finding objects for missing or misconfigured headers.
 */
import type { Finding } from "../types/index.js";
/**
 * Inspect HTTP response headers for security issues.
 *
 * @param url - The URL of the response being inspected.
 * @param responseHeaders - The array of response headers from the webRequest API.
 * @returns An array of Finding objects (empty if no issues found or on error).
 */
export declare function inspectHeaders(url: string, responseHeaders: chrome.webRequest.HttpHeader[]): Finding[];
//# sourceMappingURL=headers.d.ts.map