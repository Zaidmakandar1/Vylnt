/**
 * Report builder — assembles findings from all scanners into a ScanReport.
 * Applies ML Filter classification to DOM pattern findings before inclusion.
 * Requirements: 6.1, 6.2, 6.3, 6.5, 7.1, 7.2, 7.3, 7.4
 */
import type { Finding, ScanReport, BrowserInfo } from "../types/index.js";
export declare function computeRiskScore(findings: Finding[]): number;
export interface BuildReportOptions {
    scannedUrl: string;
    browserInfo: BrowserInfo;
    /** All findings from headers, cookies, mixed content, and CVE scanners (non-DOM) */
    nonDomFindings: Finding[];
    /** Findings from the DOM pattern scanner — will be sent through ML Filter */
    domFindings: Finding[];
    /** Override fetch for testing */
    fetchFn?: typeof fetch;
}
export declare function buildReport(options: BuildReportOptions): Promise<ScanReport>;
//# sourceMappingURL=builder.d.ts.map