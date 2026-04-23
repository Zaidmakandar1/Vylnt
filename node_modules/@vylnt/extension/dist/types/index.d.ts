/**
 * Vylnt DevGuard — Shared TypeScript contracts
 * These interfaces mirror the ScanReport JSON Schema v1.
 */
export type FindingType = "missing_header" | "misconfigured_header" | "insecure_cookie" | "mixed_content" | "dom_pattern" | "cve" | "note";
export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export interface Finding {
    /** UUID v4 */
    findingId: string;
    type: FindingType;
    severity: Severity;
    description: string;
    affectedResource: string;
    /** Arbitrary extra data specific to the finding type */
    details?: Record<string, unknown>;
    /** ML classifier confidence score [0, 1] — present when ML filter was applied */
    mlConfidence?: number;
}
export type MLFilterStatus = "applied" | "unavailable" | "not_applicable";
export type BlockchainAnchorStatus = "anchored" | "pending" | "unanchored";
export interface BlockchainAnchor {
    status: BlockchainAnchorStatus;
    txHash?: string;
    blockNumber?: number;
    auditHash?: string;
}
export interface BrowserInfo {
    name: string;
    version: string;
    extensionVersion: string;
}
export interface ScanReport {
    /** Always "1.0" for this schema version */
    schemaVersion: "1.0";
    /** UUID v4 — unique per scan session */
    sessionId: string;
    /** ISO 8601 date-time string */
    timestamp: string;
    /** Fully-qualified URI of the scanned page */
    scannedUrl: string;
    browserInfo: BrowserInfo;
    findings: Finding[];
    /** Weighted risk score in the range [0, 100] */
    riskScore: number;
    mlFilterStatus: MLFilterStatus;
    /** Present once the report has been submitted to the blockchain anchor layer */
    blockchainAnchor?: BlockchainAnchor;
}
export type DOMPatternType = "eval" | "innerHTML" | "document.write" | "setTimeout_string" | "setInterval_string";
export interface MLFilterRequest {
    finding_id: string;
    pattern_type: DOMPatternType;
    /** Tokenized surrounding code context (±10 tokens around the pattern) */
    context_tokens: string[];
}
export interface MLFilterResponse {
    finding_id: string;
    classification: "safe" | "anomalous";
    /** Confidence score in the range [0, 1] */
    confidence: number;
}
//# sourceMappingURL=index.d.ts.map