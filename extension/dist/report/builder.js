/**
 * Report builder — assembles findings from all scanners into a ScanReport.
 * Applies ML Filter classification to DOM pattern findings before inclusion.
 * Requirements: 6.1, 6.2, 6.3, 6.5, 7.1, 7.2, 7.3, 7.4
 */
// ─── UUID v4 ──────────────────────────────────────────────────────────────────
function uuidv4() {
    return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, (c) => {
        const n = parseInt(c, 10);
        return (n ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (n / 4)))).toString(16);
    });
}
// ─── Risk Score ───────────────────────────────────────────────────────────────
const SEVERITY_WEIGHTS = {
    critical: 40,
    high: 15,
    medium: 5,
    low: 2,
    informational: 0.5,
};
export function computeRiskScore(findings) {
    let raw = 0;
    for (const finding of findings) {
        raw += SEVERITY_WEIGHTS[finding.severity] ?? 0;
    }
    return Math.min(100, raw);
}
// ─── ML Filter ────────────────────────────────────────────────────────────────
const ML_FILTER_URL = "http://localhost:5000/classify";
const ML_FILTER_TIMEOUT_MS = 300;
/**
 * Classify a single DOM finding via the ML Filter microservice.
 * Returns null if the service is unavailable or times out.
 */
async function classifyFinding(finding, fetchFn) {
    const patternType = finding.details?.patternType ?? "eval";
    const request = {
        finding_id: finding.findingId,
        pattern_type: patternType,
        context_tokens: [],
    };
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), ML_FILTER_TIMEOUT_MS);
        try {
            const response = await fetchFn(ML_FILTER_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(request),
                signal: controller.signal,
            });
            if (!response.ok)
                return null;
            return (await response.json());
        }
        finally {
            clearTimeout(timeoutId);
        }
    }
    catch {
        return null;
    }
}
/**
 * Apply ML Filter to all DOM pattern findings.
 * Returns the filtered findings and the resulting mlFilterStatus.
 */
async function applyMLFilter(domFindings, fetchFn) {
    if (domFindings.length === 0) {
        return { filtered: [], mlFilterStatus: "not_applicable" };
    }
    const results = await Promise.all(domFindings.map((f) => classifyFinding(f, fetchFn)));
    // If any classification failed (null), ML filter is unavailable — include all unfiltered
    const anyUnavailable = results.some((r) => r === null);
    if (anyUnavailable) {
        return { filtered: domFindings, mlFilterStatus: "unavailable" };
    }
    const filtered = [];
    for (let i = 0; i < domFindings.length; i++) {
        const result = results[i];
        if (result.classification === "safe")
            continue;
        // anomalous — include with confidence score
        filtered.push({ ...domFindings[i], mlConfidence: result.confidence });
    }
    return { filtered, mlFilterStatus: "applied" };
}
export async function buildReport(options) {
    const { scannedUrl, browserInfo, nonDomFindings, domFindings, fetchFn = fetch, } = options;
    const { filtered: filteredDomFindings, mlFilterStatus } = await applyMLFilter(domFindings, fetchFn);
    const allFindings = [...nonDomFindings, ...filteredDomFindings];
    const riskScore = computeRiskScore(allFindings);
    return {
        schemaVersion: "1.0",
        sessionId: uuidv4(),
        timestamp: new Date().toISOString(),
        scannedUrl,
        browserInfo,
        findings: allFindings,
        riskScore,
        mlFilterStatus,
    };
}
//# sourceMappingURL=builder.js.map