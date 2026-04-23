/**
 * Cookie attribute security scanner.
 * Inspects Set-Cookie headers and produces Finding objects for insecure cookie configurations.
 */
/** Simple UUID v4 generator using the Web Crypto API (available in MV3 service workers and modern browsers). */
function uuidv4() {
    return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, (c) => {
        const n = parseInt(c, 10);
        return (n ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (n / 4)))).toString(16);
    });
}
// ─── Cookie parser ────────────────────────────────────────────────────────────
/**
 * Parse a raw Set-Cookie header value into a cookie name and its attributes.
 *
 * @param header - Raw Set-Cookie header string, e.g. "session=abc; Secure; HttpOnly; SameSite=Strict"
 * @returns An object with the cookie name and a map of attribute names to their values (or `true` for flag attributes).
 */
export function parseCookieHeader(header) {
    const parts = header.split(";").map((p) => p.trim());
    // First part is "name=value" (or just "name" for valueless cookies)
    const nameValuePart = parts[0] ?? "";
    const eqIndex = nameValuePart.indexOf("=");
    const name = eqIndex >= 0 ? nameValuePart.slice(0, eqIndex).trim() : nameValuePart.trim();
    const attributes = {};
    for (let i = 1; i < parts.length; i++) {
        const part = parts[i];
        if (!part)
            continue;
        const eqIdx = part.indexOf("=");
        if (eqIdx >= 0) {
            const attrName = part.slice(0, eqIdx).trim().toLowerCase();
            const attrValue = part.slice(eqIdx + 1).trim();
            attributes[attrName] = attrValue;
        }
        else {
            attributes[part.toLowerCase()] = true;
        }
    }
    return { name, attributes };
}
// ─── Public API ───────────────────────────────────────────────────────────────
/**
 * Inspect Set-Cookie headers for security attribute issues.
 *
 * @param url - The URL of the page that set the cookies (used to determine HTTPS context).
 * @param cookieHeaders - Array of raw Set-Cookie header values.
 * @returns An array of Finding objects (empty if no issues found or on error).
 */
export function inspectCookies(url, cookieHeaders) {
    try {
        const findings = [];
        const isHttps = typeof url === "string" && url.toLowerCase().startsWith("https://");
        if (!Array.isArray(cookieHeaders)) {
            return findings;
        }
        for (const header of cookieHeaders) {
            if (typeof header !== "string")
                continue;
            const { name, attributes } = parseCookieHeader(header);
            const hasSecure = attributes["secure"] === true;
            const hasHttpOnly = attributes["httponly"] === true;
            const sameSiteValue = typeof attributes["samesite"] === "string"
                ? attributes["samesite"].toLowerCase()
                : undefined;
            // Check: SameSite=None without Secure (highest priority — severity high)
            if (sameSiteValue === "none" && !hasSecure) {
                findings.push({
                    findingId: uuidv4(),
                    type: "insecure_cookie",
                    severity: "high",
                    description: `Cookie "${name}" has SameSite=None but is missing the Secure attribute. This allows the cookie to be sent over insecure connections in cross-site requests.`,
                    affectedResource: url,
                    details: {
                        detectedSameSite: "None",
                        missingSameSite: "Secure",
                    },
                });
            }
            // Check: Missing Secure on HTTPS page
            if (isHttps && !hasSecure) {
                findings.push({
                    findingId: uuidv4(),
                    type: "insecure_cookie",
                    severity: "medium",
                    description: `Cookie "${name}" is missing the Secure attribute on an HTTPS page. The cookie may be transmitted over insecure HTTP connections.`,
                    affectedResource: url,
                });
            }
            // Check: Missing HttpOnly
            if (!hasHttpOnly) {
                findings.push({
                    findingId: uuidv4(),
                    type: "insecure_cookie",
                    severity: "medium",
                    description: `Cookie "${name}" is missing the HttpOnly attribute. The cookie is accessible via JavaScript, which increases the risk of XSS-based session theft.`,
                    affectedResource: url,
                });
            }
        }
        return findings;
    }
    catch (err) {
        console.error(`[DevGuard] Error inspecting cookies for ${url}:`, err);
        return [];
    }
}
//# sourceMappingURL=cookies.js.map