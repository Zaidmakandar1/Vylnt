/**
 * Cookie attribute security scanner.
 * Inspects Set-Cookie headers and produces Finding objects for insecure cookie configurations.
 */
import type { Finding } from "../types/index.js";
/**
 * Parse a raw Set-Cookie header value into a cookie name and its attributes.
 *
 * @param header - Raw Set-Cookie header string, e.g. "session=abc; Secure; HttpOnly; SameSite=Strict"
 * @returns An object with the cookie name and a map of attribute names to their values (or `true` for flag attributes).
 */
export declare function parseCookieHeader(header: string): {
    name: string;
    attributes: Record<string, string | boolean>;
};
/**
 * Inspect Set-Cookie headers for security attribute issues.
 *
 * @param url - The URL of the page that set the cookies (used to determine HTTPS context).
 * @param cookieHeaders - Array of raw Set-Cookie header values.
 * @returns An array of Finding objects (empty if no issues found or on error).
 */
export declare function inspectCookies(url: string, cookieHeaders: string[]): Finding[];
//# sourceMappingURL=cookies.d.ts.map