/**
 * Blocklist URL pattern matching utility.
 * Extracted as a pure function so it can be tested without the chrome API.
 *
 * Requirements: 13.3
 */
/**
 * Returns true if `url` matches any pattern in `blocklist`.
 *
 * Patterns are matched as:
 *  - Exact string equality, OR
 *  - Glob-style wildcard where `*` matches any sequence of characters
 *    (converted to a regex for matching).
 */
export declare function matchesBlocklist(url: string, blocklist: string[]): boolean;
//# sourceMappingURL=blocklist.d.ts.map