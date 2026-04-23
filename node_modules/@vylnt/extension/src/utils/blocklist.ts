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
export function matchesBlocklist(url: string, blocklist: string[]): boolean {
  for (const pattern of blocklist) {
    if (pattern === url) return true;
    // Convert glob pattern to regex: escape special chars, then replace \* with .*
    const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
    try {
      if (new RegExp(`^${escaped}$`).test(url)) return true;
    } catch {
      // Invalid pattern — skip
    }
  }
  return false;
}
