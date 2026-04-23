/**
 * Property-based tests for scanner/cookies.ts
 *
 * Property 3: Cookie finding completeness
 *   For any cookie missing one or more of the Secure, HttpOnly, or SameSite attributes
 *   (or having SameSite=None without Secure), the scanner SHALL produce a finding
 *   containing the cookie name and the specific missing or misconfigured attribute(s).
 *
 * Feature: vylnt-devguard, Property 3: Cookie finding completeness
 * Validates: Requirements 2.1, 2.2, 2.3, 2.4
 */
export {};
//# sourceMappingURL=cookies.property.test.d.ts.map