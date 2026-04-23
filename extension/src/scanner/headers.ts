/**
 * HTTP response header security scanner.
 * Inspects security headers and produces Finding objects for missing or misconfigured headers.
 */

import type { Finding, Severity } from "../types/index.js";

/** Simple UUID v4 generator using the Web Crypto API (available in MV3 service workers and modern browsers). */
function uuidv4(): string {
  return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, (c) => {
    const n = parseInt(c, 10);
    return (n ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (n / 4)))).toString(16);
  });
}

// ─── Header definitions ──────────────────────────────────────────────────────

interface HeaderRule {
  name: string;
  /** Severity when the header is entirely absent */
  missingSeverity: Severity;
  /** Validate the header value; returns null if valid, or an error description if misconfigured */
  validate?: (value: string) => { detectedValue: string; expectedValue: string } | null;
}

const HEADER_RULES: HeaderRule[] = [
  {
    name: "content-security-policy",
    missingSeverity: "high",
    validate: (value) => {
      // Must be non-empty and not just whitespace
      if (!value.trim()) {
        return {
          detectedValue: value,
          expectedValue: "A non-empty Content-Security-Policy directive (e.g. \"default-src 'self'\")",
        };
      }
      return null;
    },
  },
  {
    name: "strict-transport-security",
    missingSeverity: "high",
    validate: (value) => {
      // Must include max-age with a positive value
      const match = value.match(/max-age\s*=\s*(\d+)/i);
      if (!match || parseInt(match[1], 10) <= 0) {
        return {
          detectedValue: value,
          expectedValue: "Strict-Transport-Security: max-age=<positive integer> (e.g. max-age=31536000)",
        };
      }
      return null;
    },
  },
  {
    name: "x-frame-options",
    missingSeverity: "medium",
    validate: (value) => {
      const normalized = value.trim().toUpperCase();
      if (normalized !== "DENY" && normalized !== "SAMEORIGIN") {
        return {
          detectedValue: value,
          expectedValue: "DENY or SAMEORIGIN",
        };
      }
      return null;
    },
  },
  {
    name: "x-content-type-options",
    missingSeverity: "medium",
    validate: (value) => {
      if (value.trim().toLowerCase() !== "nosniff") {
        return {
          detectedValue: value,
          expectedValue: "nosniff",
        };
      }
      return null;
    },
  },
  {
    name: "referrer-policy",
    missingSeverity: "medium",
    validate: (value) => {
      const valid = [
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
      ];
      if (!valid.includes(value.trim().toLowerCase())) {
        return {
          detectedValue: value,
          expectedValue: `One of: ${valid.join(", ")}`,
        };
      }
      return null;
    },
  },
];

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Inspect HTTP response headers for security issues.
 *
 * @param url - The URL of the response being inspected.
 * @param responseHeaders - The array of response headers from the webRequest API.
 * @returns An array of Finding objects (empty if no issues found or on error).
 */
export function inspectHeaders(
  url: string,
  responseHeaders: chrome.webRequest.HttpHeader[]
): Finding[] {
  try {
    const findings: Finding[] = [];

    // Build a lowercase name → value map for quick lookup
    const headerMap = new Map<string, string>();
    if (Array.isArray(responseHeaders)) {
      for (const header of responseHeaders) {
        if (header && typeof header.name === "string") {
          const name = header.name.toLowerCase();
          const value = typeof header.value === "string" ? header.value : "";
          headerMap.set(name, value);
        }
      }
    }

    for (const rule of HEADER_RULES) {
      const value = headerMap.get(rule.name);

      if (value === undefined) {
        // Header is missing entirely
        findings.push({
          findingId: uuidv4(),
          type: "missing_header",
          severity: rule.missingSeverity,
          description: `Missing security header: ${rule.name}. This header is required to protect against common web vulnerabilities.`,
          affectedResource: url,
        });
      } else if (rule.validate) {
        const misconfiguration = rule.validate(value);
        if (misconfiguration) {
          findings.push({
            findingId: uuidv4(),
            type: "misconfigured_header",
            severity: rule.missingSeverity,
            description: `Misconfigured security header: ${rule.name}. The detected value does not meet security requirements.`,
            affectedResource: url,
            details: {
              detectedValue: misconfiguration.detectedValue,
              expectedValue: misconfiguration.expectedValue,
            },
          });
        }
      }
    }

    return findings;
  } catch (err) {
    console.error(`[DevGuard] Error inspecting headers for ${url}:`, err);
    return [];
  }
}
