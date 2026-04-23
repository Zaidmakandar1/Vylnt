/**
 * DOM-level JavaScript pattern analyzer.
 * Inspects script content for dangerous patterns and produces Finding objects.
 * Requirements: 4.1, 4.2, 4.3, 4.4
 */

import type { Finding } from "../types/index.js";

/** Simple UUID v4 generator using the Web Crypto API. */
function uuidv4(): string {
  return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, (c) => {
    const n = parseInt(c, 10);
    return (n ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (n / 4)))).toString(16);
  });
}

// ─── Public types ─────────────────────────────────────────────────────────────

export interface ScriptInfo {
  /** Script src URL or "inline:<index>" for inline scripts */
  sourceUrl: string;
  /** Script text content */
  content: string;
}

// ─── Pattern definitions ──────────────────────────────────────────────────────

interface PatternDef {
  type: string;
  regex: RegExp;
}

const PATTERNS: PatternDef[] = [
  { type: "eval",              regex: /eval\(/g },
  { type: "innerHTML",         regex: /\.innerHTML\s*=/g },
  { type: "document.write",    regex: /document\.write\(/g },
  { type: "setTimeout_string", regex: /setTimeout\s*\(\s*['"`]/g },
  { type: "setInterval_string",regex: /setInterval\s*\(\s*['"`]/g },
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

interface PatternMatch {
  patternType: string;
  sourceUrl: string;
  lineNumber: number | undefined;
}

/** Find all pattern matches in a single script's content. */
function findMatches(script: ScriptInfo): PatternMatch[] {
  const matches: PatternMatch[] = [];
  const lines = script.content.split("\n");

  for (const { type, regex } of PATTERNS) {
    // Reset lastIndex since we reuse the regex with /g flag
    regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = regex.exec(script.content)) !== null) {
      // Compute 1-based line number from match index
      const before = script.content.slice(0, match.index);
      const lineNumber = before.split("\n").length;
      matches.push({ patternType: type, sourceUrl: script.sourceUrl, lineNumber });
    }
  }

  return matches;
}

function makeFinding(match: PatternMatch): Finding {
  return {
    findingId: uuidv4(),
    type: "dom_pattern",
    severity: "medium",
    description: `Dangerous DOM pattern detected: ${match.patternType} in ${match.sourceUrl}${match.lineNumber !== undefined ? ` at line ${match.lineNumber}` : ""}`,
    affectedResource: match.sourceUrl,
    details: {
      patternType: match.patternType,
      lineNumber: match.lineNumber,
    },
  };
}

function makeAggregatedFinding(patternType: string, count: number, sourceUrls: string[]): Finding {
  return {
    findingId: uuidv4(),
    type: "dom_pattern",
    severity: "medium",
    description: `Dangerous DOM pattern detected: ${patternType} — ${count} instances aggregated across page scripts`,
    affectedResource: sourceUrls[0] ?? "",
    details: {
      patternType,
      count,
      aggregated: true,
    },
  };
}

function makeCrossOriginNote(sourceUrl: string): Finding {
  return {
    findingId: uuidv4(),
    type: "note",
    severity: "informational",
    description: `Script analysis skipped for ${sourceUrl} due to cross-origin policy`,
    affectedResource: sourceUrl,
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

const AGGREGATION_THRESHOLD = 20;

export function analyzeDOMPatterns(pageUrl: string, scripts: ScriptInfo[]): Finding[] {
  try {
    if (!Array.isArray(scripts)) return [];

    const findings: Finding[] = [];

    // Collect cross-origin notes and gather all pattern matches
    const allMatches: PatternMatch[] = [];

    for (const script of scripts) {
      if (!script || typeof script !== "object") continue;

      const { sourceUrl, content } = script;

      // Cross-origin: external script with empty content
      if (typeof sourceUrl === "string" && sourceUrl.startsWith("http") && content === "") {
        findings.push(makeCrossOriginNote(sourceUrl));
        continue;
      }

      if (typeof content !== "string" || content.length === 0) continue;

      allMatches.push(...findMatches(script));
    }

    // Group matches by pattern type
    const byType = new Map<string, PatternMatch[]>();
    for (const match of allMatches) {
      const list = byType.get(match.patternType) ?? [];
      list.push(match);
      byType.set(match.patternType, list);
    }

    // Produce findings — aggregate if > 20 instances of same pattern type
    for (const [patternType, matches] of byType) {
      if (matches.length > AGGREGATION_THRESHOLD) {
        const sourceUrls = [...new Set(matches.map((m) => m.sourceUrl))];
        findings.push(makeAggregatedFinding(patternType, matches.length, sourceUrls));
      } else {
        for (const match of matches) {
          findings.push(makeFinding(match));
        }
      }
    }

    return findings;
  } catch (err) {
    console.error(`[DevGuard] Error analyzing DOM patterns for ${pageUrl}:`, err);
    return [];
  }
}
