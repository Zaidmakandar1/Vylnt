/**
 * DOM-level JavaScript pattern analyzer.
 * Inspects script content for dangerous patterns and produces Finding objects.
 * Requirements: 4.1, 4.2, 4.3, 4.4
 */
import type { Finding } from "../types/index.js";
export interface ScriptInfo {
    /** Script src URL or "inline:<index>" for inline scripts */
    sourceUrl: string;
    /** Script text content */
    content: string;
}
export declare function analyzeDOMPatterns(pageUrl: string, scripts: ScriptInfo[]): Finding[];
//# sourceMappingURL=dom-patterns.d.ts.map