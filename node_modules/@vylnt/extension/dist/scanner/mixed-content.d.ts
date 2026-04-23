/**
 * Mixed content detector.
 * Inspects a DOM snapshot for HTTP sub-resources on HTTPS pages and produces Finding objects.
 */
import type { Finding } from "../types/index.js";
export interface MixedContentDOMSnapshot {
    scripts: string[];
    links: string[];
    images: string[];
    iframes: string[];
    media: string[];
    formActions: string[];
}
/**
 * Capture a DOM snapshot from a live Document.
 */
export declare function snapshotDOM(document: Document): MixedContentDOMSnapshot;
export declare function detectMixedContent(pageUrl: string, domSnapshot: MixedContentDOMSnapshot): Finding[];
//# sourceMappingURL=mixed-content.d.ts.map