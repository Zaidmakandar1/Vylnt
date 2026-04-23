/**
 * Mixed content detector.
 * Inspects a DOM snapshot for HTTP sub-resources on HTTPS pages and produces Finding objects.
 */

import type { Finding } from "../types/index.js";

/** Simple UUID v4 generator using the Web Crypto API. */
function uuidv4(): string {
  return "10000000-1000-4000-8000-100000000000".replace(/[018]/g, (c) => {
    const n = parseInt(c, 10);
    return (n ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (n / 4)))).toString(16);
  });
}

// ─── DOM Snapshot ─────────────────────────────────────────────────────────────

export interface MixedContentDOMSnapshot {
  scripts: string[];      // src attributes of <script> tags
  links: string[];        // href attributes of <link> tags
  images: string[];       // src attributes of <img> tags
  iframes: string[];      // src attributes of <iframe> tags
  media: string[];        // src attributes of <video>/<audio> tags
  formActions: string[];  // action attributes of <form> tags
}

/**
 * Capture a DOM snapshot from a live Document.
 */
export function snapshotDOM(document: Document): MixedContentDOMSnapshot {
  const attr = (el: Element, name: string): string => el.getAttribute(name) ?? "";

  return {
    scripts: Array.from(document.querySelectorAll("script[src]")).map((el) => attr(el, "src")).filter(Boolean),
    links: Array.from(document.querySelectorAll("link[href]")).map((el) => attr(el, "href")).filter(Boolean),
    images: Array.from(document.querySelectorAll("img[src]")).map((el) => attr(el, "src")).filter(Boolean),
    iframes: Array.from(document.querySelectorAll("iframe[src]")).map((el) => attr(el, "src")).filter(Boolean),
    media: Array.from(document.querySelectorAll("video[src], audio[src]")).map((el) => attr(el, "src")).filter(Boolean),
    formActions: Array.from(document.querySelectorAll("form[action]")).map((el) => attr(el, "action")).filter(Boolean),
  };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function isHttp(url: string): boolean {
  return typeof url === "string" && url.toLowerCase().startsWith("http://");
}

type ResourceType = "script" | "stylesheet" | "image" | "iframe" | "media" | "form_action";

function makeFinding(resourceUrl: string, resourceType: ResourceType): Finding {
  return {
    findingId: uuidv4(),
    type: "mixed_content",
    severity: resourceType === "script" ? "high" : "medium",
    description: `Mixed content: ${resourceType} loaded over HTTP on an HTTPS page. Resource URL: ${resourceUrl}`,
    affectedResource: resourceUrl,
    details: { resourceType },
  };
}

// ─── Public API ───────────────────────────────────────────────────────────────

export function detectMixedContent(
  pageUrl: string,
  domSnapshot: MixedContentDOMSnapshot
): Finding[] {
  try {
    if (typeof pageUrl !== "string" || !pageUrl.toLowerCase().startsWith("https://")) {
      return [{
        findingId: uuidv4(),
        type: "note",
        severity: "informational",
        description: "Page is not served over HTTPS; mixed content checks skipped.",
        affectedResource: typeof pageUrl === "string" ? pageUrl : "",
      }];
    }

    if (!domSnapshot || typeof domSnapshot !== "object") return [];

    const findings: Finding[] = [];
    const groups: Array<{ urls: string[]; type: ResourceType }> = [
      { urls: Array.isArray(domSnapshot.scripts) ? domSnapshot.scripts : [], type: "script" },
      { urls: Array.isArray(domSnapshot.links) ? domSnapshot.links : [], type: "stylesheet" },
      { urls: Array.isArray(domSnapshot.images) ? domSnapshot.images : [], type: "image" },
      { urls: Array.isArray(domSnapshot.iframes) ? domSnapshot.iframes : [], type: "iframe" },
      { urls: Array.isArray(domSnapshot.media) ? domSnapshot.media : [], type: "media" },
      { urls: Array.isArray(domSnapshot.formActions) ? domSnapshot.formActions : [], type: "form_action" },
    ];

    for (const { urls, type } of groups) {
      for (const url of urls) {
        if (isHttp(url)) findings.push(makeFinding(url, type));
      }
    }

    return findings;
  } catch (err) {
    console.error(`[DevGuard] Error detecting mixed content for ${pageUrl}:`, err);
    return [];
  }
}
