/**
 * Vylnt DevGuard — Background Service Worker (Manifest V3)
 *
 * Cross-browser note: Chrome exposes the `chrome` namespace. Firefox exposes
 * `browser` (Promise-based). This service worker uses `chrome` directly since
 * Manifest V3 service workers run in Chrome/Edge. For Firefox MV3 support,
 * include the webextension-polyfill package and replace `chrome` with `browser`.
 */
import { inspectHeaders } from "./scanner/headers.js";
import { inspectCookies } from "./scanner/cookies.js";
import { detectMixedContent } from "./scanner/mixed-content.js";
import { analyzeDOMPatterns } from "./scanner/dom-patterns.js";
import { NvdClient, detectLibraries } from "./scanner/nvd-client.js";
import { STORAGE_KEY_SCANNING_ENABLED, STORAGE_KEY_ALLOWLIST, STORAGE_KEY_BLOCKLIST, } from "./ui/popup.js";
import { matchesBlocklist } from "./utils/blocklist.js";
import { buildReport } from "./report/builder.js";
import { submitReport, retryPendingReports } from "./report/submitter.js";
import { filterDeveloperOwnedFindings } from "./utils/resource-scope.js";
// Re-export for consumers that import matchesBlocklist from background.ts
export { matchesBlocklist };
// ─── Privacy / blocklist helpers ─────────────────────────────────────────────
/**
 * In-memory cache of privacy settings to avoid async calls in the synchronous
 * webRequest listener. Updated whenever storage changes.
 */
let privacySettingsCache = {
    scanningEnabled: true,
    allowlist: [],
    blocklist: [],
};
const headerFindingsByTab = new Map();
const setCookieHeadersByTab = new Map();
const nvdCache = new Map();
const nvdClient = new NvdClient({
    get: (key) => nvdCache.get(key),
    set: (key, value) => {
        nvdCache.set(key, value);
    },
});
/**
 * Load privacy settings from storage into the in-memory cache.
 * Called at startup and when storage changes.
 */
function syncPrivacySettingsCache() {
    chrome.storage.sync.get([STORAGE_KEY_SCANNING_ENABLED, STORAGE_KEY_ALLOWLIST, STORAGE_KEY_BLOCKLIST], (result) => {
        if (chrome.runtime.lastError)
            return;
        const safeResult = (result ?? {});
        privacySettingsCache.scanningEnabled =
            safeResult[STORAGE_KEY_SCANNING_ENABLED] === undefined
                ? true
                : Boolean(safeResult[STORAGE_KEY_SCANNING_ENABLED]);
        privacySettingsCache.allowlist = Array.isArray(safeResult[STORAGE_KEY_ALLOWLIST])
            ? safeResult[STORAGE_KEY_ALLOWLIST]
            : [];
        privacySettingsCache.blocklist = Array.isArray(safeResult[STORAGE_KEY_BLOCKLIST])
            ? safeResult[STORAGE_KEY_BLOCKLIST]
            : [];
    });
}
// Initialize cache on startup
syncPrivacySettingsCache();
// ─── Message listener (from popup) ───────────────────────────────────────────
chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === "SCANNING_STATE_CHANGED") {
        // Sync the cache when settings change
        syncPrivacySettingsCache();
    }
});
// Listen for storage changes and sync cache
chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "sync") {
        if (changes[STORAGE_KEY_ALLOWLIST] ||
            changes[STORAGE_KEY_SCANNING_ENABLED] ||
            changes[STORAGE_KEY_BLOCKLIST]) {
            syncPrivacySettingsCache();
        }
    }
});
function matchesPatterns(url, patterns) {
    for (const pattern of patterns) {
        if (pattern === url)
            return true;
        const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
        try {
            if (new RegExp(`^${escaped}$`).test(url))
                return true;
        }
        catch {
            continue;
        }
    }
    return false;
}
function shouldScanUrl(url) {
    const { scanningEnabled, allowlist, blocklist } = privacySettingsCache;
    if (!scanningEnabled)
        return false;
    if (matchesBlocklist(url, blocklist))
        return false;
    if (allowlist.length > 0 && !matchesPatterns(url, allowlist))
        return false;
    return true;
}
function appendSessionFindings(newFindings) {
    if (newFindings.length === 0)
        return;
    chrome.storage.session.get(["findings"], (result) => {
        if (chrome.runtime.lastError)
            return;
        const safeResult = (result ?? {});
        const existing = Array.isArray(safeResult.findings)
            ? safeResult.findings
            : [];
        chrome.storage.session.set({ findings: [...existing, ...newFindings] }, () => {
            if (chrome.runtime.lastError)
                return;
        });
    });
}
function executePageScanScript(tabId) {
    return new Promise((resolve) => {
        chrome.scripting.executeScript({
            target: { tabId },
            func: () => {
                const byAttr = (selector, attr) => Array.from(document.querySelectorAll(selector))
                    .map((el) => (el.getAttribute(attr) ?? "").trim())
                    .filter(Boolean);
                const scripts = Array.from(document.scripts).map((script, index) => ({
                    sourceUrl: script.src || `inline:${index}`,
                    content: script.src ? "" : script.textContent ?? "",
                }));
                return {
                    pageUrl: location.href,
                    domSnapshot: {
                        scripts: byAttr("script[src]", "src"),
                        links: byAttr("link[href]", "href"),
                        images: byAttr("img[src]", "src"),
                        iframes: byAttr("iframe[src]", "src"),
                        media: byAttr("video[src], audio[src]", "src"),
                        formActions: byAttr("form[action]", "action"),
                    },
                    scripts,
                };
            },
        }, (results) => {
            if (chrome.runtime.lastError) {
                resolve(null);
                return;
            }
            resolve(results?.[0]?.result ?? null);
        });
    });
}
function detectBrowserName(userAgent) {
    if (/Edg\//.test(userAgent))
        return "Edge";
    if (/Firefox\//.test(userAgent))
        return "Firefox";
    if (/Chrome\//.test(userAgent))
        return "Chrome";
    return "Unknown";
}
async function runTabScan(tabId, tabUrl) {
    if (!shouldScanUrl(tabUrl)) {
        headerFindingsByTab.delete(tabId);
        setCookieHeadersByTab.delete(tabId);
        return;
    }
    const pageData = await executePageScanScript(tabId);
    if (!pageData)
        return;
    const headerFindings = headerFindingsByTab.get(tabId) ?? [];
    const setCookieHeaders = setCookieHeadersByTab.get(tabId) ?? [];
    const cookieFindings = inspectCookies(pageData.pageUrl, setCookieHeaders);
    const mixedContentFindings = detectMixedContent(pageData.pageUrl, pageData.domSnapshot);
    const domAnalysisFindings = analyzeDOMPatterns(pageData.pageUrl, pageData.scripts);
    const libraries = detectLibraries(pageData.scripts);
    const cveFindings = [];
    for (const library of libraries) {
        const findings = await nvdClient.checkLibrary(library);
        cveFindings.push(...findings);
    }
    const domFindings = domAnalysisFindings.filter((f) => f.type === "dom_pattern");
    const domNotes = domAnalysisFindings.filter((f) => f.type !== "dom_pattern");
    const nonDomFindings = [
        ...headerFindings,
        ...cookieFindings,
        ...mixedContentFindings,
        ...domNotes,
        ...cveFindings,
    ];
    const developerOwnedNonDomFindings = filterDeveloperOwnedFindings(tabUrl, nonDomFindings);
    const developerOwnedDomFindings = filterDeveloperOwnedFindings(tabUrl, domFindings);
    const report = await buildReport({
        scannedUrl: pageData.pageUrl,
        browserInfo: {
            name: detectBrowserName(navigator.userAgent),
            version: navigator.userAgent,
            extensionVersion: chrome.runtime.getManifest().version,
        },
        nonDomFindings: developerOwnedNonDomFindings,
        domFindings: developerOwnedDomFindings,
    });
    appendSessionFindings(report.findings);
    await submitReport(report);
    await retryPendingReports();
    headerFindingsByTab.delete(tabId);
    setCookieHeadersByTab.delete(tabId);
}
// ─── webRequest listener ─────────────────────────────────────────────────────
chrome.webRequest.onHeadersReceived.addListener((details) => {
    const { url, responseHeaders, tabId } = details;
    if (!url || !responseHeaders || tabId === undefined || tabId < 0)
        return;
    if (!shouldScanUrl(url))
        return;
    const findings = inspectHeaders(url, responseHeaders);
    const priorHeaderFindings = headerFindingsByTab.get(tabId) ?? [];
    headerFindingsByTab.set(tabId, [...priorHeaderFindings, ...findings]);
    const setCookieHeaders = responseHeaders
        .filter((header) => header.name.toLowerCase() === "set-cookie")
        .map((header) => header.value)
        .filter((value) => typeof value === "string");
    if (setCookieHeaders.length > 0) {
        const existing = setCookieHeadersByTab.get(tabId) ?? [];
        setCookieHeadersByTab.set(tabId, [...existing, ...setCookieHeaders]);
    }
}, { urls: ["<all_urls>"] }, ["responseHeaders"]);
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== "complete")
        return;
    if (!tab.url || !tab.url.startsWith("http"))
        return;
    void runTabScan(tabId, tab.url);
});
chrome.tabs.onRemoved.addListener((tabId) => {
    headerFindingsByTab.delete(tabId);
    setCookieHeadersByTab.delete(tabId);
});
chrome.action.onClicked.addListener(async (tab) => {
    if (tab.id === undefined)
        return;
    await chrome.sidePanel.open({ tabId: tab.id });
});
//# sourceMappingURL=background.js.map