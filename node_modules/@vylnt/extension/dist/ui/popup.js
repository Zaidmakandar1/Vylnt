/**
 * Vylnt DevGuard — Popup UI logic
 *
 * Handles:
 *  - Enable/disable scanning toggle (persisted to browser.storage.sync as `scanningEnabled`)
 *  - Allowlist management (persisted to browser.storage.sync as `allowlist`)
 *  - Blocklist management (persisted to browser.storage.sync as `blocklist`)
 *
 * Requirements: 13.1, 13.2, 13.5
 */
// ─── Storage keys ─────────────────────────────────────────────────────────────
export const STORAGE_KEY_SCANNING_ENABLED = "scanningEnabled";
export const STORAGE_KEY_ALLOWLIST = "allowlist";
export const STORAGE_KEY_BLOCKLIST = "blocklist";
function defaultSyncStorage() {
    return {
        get: (keys) => new Promise((resolve, reject) => chrome.storage.sync.get(keys, (result) => {
            if (chrome.runtime.lastError)
                reject(chrome.runtime.lastError);
            else
                resolve(result);
        })),
        set: (items) => new Promise((resolve, reject) => chrome.storage.sync.set(items, () => {
            if (chrome.runtime.lastError)
                reject(chrome.runtime.lastError);
            else
                resolve();
        })),
    };
}
function defaultRuntime() {
    return {
        sendMessage: (message) => {
            chrome.runtime.sendMessage(message, () => {
                // Background may not be listening yet — ignore
                void chrome.runtime.lastError;
            });
        },
    };
}
// ─── State helpers ────────────────────────────────────────────────────────────
export async function getScanningEnabled(storage) {
    const result = await storage.get([STORAGE_KEY_SCANNING_ENABLED]);
    const value = result[STORAGE_KEY_SCANNING_ENABLED];
    // Default to enabled if not set
    return value === undefined ? true : Boolean(value);
}
export async function setScanningEnabled(enabled, storage, runtime) {
    await storage.set({ [STORAGE_KEY_SCANNING_ENABLED]: enabled });
    runtime.sendMessage({ type: "SCANNING_STATE_CHANGED", enabled });
}
export async function getList(key, storage) {
    const result = await storage.get([key]);
    const value = result[key];
    return Array.isArray(value) ? value : [];
}
export async function addPattern(key, pattern, storage) {
    const list = await getList(key, storage);
    const trimmed = pattern.trim();
    if (!trimmed || list.includes(trimmed))
        return list;
    const updated = [...list, trimmed];
    await storage.set({ [key]: updated });
    return updated;
}
export async function removePattern(key, pattern, storage) {
    const list = await getList(key, storage);
    const updated = list.filter((p) => p !== pattern);
    await storage.set({ [key]: updated });
    return updated;
}
// ─── DOM rendering helpers ────────────────────────────────────────────────────
function renderList(ulElement, patterns, onRemove) {
    ulElement.innerHTML = "";
    for (const pattern of patterns) {
        const li = document.createElement("li");
        li.textContent = pattern;
        const removeBtn = document.createElement("button");
        removeBtn.textContent = "×";
        removeBtn.setAttribute("aria-label", `Remove ${pattern}`);
        removeBtn.addEventListener("click", () => onRemove(pattern));
        li.appendChild(removeBtn);
        ulElement.appendChild(li);
    }
}
// ─── Popup initialisation ─────────────────────────────────────────────────────
export async function initPopup(storage = defaultSyncStorage(), runtime = defaultRuntime()) {
    const summaryEl = document.getElementById("scan-summary");
    const findingsListEl = document.getElementById("findings-list");
    const renderFindings = (findings) => {
        if (!findingsListEl)
            return;
        findingsListEl.innerHTML = "";
        if (findings.length === 0) {
            const empty = document.createElement("li");
            empty.textContent = "No findings yet.";
            findingsListEl.appendChild(empty);
            return;
        }
        const recent = findings.slice(-5).reverse();
        for (const finding of recent) {
            const li = document.createElement("li");
            const title = document.createElement("div");
            title.className = "findings-title";
            const type = String(finding.type ?? "unknown");
            const severity = String(finding.severity ?? "unknown");
            title.textContent = `${severity.toUpperCase()} · ${type}`;
            const meta = document.createElement("div");
            meta.className = "findings-meta";
            const affectedResource = String(finding.affectedResource ?? "");
            meta.textContent = affectedResource;
            li.appendChild(title);
            if (affectedResource)
                li.appendChild(meta);
            findingsListEl.appendChild(li);
        }
    };
    const refreshSummary = () => {
        if (!summaryEl)
            return;
        chrome.storage.session.get(["findings"], (result) => {
            const safeResult = (result ?? {});
            const findings = Array.isArray(safeResult.findings)
                ? safeResult.findings
                : [];
            summaryEl.textContent = `Findings captured: ${findings.length}`;
            renderFindings(findings);
        });
    };
    refreshSummary();
    chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName === "session" && changes.findings) {
            refreshSummary();
        }
    });
    // ── Scanning toggle ──────────────────────────────────────────────────────
    const toggle = document.getElementById("scanning-toggle");
    const statusLabel = document.getElementById("scanning-status");
    const enabled = await getScanningEnabled(storage);
    toggle.checked = enabled;
    statusLabel.textContent = enabled ? "Scanning: On" : "Scanning: Off";
    toggle.addEventListener("change", async () => {
        const newEnabled = toggle.checked;
        statusLabel.textContent = newEnabled ? "Scanning: On" : "Scanning: Off";
        await setScanningEnabled(newEnabled, storage, runtime);
        refreshSummary();
    });
    // ── Allowlist ────────────────────────────────────────────────────────────
    const allowlistUl = document.getElementById("allowlist");
    const allowlistInput = document.getElementById("allowlist-input");
    const allowlistAddBtn = document.getElementById("allowlist-add");
    let allowlist = await getList(STORAGE_KEY_ALLOWLIST, storage);
    const refreshAllowlist = () => renderList(allowlistUl, allowlist, async (pattern) => {
        allowlist = await removePattern(STORAGE_KEY_ALLOWLIST, pattern, storage);
        refreshAllowlist();
    });
    refreshAllowlist();
    allowlistAddBtn.addEventListener("click", async () => {
        const pattern = allowlistInput.value.trim();
        if (!pattern)
            return;
        allowlist = await addPattern(STORAGE_KEY_ALLOWLIST, pattern, storage);
        allowlistInput.value = "";
        refreshAllowlist();
    });
    allowlistInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter")
            allowlistAddBtn.click();
    });
    // ── Blocklist ────────────────────────────────────────────────────────────
    const blocklistUl = document.getElementById("blocklist");
    const blocklistInput = document.getElementById("blocklist-input");
    const blocklistAddBtn = document.getElementById("blocklist-add");
    let blocklist = await getList(STORAGE_KEY_BLOCKLIST, storage);
    const refreshBlocklist = () => renderList(blocklistUl, blocklist, async (pattern) => {
        blocklist = await removePattern(STORAGE_KEY_BLOCKLIST, pattern, storage);
        refreshBlocklist();
    });
    refreshBlocklist();
    blocklistAddBtn.addEventListener("click", async () => {
        const pattern = blocklistInput.value.trim();
        if (!pattern)
            return;
        blocklist = await addPattern(STORAGE_KEY_BLOCKLIST, pattern, storage);
        blocklistInput.value = "";
        refreshBlocklist();
    });
    blocklistInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter")
            blocklistAddBtn.click();
    });
}
// ─── Auto-init when running in the browser ────────────────────────────────────
if (typeof document !== "undefined") {
    document.addEventListener("DOMContentLoaded", () => {
        initPopup().catch(console.error);
    });
}
//# sourceMappingURL=popup.js.map