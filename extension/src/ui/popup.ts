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

// ─── Message types ────────────────────────────────────────────────────────────

export interface ScanningStateMessage {
  type: "SCANNING_STATE_CHANGED";
  enabled: boolean;
}

// ─── Storage adapter (injectable for tests) ──────────────────────────────────

export interface SyncStorageAdapter {
  get(keys: string[]): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
}

export interface RuntimeAdapter {
  sendMessage(message: ScanningStateMessage): void;
}

function defaultSyncStorage(): SyncStorageAdapter {
  return {
    get: (keys) =>
      new Promise((resolve, reject) =>
        chrome.storage.sync.get(keys, (result) => {
          if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
          else resolve(result as Record<string, unknown>);
        })
      ),
    set: (items) =>
      new Promise((resolve, reject) =>
        chrome.storage.sync.set(items, () => {
          if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
          else resolve();
        })
      ),
  };
}

function defaultRuntime(): RuntimeAdapter {
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

export async function getScanningEnabled(storage: SyncStorageAdapter): Promise<boolean> {
  const result = await storage.get([STORAGE_KEY_SCANNING_ENABLED]);
  const value = result[STORAGE_KEY_SCANNING_ENABLED];
  // Default to enabled if not set
  return value === undefined ? true : Boolean(value);
}

export async function setScanningEnabled(
  enabled: boolean,
  storage: SyncStorageAdapter,
  runtime: RuntimeAdapter
): Promise<void> {
  await storage.set({ [STORAGE_KEY_SCANNING_ENABLED]: enabled });
  runtime.sendMessage({ type: "SCANNING_STATE_CHANGED", enabled });
}

export async function getList(
  key: typeof STORAGE_KEY_ALLOWLIST | typeof STORAGE_KEY_BLOCKLIST,
  storage: SyncStorageAdapter
): Promise<string[]> {
  const result = await storage.get([key]);
  const value = result[key];
  return Array.isArray(value) ? (value as string[]) : [];
}

export async function addPattern(
  key: typeof STORAGE_KEY_ALLOWLIST | typeof STORAGE_KEY_BLOCKLIST,
  pattern: string,
  storage: SyncStorageAdapter
): Promise<string[]> {
  const list = await getList(key, storage);
  const trimmed = pattern.trim();
  if (!trimmed || list.includes(trimmed)) return list;
  const updated = [...list, trimmed];
  await storage.set({ [key]: updated });
  return updated;
}

export async function removePattern(
  key: typeof STORAGE_KEY_ALLOWLIST | typeof STORAGE_KEY_BLOCKLIST,
  pattern: string,
  storage: SyncStorageAdapter
): Promise<string[]> {
  const list = await getList(key, storage);
  const updated = list.filter((p) => p !== pattern);
  await storage.set({ [key]: updated });
  return updated;
}

// ─── DOM rendering helpers ────────────────────────────────────────────────────

function renderList(
  ulElement: HTMLUListElement,
  patterns: string[],
  onRemove: (pattern: string) => void
): void {
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

export async function initPopup(
  storage: SyncStorageAdapter = defaultSyncStorage(),
  runtime: RuntimeAdapter = defaultRuntime()
): Promise<void> {
  const summaryEl = document.getElementById("scan-summary") as HTMLParagraphElement | null;
  const findingsListEl = document.getElementById("findings-list") as HTMLUListElement | null;

  const renderFindings = (findings: Array<Record<string, unknown>>) => {
    if (!findingsListEl) return;
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
      if (affectedResource) li.appendChild(meta);
      findingsListEl.appendChild(li);
    }
  };

  const refreshSummary = () => {
    if (!summaryEl) return;
    chrome.storage.session.get(["findings"], (result) => {
      const safeResult = (result ?? {}) as Record<string, unknown>;
      const findings = Array.isArray(safeResult.findings)
        ? (safeResult.findings as Array<Record<string, unknown>>)
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
  const toggle = document.getElementById("scanning-toggle") as HTMLInputElement;
  const statusLabel = document.getElementById("scanning-status") as HTMLSpanElement;

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
  const allowlistUl = document.getElementById("allowlist") as HTMLUListElement;
  const allowlistInput = document.getElementById("allowlist-input") as HTMLInputElement;
  const allowlistAddBtn = document.getElementById("allowlist-add") as HTMLButtonElement;

  let allowlist = await getList(STORAGE_KEY_ALLOWLIST, storage);

  const refreshAllowlist = () =>
    renderList(allowlistUl, allowlist, async (pattern) => {
      allowlist = await removePattern(STORAGE_KEY_ALLOWLIST, pattern, storage);
      refreshAllowlist();
    });

  refreshAllowlist();

  allowlistAddBtn.addEventListener("click", async () => {
    const pattern = allowlistInput.value.trim();
    if (!pattern) return;
    allowlist = await addPattern(STORAGE_KEY_ALLOWLIST, pattern, storage);
    allowlistInput.value = "";
    refreshAllowlist();
  });

  allowlistInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") allowlistAddBtn.click();
  });

  // ── Blocklist ────────────────────────────────────────────────────────────
  const blocklistUl = document.getElementById("blocklist") as HTMLUListElement;
  const blocklistInput = document.getElementById("blocklist-input") as HTMLInputElement;
  const blocklistAddBtn = document.getElementById("blocklist-add") as HTMLButtonElement;

  let blocklist = await getList(STORAGE_KEY_BLOCKLIST, storage);

  const refreshBlocklist = () =>
    renderList(blocklistUl, blocklist, async (pattern) => {
      blocklist = await removePattern(STORAGE_KEY_BLOCKLIST, pattern, storage);
      refreshBlocklist();
    });

  refreshBlocklist();

  blocklistAddBtn.addEventListener("click", async () => {
    const pattern = blocklistInput.value.trim();
    if (!pattern) return;
    blocklist = await addPattern(STORAGE_KEY_BLOCKLIST, pattern, storage);
    blocklistInput.value = "";
    refreshBlocklist();
  });

  blocklistInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") blocklistAddBtn.click();
  });
}

// ─── Auto-init when running in the browser ────────────────────────────────────

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    initPopup().catch(console.error);
  });
}
