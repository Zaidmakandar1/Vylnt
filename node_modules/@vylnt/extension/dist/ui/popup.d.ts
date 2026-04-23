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
export declare const STORAGE_KEY_SCANNING_ENABLED = "scanningEnabled";
export declare const STORAGE_KEY_ALLOWLIST = "allowlist";
export declare const STORAGE_KEY_BLOCKLIST = "blocklist";
export interface ScanningStateMessage {
    type: "SCANNING_STATE_CHANGED";
    enabled: boolean;
}
export interface SyncStorageAdapter {
    get(keys: string[]): Promise<Record<string, unknown>>;
    set(items: Record<string, unknown>): Promise<void>;
}
export interface RuntimeAdapter {
    sendMessage(message: ScanningStateMessage): void;
}
export declare function getScanningEnabled(storage: SyncStorageAdapter): Promise<boolean>;
export declare function setScanningEnabled(enabled: boolean, storage: SyncStorageAdapter, runtime: RuntimeAdapter): Promise<void>;
export declare function getList(key: typeof STORAGE_KEY_ALLOWLIST | typeof STORAGE_KEY_BLOCKLIST, storage: SyncStorageAdapter): Promise<string[]>;
export declare function addPattern(key: typeof STORAGE_KEY_ALLOWLIST | typeof STORAGE_KEY_BLOCKLIST, pattern: string, storage: SyncStorageAdapter): Promise<string[]>;
export declare function removePattern(key: typeof STORAGE_KEY_ALLOWLIST | typeof STORAGE_KEY_BLOCKLIST, pattern: string, storage: SyncStorageAdapter): Promise<string[]>;
export declare function initPopup(storage?: SyncStorageAdapter, runtime?: RuntimeAdapter): Promise<void>;
//# sourceMappingURL=popup.d.ts.map