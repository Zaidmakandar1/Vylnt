/**
 * Vylnt DevGuard — Background Service Worker (Manifest V3)
 *
 * Cross-browser note: Chrome exposes the `chrome` namespace. Firefox exposes
 * `browser` (Promise-based). This service worker uses `chrome` directly since
 * Manifest V3 service workers run in Chrome/Edge. For Firefox MV3 support,
 * include the webextension-polyfill package and replace `chrome` with `browser`.
 */
import { matchesBlocklist } from "./utils/blocklist.js";
export { matchesBlocklist };
//# sourceMappingURL=background.d.ts.map