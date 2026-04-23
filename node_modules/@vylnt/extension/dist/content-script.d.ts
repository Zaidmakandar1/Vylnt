/**
 * Content script — injects a findings panel into the page.
 * Communicates with background to get current session findings.
 */
declare function createPanel(): HTMLDivElement;
declare function renderFindings(findings: import("./types/index.js").Finding[]): void;
declare function init(): void;
//# sourceMappingURL=content-script.d.ts.map