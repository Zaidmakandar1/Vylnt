/**
 * Side panel — persistent findings display that stays open on the right side of the browser.
 */
import { STORAGE_KEY_SCANNING_ENABLED, } from "./ui/popup.js";
function renderFindings(findings) {
    const list = document.getElementById("findings-list");
    const summary = document.getElementById("summary");
    if (!list)
        return;
    list.innerHTML = "";
    if (summary)
        summary.textContent = `Findings: ${findings.length}`;
    if (findings.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty";
        empty.textContent = "No findings yet. Browse pages to see security issues.";
        list.appendChild(empty);
        return;
    }
    const recent = findings.slice(-50).reverse();
    for (const finding of recent) {
        const li = document.createElement("li");
        const severityClass = finding.severity.toLowerCase();
        const severityDiv = document.createElement("div");
        severityDiv.className = `finding-severity ${severityClass}`;
        severityDiv.textContent = finding.severity.toUpperCase();
        const typeDiv = document.createElement("div");
        typeDiv.className = "finding-type";
        typeDiv.textContent = finding.type.replace(/_/g, " ");
        const resourceDiv = document.createElement("div");
        resourceDiv.className = "finding-resource";
        resourceDiv.textContent = finding.affectedResource || finding.description.slice(0, 100);
        li.appendChild(severityDiv);
        li.appendChild(typeDiv);
        li.appendChild(resourceDiv);
        list.appendChild(li);
    }
}
function init() {
    const toggle = document.getElementById("scanning-toggle");
    const toggleText = document.getElementById("toggle-text");
    chrome.storage.sync.get([STORAGE_KEY_SCANNING_ENABLED], (result) => {
        const enabled = result[STORAGE_KEY_SCANNING_ENABLED] === undefined
            ? true
            : Boolean(result[STORAGE_KEY_SCANNING_ENABLED]);
        if (toggle)
            toggle.checked = enabled;
        if (toggleText)
            toggleText.textContent = enabled ? "Scanning: On" : "Scanning: Off";
    });
    if (toggle) {
        toggle.addEventListener("change", () => {
            const newEnabled = toggle.checked;
            if (toggleText)
                toggleText.textContent = newEnabled ? "Scanning: On" : "Scanning: Off";
            chrome.storage.sync.set({ [STORAGE_KEY_SCANNING_ENABLED]: newEnabled });
            chrome.runtime.sendMessage({ type: "SCANNING_STATE_CHANGED", enabled: newEnabled }, () => {
                void chrome.runtime.lastError;
            });
        });
    }
    chrome.storage.session.get(["findings"], (result) => {
        const findings = result.findings || [];
        renderFindings(findings);
    });
    chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName === "session" && changes.findings) {
            const findings = changes.findings.newValue || [];
            renderFindings(findings);
        }
        else if (areaName === "sync" && changes[STORAGE_KEY_SCANNING_ENABLED]) {
            const enabled = Boolean(changes[STORAGE_KEY_SCANNING_ENABLED].newValue);
            if (toggleText)
                toggleText.textContent = enabled ? "Scanning: On" : "Scanning: Off";
            if (toggle)
                toggle.checked = enabled;
        }
    });
}
init();
//# sourceMappingURL=side-panel.js.map