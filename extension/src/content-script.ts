/**
 * Content script — injects a findings panel into the page.
 * Communicates with background to get current session findings.
 */

function createPanel(): HTMLDivElement {
  const panel = document.createElement("div");
  panel.id = "devguard-findings-panel";
  panel.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    width: 350px;
    max-height: 500px;
    background: #fff;
    border: 1px solid #e5e5e5;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    font-family: system-ui, -apple-system, sans-serif;
    font-size: 12px;
    z-index: 2147483647;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  `;

  const header = document.createElement("div");
  header.style.cssText = `
    background: #0f172a;
    color: #fff;
    padding: 10px 12px;
    font-weight: 600;
    display: flex;
    justify-content: space-between;
    align-items: center;
  `;
  header.innerHTML = `
    <span>Vylnt DevGuard</span>
    <button id="devguard-close" style="background:none;border:none;color:#fff;cursor:pointer;font-size:18px;">×</button>
  `;

  const content = document.createElement("div");
  content.id = "devguard-findings-content";
  content.style.cssText = `
    flex: 1;
    overflow-y: auto;
    padding: 8px;
  `;

  const emptyState = document.createElement("div");
  emptyState.style.cssText = "color:#9ca3af;padding:8px;text-align:center;";
  emptyState.textContent = "No findings yet.";
  content.appendChild(emptyState);

  panel.appendChild(header);
  panel.appendChild(content);

  document.body.appendChild(panel);

  document.getElementById("devguard-close")?.addEventListener("click", () => {
    panel.style.display = "none";
  });

  return panel;
}

function renderFindings(findings: import("./types/index.js").Finding[]): void {
  const content = document.getElementById("devguard-findings-content");
  if (!content) return;

  content.innerHTML = "";

  if (findings.length === 0) {
    const empty = document.createElement("div");
    empty.style.cssText = "color:#9ca3af;padding:8px;text-align:center;font-size:11px;";
    empty.textContent = "No findings yet.";
    content.appendChild(empty);
    return;
  }

  const recent = findings.slice(-10).reverse();
  for (const finding of recent) {
    const item = document.createElement("div");
    item.style.cssText = `
      padding: 8px;
      border-bottom: 1px solid #f3f4f6;
      font-size: 11px;
    `;

    const title = document.createElement("div");
    title.style.cssText = "font-weight:600;margin-bottom:2px;";
    const severity = finding.severity.toUpperCase();
    const type = finding.type.replace(/_/g, " ");
    title.textContent = `${severity} · ${type}`;
    title.style.color =
      finding.severity === "critical" ? "#dc2626" :
      finding.severity === "high" ? "#ea580c" :
      finding.severity === "medium" ? "#f59e0b" :
      "#6b7280";

    const meta = document.createElement("div");
    meta.style.cssText = "color:#6b7280;margin-top:2px;word-break:break-all;line-height:1.3;";
    meta.textContent = finding.affectedResource || finding.description.slice(0, 80);

    item.appendChild(title);
    item.appendChild(meta);
    content.appendChild(item);
  }
}

function init(): void {
  if (document.getElementById("devguard-findings-panel")) return;

  createPanel();

  chrome.storage.session.get(["findings"], (result) => {
    const findings = (result.findings as import("./types/index.js").Finding[]) || [];
    renderFindings(findings);
  });

  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === "session" && changes.findings) {
      const findings = (changes.findings.newValue as import("./types/index.js").Finding[]) || [];
      renderFindings(findings);
    }
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
