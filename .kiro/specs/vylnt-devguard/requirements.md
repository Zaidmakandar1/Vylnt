# Requirements Document

## Introduction

Vylnt (DevGuard) is a multi-layered developer security tool that passively scans web pages for vulnerabilities in real time via a browser extension, filters results through an ML model to reduce false positives, anchors scan reports to a blockchain for immutable auditability, and surfaces findings through a web dashboard with CI/CD integration. The system targets developers and security engineers who need continuous, automated security feedback during development and code review.

## Glossary

- **Extension**: The browser extension component built on WebExtensions API (Manifest V3), compatible with Chrome, Edge, and Firefox.
- **Scanner**: The passive scanning engine embedded in the Extension that inspects HTTP response headers, cookies, mixed content, and DOM-level JavaScript patterns.
- **NVD_Client**: The component responsible for querying the National Vulnerability Database (NVD) and CVE databases to identify outdated third-party scripts.
- **ML_Filter**: The LSTM-based machine learning model that classifies DOM manipulation patterns as safe or anomalous and suppresses false positives.
- **Dashboard**: The React.js web application that displays risk scores, vulnerability reports, and historical scan data.
- **API_Server**: The backend service (Node.js/Express or Python FastAPI) that receives scan results, stores them, and serves data to the Dashboard.
- **Blockchain_Anchor**: The smart contract and integration layer (Solidity + Web3.js/Ethers.js) that stores cryptographic hashes of scan reports on-chain for immutable audit trails.
- **CI_CD_Integration**: The GitHub Actions workflow that triggers scans on pull requests and enforces merge policies based on vulnerability severity.
- **Scan_Report**: A structured JSON document produced by the Scanner containing all findings for a given page scan session.
- **Risk_Score**: A numeric value (0–100) computed from the severity and count of vulnerabilities found in a Scan_Report.
- **Critical_Vulnerability**: A vulnerability with a CVSS score of 9.0 or higher, or a finding classified as critical severity by the ML_Filter.
- **Audit_Hash**: A SHA-256 cryptographic hash of a Scan_Report stored on-chain via the Blockchain_Anchor.

---

## Requirements

### Requirement 1: Real-Time Passive HTTP Header Scanning

**User Story:** As a developer, I want the browser extension to passively inspect HTTP response headers on every page load, so that I can identify missing or misconfigured security headers without interrupting my workflow.

#### Acceptance Criteria

1. WHEN a web page response is received by the browser, THE Scanner SHALL inspect the response headers for the presence and correct configuration of security headers including `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy`.
2. WHEN a required security header is absent from a response, THE Scanner SHALL record a finding with the header name, severity level, and the URL of the affected resource.
3. WHEN a security header is present but misconfigured, THE Scanner SHALL record a finding that includes the header name, the detected value, the expected value, and the severity level.
4. THE Scanner SHALL complete header inspection within 500ms of receiving the HTTP response.
5. IF the Scanner encounters an error while inspecting headers, THEN THE Scanner SHALL log the error with the affected URL and continue scanning subsequent requests without interruption.

---

### Requirement 2: Cookie Attribute Inspection

**User Story:** As a developer, I want the extension to check cookie security attributes on every page, so that I can detect insecure cookie configurations that could expose session data.

#### Acceptance Criteria

1. WHEN a web page sets one or more cookies, THE Scanner SHALL inspect each cookie for the presence of the `Secure`, `HttpOnly`, and `SameSite` attributes.
2. WHEN a cookie is missing the `Secure` attribute on an HTTPS page, THE Scanner SHALL record a finding with the cookie name and the missing attribute.
3. WHEN a cookie is missing the `HttpOnly` attribute, THE Scanner SHALL record a finding with the cookie name and the missing attribute.
4. WHEN a cookie has `SameSite` set to `None` without the `Secure` attribute, THE Scanner SHALL record a finding with the cookie name, the detected `SameSite` value, and the missing `Secure` attribute.
5. THE Scanner SHALL inspect all cookies set by a page within 200ms of the page load event completing.

---

### Requirement 3: Mixed Content Detection

**User Story:** As a developer, I want the extension to detect mixed content on HTTPS pages, so that I can identify resources loaded over HTTP that undermine transport security.

#### Acceptance Criteria

1. WHEN an HTTPS page loads a sub-resource (script, stylesheet, image, iframe, or media) over HTTP, THE Scanner SHALL record a finding with the resource URL, resource type, and severity level.
2. WHEN an HTTPS page contains a form with an `action` attribute pointing to an HTTP URL, THE Scanner SHALL record a finding with the form's action URL and severity level.
3. THE Scanner SHALL detect all mixed content resources present in the DOM within 1 second of the `DOMContentLoaded` event.
4. IF a page is loaded over HTTP, THEN THE Scanner SHALL skip mixed content checks for that page and record a note that the page is not served over HTTPS.

---

### Requirement 4: DOM-Level JavaScript Pattern Analysis

**User Story:** As a developer, I want the extension to analyze DOM manipulation patterns in JavaScript, so that I can detect potentially dangerous patterns such as `eval`, `innerHTML` assignments, and `document.write` usage.

#### Acceptance Criteria

1. WHEN a page's JavaScript executes DOM manipulation patterns classified as dangerous (including `eval()`, `innerHTML` assignment, `document.write()`, and `setTimeout`/`setInterval` with string arguments), THE Scanner SHALL record a finding with the pattern type, the script source URL or inline script identifier, and the line number where available.
2. THE Scanner SHALL analyze DOM-level JavaScript patterns on each page load without modifying or blocking the execution of any page scripts.
3. WHEN the Scanner detects more than 20 instances of the same dangerous pattern on a single page, THE Scanner SHALL aggregate them into a single finding with a count rather than recording individual findings.
4. IF the Scanner is unable to access a script's source due to cross-origin restrictions, THEN THE Scanner SHALL record a note indicating the script URL and that analysis was skipped due to cross-origin policy.

---

### Requirement 5: Third-Party Script Vulnerability Checking

**User Story:** As a developer, I want the extension to identify outdated third-party scripts with known CVEs, so that I can prioritize patching vulnerable dependencies loaded on pages I visit.

#### Acceptance Criteria

1. WHEN the Scanner detects a third-party JavaScript library loaded on a page, THE NVD_Client SHALL query the NVD/CVE database for known vulnerabilities associated with the detected library name and version.
2. WHEN the NVD_Client identifies one or more CVEs for a detected library version, THE Scanner SHALL record a finding with the library name, detected version, CVE identifiers, CVSS scores, and a link to the CVE detail page.
3. THE NVD_Client SHALL cache CVE query results locally for a minimum of 24 hours to reduce redundant API calls.
4. IF the NVD_Client cannot reach the NVD API within 5 seconds, THEN THE NVD_Client SHALL use the cached data if available and record a warning that live CVE data could not be retrieved.
5. IF no version information can be extracted from a detected third-party script, THEN THE Scanner SHALL record a note that the library was detected but version-based CVE lookup was skipped.

---

### Requirement 6: ML-Based False Positive Filtering

**User Story:** As a developer, I want an ML model to filter out false positive findings from DOM analysis, so that I only see actionable security issues rather than noise.

#### Acceptance Criteria

1. WHEN the Scanner produces DOM-level JavaScript findings, THE ML_Filter SHALL classify each finding as `safe` or `anomalous` using the LSTM sequence model before the finding is included in the Scan_Report.
2. WHEN the ML_Filter classifies a finding as `safe`, THE Scanner SHALL exclude that finding from the Scan_Report.
3. WHEN the ML_Filter classifies a finding as `anomalous`, THE Scanner SHALL include the finding in the Scan_Report with the ML_Filter's confidence score attached.
4. THE ML_Filter SHALL return a classification result within 300ms per finding.
5. IF the ML_Filter service is unavailable, THEN THE Scanner SHALL include all DOM-level findings in the Scan_Report unfiltered and attach a warning that ML filtering was not applied.
6. THE ML_Filter SHALL maintain a false positive rate below 10% as measured against a labeled validation dataset of at least 1,000 DOM manipulation samples.

---

### Requirement 7: Scan Report Generation

**User Story:** As a developer, I want each scan session to produce a structured JSON report, so that findings can be stored, transmitted, and audited consistently.

#### Acceptance Criteria

1. WHEN a page scan session completes, THE Scanner SHALL produce a Scan_Report as a valid JSON document containing: session ID, timestamp (ISO 8601), scanned URL, browser and extension version, list of findings (each with type, severity, description, and affected resource), Risk_Score, and ML_Filter status.
2. THE Scanner SHALL assign a unique session ID to each Scan_Report using a UUID v4.
3. THE Scanner SHALL compute the Risk_Score for each Scan_Report on a scale of 0–100 based on the count and CVSS-equivalent severity of all findings.
4. THE Scan_Report JSON Schema SHALL be versioned, and THE Scanner SHALL include the schema version in every Scan_Report.
5. FOR ALL valid Scan_Reports, serializing a Scan_Report to JSON and then deserializing it SHALL produce an equivalent Scan_Report object (round-trip property).

---

### Requirement 8: Blockchain Audit Anchoring

**User Story:** As a security engineer, I want scan reports to be cryptographically anchored to a blockchain, so that I have an immutable, tamper-evident audit trail of all security findings.

#### Acceptance Criteria

1. WHEN a Scan_Report is finalized, THE Blockchain_Anchor SHALL compute a SHA-256 hash of the canonical JSON representation of the Scan_Report.
2. WHEN the Audit_Hash is computed, THE Blockchain_Anchor SHALL submit a transaction to the configured blockchain network (Ganache local or Ethereum Sepolia/Polygon Mumbai testnet) storing the Audit_Hash, session ID, timestamp, and scanned URL.
3. WHEN the blockchain transaction is confirmed, THE Blockchain_Anchor SHALL record the transaction hash and block number in the Scan_Report metadata.
4. IF the blockchain network is unreachable, THEN THE Blockchain_Anchor SHALL queue the Audit_Hash locally and retry submission with exponential backoff at intervals of 30 seconds, 60 seconds, and 120 seconds before marking the report as unanchored.
5. THE Blockchain_Anchor SHALL verify that a stored Audit_Hash matches the hash of the original Scan_Report when a verification request is made.
6. WHEN a verification request is made for a Scan_Report, THE Blockchain_Anchor SHALL return a verification result indicating whether the on-chain hash matches the provided report within 10 seconds.

---

### Requirement 9: Web Dashboard — Vulnerability Reporting

**User Story:** As a developer, I want a web dashboard that displays my scan history and vulnerability findings, so that I can track security posture over time and prioritize remediation.

#### Acceptance Criteria

1. THE Dashboard SHALL display a list of all Scan_Reports for the authenticated user, sorted by timestamp in descending order.
2. WHEN a user selects a Scan_Report from the list, THE Dashboard SHALL display the full findings list, Risk_Score, scanned URL, timestamp, and blockchain anchor status for that report.
3. THE Dashboard SHALL render a Risk_Score trend chart showing Risk_Score over time for a selected URL or domain, using a minimum of the last 30 scan sessions.
4. THE Dashboard SHALL render a vulnerability breakdown chart showing the count of findings grouped by severity (critical, high, medium, low, informational).
5. WHEN a user filters the findings list by severity, THE Dashboard SHALL update the displayed findings within 200ms without a full page reload.
6. THE Dashboard SHALL be accessible over HTTPS and require authenticated sessions before displaying any scan data.

---

### Requirement 10: Web Dashboard — API Server

**User Story:** As a developer, I want a backend API to store and serve scan data, so that the dashboard and CI/CD integration have a reliable data source.

#### Acceptance Criteria

1. THE API_Server SHALL expose a REST endpoint to receive Scan_Reports submitted by the Extension, validate the JSON against the versioned Scan_Report schema, and persist valid reports to the data store.
2. WHEN the API_Server receives a Scan_Report with an invalid schema, THE API_Server SHALL return an HTTP 400 response with a descriptive error message identifying the validation failure.
3. THE API_Server SHALL expose a REST endpoint to retrieve paginated Scan_Reports for an authenticated user, returning results in JSON format.
4. THE API_Server SHALL authenticate all requests using JWT tokens and reject unauthenticated requests with an HTTP 401 response.
5. IF the data store is unavailable when a Scan_Report submission is received, THEN THE API_Server SHALL return an HTTP 503 response and log the error with the submitted report's session ID.
6. THE API_Server SHALL respond to all read endpoints within 500ms under a load of up to 100 concurrent requests.

---

### Requirement 11: CI/CD Integration — Automated Scanning on Pull Requests

**User Story:** As a developer, I want security scans to run automatically on pull requests in GitHub Actions, so that vulnerabilities are caught before code is merged.

#### Acceptance Criteria

1. WHEN a pull request is opened or updated in a configured GitHub repository, THE CI_CD_Integration SHALL trigger a security scan of the affected web application build.
2. WHEN the scan completes, THE CI_CD_Integration SHALL post a summary of findings as a comment on the pull request, including the Risk_Score, count of findings by severity, and a link to the full Scan_Report in the Dashboard.
3. WHEN the scan detects one or more Critical_Vulnerabilities, THE CI_CD_Integration SHALL set the GitHub check status to `failed` and block the pull request from merging.
4. WHEN the scan detects no Critical_Vulnerabilities, THE CI_CD_Integration SHALL set the GitHub check status to `passed` regardless of the presence of lower-severity findings.
5. THE CI_CD_Integration SHALL complete the scan and post results within 10 minutes of the pull request event being received.
6. IF the scan service is unreachable during a CI run, THEN THE CI_CD_Integration SHALL set the GitHub check status to `failed` with a message indicating the scan service was unavailable, rather than allowing the merge to proceed.

---

### Requirement 12: Extension Cross-Browser Compatibility

**User Story:** As a developer, I want the extension to work on Chrome, Edge, and Firefox, so that I can use it regardless of my preferred browser.

#### Acceptance Criteria

1. THE Extension SHALL function correctly on Google Chrome version 114 and later using Manifest V3.
2. THE Extension SHALL function correctly on Microsoft Edge version 114 and later using Manifest V3.
3. THE Extension SHALL function correctly on Mozilla Firefox version 109 and later using the WebExtensions API with Manifest V3 compatibility.
4. WHEN the Extension is installed on any supported browser, THE Extension SHALL activate scanning on all HTTP and HTTPS pages without requiring additional user configuration.
5. WHERE a browser does not support a specific WebExtensions API used by the Extension, THE Extension SHALL degrade gracefully by skipping the unsupported check and logging a compatibility note.

---

### Requirement 13: User Controls and Privacy

**User Story:** As a developer, I want control over which sites are scanned and what data is transmitted, so that I can protect sensitive internal URLs from being sent to external services.

#### Acceptance Criteria

1. THE Extension SHALL provide a user interface allowing the user to add URLs or domain patterns to an allowlist that restricts scanning to only those patterns.
2. THE Extension SHALL provide a user interface allowing the user to add URLs or domain patterns to a blocklist that prevents scanning of those patterns.
3. WHEN a page URL matches a blocklist pattern, THE Scanner SHALL skip all scanning for that page and not transmit any data about that page to the API_Server.
4. THE Extension SHALL not transmit the full page content, DOM tree, or any user-entered form data to the API_Server; only findings metadata and the scanned URL SHALL be transmitted.
5. WHEN the user disables the Extension from the browser toolbar, THE Scanner SHALL immediately cease all scanning activity and not resume until the user re-enables the Extension.
