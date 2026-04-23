# Implementation Plan: Vylnt (DevGuard)

## Overview

Incremental implementation across five loosely coupled layers. Each layer is built and wired independently, then integrated. Property-based tests are placed close to the implementation they validate to catch regressions early.

## Tasks

- [x] 1. Project scaffolding and shared contracts
  - Create monorepo directory structure: `extension/`, `ml-filter/`, `blockchain/`, `api-server/`, `dashboard/`, `cicd/`
  - Define and export the versioned `ScanReport` JSON Schema (`schemas/scan-report.v1.json`)
  - Define shared TypeScript interfaces: `ScanReport`, `Finding`, `MLFilterRequest`, `MLFilterResponse`
  - Set up testing frameworks: `fast-check` + `vitest` for TypeScript packages, `pytest` + `hypothesis` for Python, Foundry for Solidity
  - _Requirements: 7.4_

---

- [x] 2. Browser Extension — HTTP header scanner
  - [x] 2.1 Implement `scanner/headers.ts`
    - Intercept `webRequest.onHeadersReceived` events in `background.ts`
    - Check for presence and configuration of `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`
    - Produce `Finding` objects (type `missing_header` / `misconfigured_header`) with header name, severity, affected URL, detected value, expected value
    - Wrap all inspection logic in try/catch; log errors with URL and continue
    - _Requirements: 1.1, 1.2, 1.3, 1.5_

  - [ ]* 2.2 Write property test for header finding completeness (Property 1)
    - **Property 1: Header finding completeness**
    - **Validates: Requirements 1.1, 1.2, 1.3**
    - Use `fast-check` to generate arbitrary header maps; assert a finding exists for each missing/misconfigured header

  - [ ]* 2.3 Write property test for scanner error resilience (Property 2)
    - **Property 2: Scanner error resilience**
    - **Validates: Requirements 1.5**
    - Use `fast-check` to generate malformed/null header inputs; assert no unhandled exception is thrown and subsequent requests are processed

  - [ ]* 2.4 Write unit tests for header scanner
    - Test: all five headers present and correct → zero findings
    - Test: each header individually absent → one finding per missing header
    - Test: misconfigured header → finding includes detected and expected values
    - Test: error during inspection → error logged, scanning continues
    - _Requirements: 1.1, 1.2, 1.3, 1.5_

- [x] 3. Browser Extension — Cookie attribute inspector
  - [x] 3.1 Implement `scanner/cookies.ts`
    - Parse cookies from `document.cookie` and `Set-Cookie` response headers
    - Check for `Secure`, `HttpOnly`, `SameSite` attributes; flag `SameSite=None` without `Secure`
    - Produce `Finding` objects (type `insecure_cookie`) with cookie name and missing/misconfigured attribute(s)
    - Complete inspection within 200ms of page `load` event
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5_

  - [ ] 3.2 Write property test for cookie finding completeness (Property 3)
    - **Property 3: Cookie finding completeness**
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.4**
    - Use `fast-check` to generate arbitrary cookie attribute combinations; assert a finding is produced for each missing/misconfigured attribute

  - [ ]* 3.3 Write unit tests for cookie inspector
    - Test: cookie with all attributes → zero findings
    - Test: missing `Secure` on HTTPS → finding produced
    - Test: missing `HttpOnly` → finding produced
    - Test: `SameSite=None` without `Secure` → finding produced
    - _Requirements: 2.1–2.4_

- [x] 4. Browser Extension — Mixed content detector
  - [x] 4.1 Implement `scanner/mixed-content.ts` (content script)
    - Traverse DOM after `DOMContentLoaded` to find HTTP sub-resources: `<script src>`, `<link href>`, `<img src>`, `<iframe src>`, `<video>/<audio> src`, `<form action>`
    - Produce `Finding` objects (type `mixed_content`) with resource URL, resource type, severity
    - Skip check and record a note if page is loaded over HTTP
    - Complete detection within 1000ms of `DOMContentLoaded`
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

  - [x]* 4.2 Write property test for mixed content finding completeness (Property 4)
    - **Property 4: Mixed content finding completeness**
    - **Validates: Requirements 3.1, 3.2**
    - Use `fast-check` to generate DOM trees with varying HTTP/HTTPS sub-resource combinations; assert a finding is produced for each HTTP resource on an HTTPS page

  - [x]* 4.3 Write unit tests for mixed content detector
    - Test: HTTPS page, all resources HTTPS → zero findings
    - Test: HTTPS page with HTTP `<script>` → finding produced
    - Test: HTTPS page with HTTP form action → finding produced
    - Test: HTTP page → check skipped, note recorded
    - _Requirements: 3.1–3.4_

- [x] 5. Browser Extension — DOM pattern analyzer
  - [x] 5.1 Implement `scanner/dom-patterns.ts` (content script)
    - Detect `eval()`, `innerHTML` assignment, `document.write()`, `setTimeout`/`setInterval` with string arguments in page scripts
    - Produce `Finding` objects (type `dom_pattern`) with pattern type, script source URL or inline identifier, line number where available
    - Aggregate: if > 20 instances of the same pattern detected, produce one finding with total count
    - Record a note for cross-origin scripts that cannot be accessed
    - Do not modify or block page script execution
    - _Requirements: 4.1, 4.2, 4.3, 4.4_

  - [ ]* 5.2 Write property test for DOM pattern finding completeness (Property 5)
    - **Property 5: DOM pattern finding completeness**
    - **Validates: Requirements 4.1**
    - Use `fast-check` to generate script content with varying dangerous pattern occurrences; assert a finding is produced for each detected pattern

  - [ ]* 5.3 Write property test for DOM pattern aggregation (Property 6)
    - **Property 6: DOM pattern aggregation**
    - **Validates: Requirements 4.3**
    - Use `fast-check` to generate inputs with > 20 instances of the same pattern; assert exactly one aggregated finding is produced with the correct count

  - [ ]* 5.4 Write unit tests for DOM pattern analyzer
    - Test: no dangerous patterns → zero findings
    - Test: single `eval()` → one finding with pattern type and location
    - Test: 21 `innerHTML` assignments → one aggregated finding with count 21
    - Test: cross-origin script → note recorded, no finding
    - _Requirements: 4.1–4.4_

- [x] 6. Browser Extension — NVD client
  - [x] 6.1 Implement `scanner/nvd-client.ts`
    - Detect third-party JS libraries and versions from page scripts (e.g., via global variable patterns or script URL naming conventions)
    - Query NVD API for CVEs by library name and version
    - Cache results in IndexedDB with a 24-hour TTL
    - On NVD API timeout (> 5s): use cached data if available, record warning; skip CVE lookup if no cache
    - If no version extractable: record a note, skip CVE lookup
    - Produce `Finding` objects (type `cve`) with library name, version, CVE IDs, CVSS scores, CVE detail links
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

  - [ ]* 6.2 Write property test for CVE finding completeness (Property 7)
    - **Property 7: CVE finding completeness**
    - **Validates: Requirements 5.2**
    - Use `fast-check` to generate library/version/CVE combinations; assert a finding is produced containing all required fields for each CVE

  - [ ]* 6.3 Write property test for NVD cache hit (Property 8)
    - **Property 8: NVD cache hit prevents redundant API calls**
    - **Validates: Requirements 5.3**
    - Use `fast-check` to generate library/version pairs; assert that a second query within 24h uses the cache and makes zero new API calls

  - [ ]* 6.4 Write unit tests for NVD client
    - Test: library with known CVEs → finding produced with all required fields
    - Test: library queried twice within 24h → second call uses cache
    - Test: NVD API timeout, cache available → cached result used, warning recorded
    - Test: no version extractable → note recorded, no CVE lookup
    - _Requirements: 5.1–5.5_

- [x] 7. Checkpoint — Extension scanners complete
  - Ensure all scanner unit and property tests pass, ask the user if questions arise.

- [x] 8. ML Filter Microservice
  - [x] 8.1 Implement LSTM model training pipeline (`ml-filter/train.py`)
    - Define bidirectional LSTM architecture in TensorFlow/Keras: input tokenized JS context window (±10 tokens), output binary classification + confidence
    - Implement tokenizer and context window extractor
    - Train on labeled DOM manipulation dataset; target FPR < 10% on validation set of ≥ 1,000 samples
    - Save model artifacts to `ml-filter/model/`
    - _Requirements: 6.1, 6.6_

  - [x] 8.2 Implement `POST /classify` REST endpoint (`ml-filter/app.py`)
    - Accept `MLFilterRequest` JSON body; validate `pattern_type` enum and `context_tokens` array
    - Run inference through loaded LSTM model
    - Return `MLFilterResponse` with `finding_id`, `classification`, `confidence`
    - Enforce ≤ 300ms response time; return HTTP 503 on model load failure
    - _Requirements: 6.1, 6.4_

  - [x]* 8.3 Write property test for ML Filter classification coverage (Property 9)
    - **Property 9: ML Filter classification applied to all DOM findings**
    - **Validates: Requirements 6.1, 6.2, 6.3**
    - Use `hypothesis` to generate sets of DOM findings; assert each finding is sent to the classifier and the response correctly routes safe/anomalous findings

  - [x]* 8.4 Write unit tests for ML Filter service
    - Test: valid request → response within 300ms with valid classification and confidence in [0,1]
    - Test: invalid `pattern_type` → HTTP 400
    - Test: model unavailable → HTTP 503
    - _Requirements: 6.1, 6.4, 6.5_

- [x] 9. Browser Extension — Report builder and ML Filter integration
  - [x] 9.1 Implement `report/builder.ts`
    - Collect findings from all scanners (headers, cookies, mixed content, DOM patterns, CVE)
    - For each DOM pattern finding: call ML Filter via `report/submitter.ts`; exclude `safe` findings; attach `mlConfidence` to `anomalous` findings
    - On ML Filter timeout/unavailable: include all DOM findings unfiltered, set `mlFilterStatus: "unavailable"`
    - Compute Risk Score: `min(100, sum(weight[severity] * count[severity]))` with weights `{critical:40, high:15, medium:5, low:2, informational:0.5}`
    - Assemble `ScanReport` with all required fields: `schemaVersion`, `sessionId` (UUID v4), `timestamp`, `scannedUrl`, `browserInfo`, `findings`, `riskScore`, `mlFilterStatus`
    - _Requirements: 6.1, 6.2, 6.3, 6.5, 7.1, 7.2, 7.3, 7.4_

  - [ ]* 9.2 Write property test for Scan Report structural invariants (Property 10)
    - **Property 10: Scan Report structural invariants**
    - **Validates: Requirements 7.1, 7.2, 7.3, 7.4**
    - Use `fast-check` to generate arbitrary finding sets; assert every produced report has a unique UUID v4 session ID, non-empty `schemaVersion`, `riskScore` in [0,100], and all required fields present

  - [ ]* 9.3 Write property test for Scan Report serialization round-trip (Property 11)
    - **Property 11: Scan Report serialization round-trip**
    - **Validates: Requirements 7.5**
    - Use `fast-check` to generate valid `ScanReport` objects; assert `JSON.parse(JSON.stringify(report))` is deeply equal to the original

  - [ ]* 9.4 Write unit tests for report builder
    - Test: ML Filter returns `safe` → finding excluded from report
    - Test: ML Filter returns `anomalous` → finding included with `mlConfidence`
    - Test: ML Filter unavailable → all DOM findings included, `mlFilterStatus: "unavailable"`
    - Test: Risk Score computation for known severity counts
    - _Requirements: 6.1–6.3, 6.5, 7.1–7.4_

- [ ] 10. Browser Extension — Report submitter, popup UI, and privacy controls
  - [ ] 10.1 Implement `report/submitter.ts`
    - POST `ScanReport` JSON to API Server endpoint
    - On API Server unreachable: queue report in `browser.storage.local`, retry on next opportunity
    - Ensure payload contains only findings metadata and scanned URL — no page content, DOM tree, or form data
    - _Requirements: 13.4_

  - [ ] 10.2 Implement `ui/popup.ts`
    - Render enable/disable toggle; on disable, immediately cease all scanning
    - Render allowlist and blocklist management UI (add/remove URL patterns)
    - Persist allowlist/blocklist to `browser.storage.sync`
    - _Requirements: 13.1, 13.2, 13.5_

  - [ ] 10.3 Implement blocklist enforcement in `background.ts`
    - Before any scan or API call, check if the current URL matches a blocklist pattern
    - If matched: skip all scanning, make zero API calls, produce zero findings
    - _Requirements: 13.3_

  - [ ]* 10.4 Write property test for blocklist privacy enforcement (Property 21)
    - **Property 21: Blocklist privacy enforcement**
    - **Validates: Requirements 13.3**
    - Use `fast-check` to generate URL/blocklist-pattern combinations; assert that matching URLs produce zero findings and zero API calls

  - [ ]* 10.5 Write property test for transmitted payload privacy invariant (Property 22)
    - **Property 22: Transmitted payload privacy invariant**
    - **Validates: Requirements 13.4**
    - Use `fast-check` to generate scan sessions with arbitrary page content; assert the transmitted payload contains only findings metadata and scanned URL

  - [ ]* 10.6 Write unit tests for privacy controls
    - Test: blocklisted URL → zero findings, zero API calls
    - Test: extension disabled → scanning ceases immediately
    - Test: submitted payload → no page content, DOM tree, or form data present
    - _Requirements: 13.3, 13.4, 13.5_

- [~] 11. Checkpoint — Extension complete
  - Ensure all extension tests pass, ask the user if questions arise.

- [ ] 12. Blockchain Audit Layer — Smart contract
  - [ ] 12.1 Implement `AuditAnchor.sol`
    - Define `AuditRecord` struct: `auditHash`, `sessionId`, `timestamp`, `scannedUrl`
    - Implement `anchor(sessionId, auditHash, scannedUrl)` — store record, emit `AuditAnchored` event
    - Implement `verify(sessionId, auditHash) returns (bool)` — compare stored hash
    - _Requirements: 8.1, 8.2, 8.5_

  - [ ]* 12.2 Write Foundry fuzz test for audit hash correctness (Property 12)
    - **Property 12: Audit hash correctness**
    - **Validates: Requirements 8.1**
    - Fuzz `auditHash` bytes32 inputs; assert the stored hash equals the submitted hash after `anchor()`

  - [ ]* 12.3 Write Foundry fuzz test for blockchain anchor verification round-trip (Property 13)
    - **Property 13: Blockchain anchor verification round-trip**
    - **Validates: Requirements 8.5**
    - Fuzz `sessionId` and `auditHash`; assert `verify(sessionId, originalHash)` returns `true` and `verify(sessionId, modifiedHash)` returns `false` for any modified hash

  - [ ]* 12.4 Write unit tests for AuditAnchor contract
    - Test: `anchor()` stores record and emits event
    - Test: `verify()` returns `true` for matching hash
    - Test: `verify()` returns `false` for non-matching hash
    - Test: overwriting an existing sessionId updates the record
    - _Requirements: 8.1, 8.2, 8.5_

- [ ] 13. Blockchain Audit Layer — Ethers.js anchor service
  - [ ] 13.1 Implement `blockchain/anchor-service.ts`
    - Compute SHA-256 of canonical JSON (sorted keys, no whitespace) of `ScanReport` → `auditHash`
    - Call `anchor(sessionId, auditHash, scannedUrl)` on deployed `AuditAnchor` contract via Ethers.js
    - On confirmation: return `txHash` and `blockNumber`
    - Implement retry queue: on network failure, retry at 30s → 60s → 120s; after 3 failures mark as `unanchored`
    - Persist retry queue in `anchor_queue` DB table
    - _Requirements: 8.1, 8.2, 8.3, 8.4_

  - [ ] 13.2 Implement `blockchain/verify-service.ts`
    - Accept `sessionId` and `ScanReport`; recompute `auditHash`; call `verify()` on contract
    - Return verification result within 10 seconds
    - _Requirements: 8.5, 8.6_

  - [ ]* 13.3 Write unit tests for anchor service
    - Test: successful anchor → `txHash` and `blockNumber` returned
    - Test: network failure → retry queue populated, retried at correct intervals
    - Test: 3 failures → report marked `unanchored`
    - Test: verify with matching hash → `true`; with modified hash → `false`
    - _Requirements: 8.1–8.6_

- [ ] 14. Checkpoint — Blockchain layer complete
  - Ensure all blockchain tests pass against local Ganache instance, ask the user if questions arise.

- [~] 15. API Server — Database schema and data access layer
  - [ ] 15.1 Create PostgreSQL migration files
    - `users` table: `id`, `email`, `password_hash`, `created_at`
    - `scan_reports` table with all columns and indexes on `(user_id, timestamp DESC)` and `session_id`
    - `findings` table with indexes on `session_id` and `severity`
    - `anchor_queue` table
    - _Requirements: 10.1, 10.3_

  - [ ] 15.2 Implement data access layer (`api-server/src/db/`)
    - `reports.ts`: insert report + findings, query paginated reports by user, query single report by session ID, update blockchain status
    - `users.ts`: create user, find user by email
    - `anchor-queue.ts`: enqueue, dequeue, update retry state
    - _Requirements: 10.1, 10.3_

  - [ ]* 15.3 Write integration tests for data access layer
    - Test: insert and retrieve report round-trip
    - Test: paginated query returns results sorted by timestamp DESC
    - Test: findings inserted and retrievable by session ID
    - _Requirements: 10.1, 10.3_

- [~] 16. API Server — REST endpoints and JWT authentication
  - [ ] 16.1 Implement JWT authentication middleware (`api-server/src/middleware/auth.ts`)
    - Validate `Authorization: Bearer <token>` header on all `/api/v1/reports` routes
    - Return HTTP 401 for missing, expired, malformed, or invalid-signature tokens
    - _Requirements: 10.4_

  - [ ] 16.2 Implement `POST /api/v1/auth/login`
    - Accept `email` + `password`; verify against `users` table; return signed JWT on success
    - _Requirements: 10.4_

  - [ ] 16.3 Implement `POST /api/v1/reports`
    - Validate incoming JSON against versioned `ScanReport` JSON Schema using `ajv`
    - Return HTTP 400 with structured validation error on schema failure
    - Persist valid report and findings to PostgreSQL
    - Trigger blockchain anchoring asynchronously
    - Return HTTP 503 if DB unavailable
    - _Requirements: 10.1, 10.2, 10.5_

  - [ ] 16.4 Implement `GET /api/v1/reports` and `GET /api/v1/reports/:sessionId`
    - Return paginated reports sorted by `timestamp DESC` for authenticated user
    - Return single report with all findings and blockchain anchor status
    - Respond within 500ms under 100 concurrent requests
    - _Requirements: 10.3, 10.6_

  - [ ] 16.5 Implement `GET /api/v1/reports/:sessionId/verify`
    - Invoke `verify-service.ts`; return verification result
    - _Requirements: 8.5, 8.6_

  - [ ] 16.6 Implement `GET /api/v1/health`
    - Return HTTP 200 with service status
    - _Requirements: 10.1_

  - [ ]* 16.7 Write property test for invalid report rejection (Property 17)
    - **Property 17: Invalid report rejection**
    - **Validates: Requirements 10.2**
    - Use `fast-check` to generate structurally invalid `ScanReport` objects (missing fields, wrong types, out-of-range values); assert HTTP 400 is returned with a descriptive error for each

  - [ ]* 16.8 Write property test for JWT authentication enforcement (Property 18)
    - **Property 18: JWT authentication enforcement**
    - **Validates: Requirements 10.4**
    - Use `fast-check` to generate invalid tokens (missing, expired, malformed, wrong signature); assert HTTP 401 is returned and no scan data is included in the response

  - [ ]* 16.9 Write unit tests for API Server endpoints
    - Test: valid report submission → HTTP 201, persisted to DB, blockchain anchor triggered
    - Test: invalid schema → HTTP 400 with validation details
    - Test: unauthenticated request → HTTP 401
    - Test: DB unavailable → HTTP 503 with session ID in log
    - Test: paginated list sorted by timestamp DESC
    - _Requirements: 10.1–10.6_

- [~] 17. Checkpoint — API Server complete
  - Ensure all API Server tests pass, ask the user if questions arise.

- [~] 18. Web Dashboard — Core views
  - [ ] 18.1 Implement React app scaffold and routing (`dashboard/src/`)
    - Set up React Router with routes: `/login`, `/reports`, `/reports/:sessionId`, `/settings`
    - Implement JWT-aware Axios instance; redirect unauthenticated users to `/login`
    - Serve over HTTPS
    - _Requirements: 9.6_

  - [ ] 18.2 Implement Report List view (`/reports`)
    - Fetch paginated `ScanReport` list from `GET /api/v1/reports`
    - Render table sorted by timestamp descending
    - _Requirements: 9.1_

  - [ ] 18.3 Implement Report Detail view (`/reports/:sessionId`)
    - Fetch report from `GET /api/v1/reports/:sessionId`
    - Render full findings list, Risk Score, scanned URL, timestamp, blockchain anchor status
    - _Requirements: 9.2_

  - [ ] 18.4 Implement severity filter
    - Client-side filter on findings list by severity
    - Update displayed findings within 200ms via React state — no network call
    - _Requirements: 9.5_

  - [ ]* 18.5 Write property test for report list sort order (Property 14)
    - **Property 14: Report list sort order**
    - **Validates: Requirements 9.1**
    - Use `fast-check` to generate report lists with arbitrary timestamps; assert rendered list is sorted strictly descending by timestamp

  - [ ]* 18.6 Write property test for report detail completeness (Property 15)
    - **Property 15: Report detail completeness**
    - **Validates: Requirements 9.2**
    - Use `fast-check` to generate `ScanReport` objects; assert the detail view renders all required fields

  - [ ]* 18.7 Write property test for severity grouping correctness (Property 16)
    - **Property 16: Severity grouping correctness**
    - **Validates: Requirements 9.4, 9.5**
    - Use `fast-check` to generate finding sets with varying severities; assert chart data counts match actual severity counts and severity filter produces correct subsets

  - [ ]* 18.8 Write unit tests for Dashboard views
    - Test: unauthenticated user → redirected to `/login`
    - Test: report list renders in descending timestamp order
    - Test: severity filter updates list within 200ms without network call
    - _Requirements: 9.1, 9.5, 9.6_

- [~] 19. Web Dashboard — Charts
  - [ ] 19.1 Implement Risk Score trend chart
    - Fetch last 30+ scan sessions for selected URL/domain
    - Render line chart using Chart.js
    - _Requirements: 9.3_

  - [ ] 19.2 Implement vulnerability breakdown chart
    - Render bar/donut chart of findings grouped by severity using Chart.js
    - _Requirements: 9.4_

- [~] 20. Web Dashboard — Settings view
  - [ ] 20.1 Implement Settings view (`/settings`)
    - Render allowlist/blocklist management UI
    - Sync patterns with extension via API
    - _Requirements: 13.1, 13.2_

- [~] 21. Checkpoint — Dashboard complete
  - Ensure all Dashboard tests pass, ask the user if questions arise.

- [~] 22. CI/CD Integration — GitHub Actions workflow
  - [ ] 22.1 Implement GitHub Actions workflow file (`.github/workflows/devguard-scan.yml`)
    - Trigger on `pull_request` events: `opened`, `synchronize`, `reopened`
    - Steps: build app, start staging server, POST scan request to API Server, poll for completion (timeout 10 min), retrieve Scan Report
    - _Requirements: 11.1, 11.5_

  - [ ] 22.2 Implement PR comment posting script (`cicd/post-comment.ts`)
    - Format comment with Risk Score, severity counts, and dashboard link
    - Post comment to GitHub PR via GitHub API
    - _Requirements: 11.2_

  - [ ] 22.3 Implement check status enforcement (`cicd/set-status.ts`)
    - Set check status to `failed` if any Critical Vulnerabilities found (CVSS ≥ 9.0 or ML-classified critical)
    - Set check status to `passed` for all other results
    - Set check status to `failed` with "scan service unavailable" if API Server unreachable
    - Set check status to `failed` with "scan timed out" if poll exceeds 10 minutes
    - _Requirements: 11.3, 11.4, 11.6_

  - [ ]* 22.4 Write property test for CI/CD check status correctness (Property 19)
    - **Property 19: CI/CD check status correctness**
    - **Validates: Requirements 11.3, 11.4**
    - Use `fast-check` to generate scan results with varying critical/non-critical finding combinations; assert check status is `failed` if and only if at least one critical finding is present

  - [ ]* 22.5 Write property test for PR comment completeness (Property 20)
    - **Property 20: PR comment completeness**
    - **Validates: Requirements 11.2**
    - Use `fast-check` to generate completed scan results; assert the PR comment contains Risk Score, severity counts, and a dashboard link

  - [ ]* 22.6 Write unit tests for CI/CD integration
    - Test: scan with critical finding → check status `failed`, merge blocked
    - Test: scan with only high/medium/low findings → check status `passed`
    - Test: API Server unreachable → check status `failed` with correct message
    - Test: scan timeout → check status `failed` with correct message
    - Test: PR comment contains all required fields
    - _Requirements: 11.1–11.6_

- [~] 23. Final checkpoint — Full system integration
  - Wire Extension → ML Filter → API Server → Blockchain Anchor → Dashboard end-to-end
  - Verify Extension submits reports to API Server with correct schema
  - Verify API Server triggers blockchain anchoring after report persistence
  - Verify Dashboard reads and renders reports from API Server
  - Verify CI/CD workflow triggers scan and posts PR comment
  - Ensure all tests pass across all layers, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for a faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation at each layer boundary
- Property tests validate universal correctness properties using `fast-check` (TypeScript), `hypothesis` (Python), and Foundry fuzzer (Solidity)
- Unit tests validate specific examples and edge cases
- The ML model training pipeline (task 8.1) must complete before the ML Filter service (task 8.2) can be tested end-to-end
- Deploy `AuditAnchor.sol` to a local Ganache instance for development; configure Sepolia/Mumbai for staging
