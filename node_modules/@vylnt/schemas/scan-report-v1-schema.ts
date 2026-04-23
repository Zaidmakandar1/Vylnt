/**
 * Vylnt DevGuard — ScanReport JSON Schema v1
 * This file is the canonical source for the schema.
 * Run `npm run generate-schema` from the root to emit scan-report.v1.json.
 */
export const scanReportV1Schema = {
  $schema: "http://json-schema.org/draft-07/schema#",
  $id: "https://vylnt.dev/schemas/scan-report/v1",
  type: "object",
  required: [
    "schemaVersion",
    "sessionId",
    "timestamp",
    "scannedUrl",
    "browserInfo",
    "findings",
    "riskScore",
    "mlFilterStatus",
  ],
  properties: {
    schemaVersion: { type: "string", const: "1.0" },
    sessionId: { type: "string", format: "uuid" },
    timestamp: { type: "string", format: "date-time" },
    scannedUrl: { type: "string", format: "uri" },
    browserInfo: {
      type: "object",
      required: ["name", "version", "extensionVersion"],
      properties: {
        name: { type: "string" },
        version: { type: "string" },
        extensionVersion: { type: "string" },
      },
      additionalProperties: false,
    },
    findings: {
      type: "array",
      items: { $ref: "#/definitions/Finding" },
    },
    riskScore: { type: "number", minimum: 0, maximum: 100 },
    mlFilterStatus: {
      type: "string",
      enum: ["applied", "unavailable", "not_applicable"],
    },
    blockchainAnchor: {
      type: "object",
      properties: {
        status: { type: "string", enum: ["anchored", "pending", "unanchored"] },
        txHash: { type: "string" },
        blockNumber: { type: "integer" },
        auditHash: { type: "string" },
      },
      additionalProperties: false,
    },
  },
  additionalProperties: false,
  definitions: {
    Finding: {
      type: "object",
      required: ["findingId", "type", "severity", "description", "affectedResource"],
      properties: {
        findingId: { type: "string", format: "uuid" },
        type: {
          type: "string",
          enum: [
            "missing_header",
            "misconfigured_header",
            "insecure_cookie",
            "mixed_content",
            "dom_pattern",
            "cve",
            "note",
          ],
        },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low", "informational"],
        },
        description: { type: "string" },
        affectedResource: { type: "string" },
        details: { type: "object" },
        mlConfidence: { type: "number", minimum: 0, maximum: 1 },
      },
      additionalProperties: false,
    },
  },
} as const;
