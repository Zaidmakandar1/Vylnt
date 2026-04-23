import { writeFileSync } from "node:fs";
import { scanReportV1Schema } from "./scan-report-v1-schema";

writeFileSync(
  new URL("./scan-report.v1.json", import.meta.url).pathname,
  JSON.stringify(scanReportV1Schema, null, 2) + "\n",
  "utf-8"
);

console.log("Generated schemas/scan-report.v1.json");
