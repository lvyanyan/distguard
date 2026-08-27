import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const pkgPath = join(here, "..", "package.json");
export const VERSION = existsSync(pkgPath)
  ? (JSON.parse(readFileSync(pkgPath, "utf8")) as { version: string }).version
  : "0.0.0";

export { scanDirectory, scanText, redact } from "./engine/scan";
export { RULES, getRule } from "./rules";
export type { Finding, Rule, ScanReport } from "./engine/types";
export { severityRank, meetsThreshold, SEVERITY_ORDER } from "./engine/severity";
