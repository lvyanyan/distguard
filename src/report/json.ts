import type { ScanReport } from "../engine/types";

export function renderJson(report: ScanReport, version: string): string {
  return JSON.stringify(
    {
      tool: "distguard",
      version,
      scannedFiles: report.scannedFiles,
      summary: report.bySeverity,
      total: report.findings.length,
      findings: report.findings.map(({ ruleId, severity, category, file, line, preview }) => ({
        ruleId,
        severity,
        category,
        file,
        line,
        preview,
      })),
    },
    null,
    2,
  );
}
