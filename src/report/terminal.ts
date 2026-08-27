import type { Finding, ScanReport } from "../engine/types";
import { getRule } from "../rules";
import { SEVERITY_ORDER } from "../engine/severity";
import { buildCodeFrame } from "./frame";

const RESET = "\u001b[0m";
const COLORS: Record<string, string> = {
  critical: "\u001b[31m",
  high: "\u001b[33m",
  medium: "\u001b[36m",
  low: "\u001b[90m",
  info: "\u001b[2m",
  green: "\u001b[32m",
  bold: "\u001b[1m",
};

function paint(text: string, key: string): string {
  return (COLORS[key] ?? "") + text + RESET;
}

/**
 * Terminal report following the ESLint `stylish` + `codeframe` conventions:
 * findings grouped by file with aligned `line:col severity rule` rows and a
 * masked source excerpt, closed by a tally line. Remediation notes (why /
 * fix / reference) print once per distinct rule in a trailing section so the
 * report doubles as a fix guide without per-row spam.
 *
 * Diagnostics are results, not logs: everything here goes to stdout.
 */
export function renderTerminal(report: ScanReport, contents?: Map<string, string>): void {
  console.log("");

  if (report.findings.length === 0) {
    console.log(`distguard scanned ${report.scannedFiles} file(s)`);
    console.log(paint(" ✓ no findings", "green"));
    return;
  }

  // group by file, preserving severity order within each file group
  const byFile = new Map<string, Finding[]>();
  for (const finding of report.findings) {
    const list = byFile.get(finding.file);
    if (list) list.push(finding);
    else byFile.set(finding.file, [finding]);
  }

  for (const [file, findings] of byFile) {
    console.log(paint(file, "bold"));
    for (const finding of findings) {
      // synthetic analyzer summaries have no meaningful column — omit the locator
      const loc =
        finding.length > 0
          ? paint(`${finding.line}:${finding.column}`.padEnd(7), finding.severity)
          : "".padEnd(7);
      const row = `  ${loc}  ${paint(finding.severity.padEnd(8), finding.severity)}  ${paint(finding.ruleId, finding.severity)}  ${finding.preview}`;
      console.log(row);

      const lineText = contents?.get(finding.file)?.split(/\r?\n/)[finding.line - 1];
      if (lineText !== undefined && finding.length > 0) {
        const frame = buildCodeFrame(lineText, finding.column, finding.length);
        const gutterPad = " ".repeat(String(finding.line).length);
        console.log(`${gutterPad} |`);
        console.log(`${paint(String(finding.line), finding.severity)} | ${frame.maskedSource}`);
        console.log(`${gutterPad} | ${paint(frame.carets.trimEnd(), finding.severity)}`);
      }
    }
    console.log("");
  }

  // ESLint-style tally
  const parts = SEVERITY_ORDER.map((sev) =>
    report.bySeverity[sev] ? `${report.bySeverity[sev]} ${sev}` : "",
  ).filter(Boolean);
  console.log(
    paint(`✖ ${report.findings.length} problems`, "critical") +
      paint(` (${parts.join(", ")})`, "info"),
  );

  // remediation notes: once per distinct rule, in encounter order
  const seenRules = new Set<string>();
  for (const finding of report.findings) {
    if (seenRules.has(finding.ruleId)) continue;
    seenRules.add(finding.ruleId);
    const rule = getRule(finding.ruleId);
    if (!rule || rule.synthetic) continue;
    console.log("");
    console.log(paint(`◆ ${rule.id}`, rule.severity));
    console.log(`   why: ${rule.why}`);
    console.log(`   fix: ${rule.fix}`);
    if (rule.reference) console.log(`   ref: ${rule.reference}`);
  }
}
