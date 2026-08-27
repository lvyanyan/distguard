import { readdir, readFile, stat } from "node:fs/promises";
import type { Dirent } from "node:fs";
import { join, relative, sep } from "node:path";
import type { Rule, Finding, ScanReport } from "./types";
import { SEVERITY_ORDER, type Severity } from "./severity";
import { sourcemapFindings } from "../analyzers/sourcemap";

const SKIP_DIRS = new Set(["node_modules", ".git"]);
const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;

const TEXT_EXTENSIONS = new Set([
  ".js",
  ".mjs",
  ".cjs",
  ".ts",
  ".jsx",
  ".tsx",
  ".json",
  ".map",
  ".html",
  ".htm",
  ".css",
  ".txt",
  ".env",
  ".yml",
  ".yaml",
  ".xml",
  ".svg",
  ".vue",
]);

export interface ScanOptions {
  rules?: Rule[];
  maxFileBytes?: number;
}

/** Redact a secret for report display: keep a short prefix only. */
export function redact(value: string): string {
  if (value.length <= 8) return "*".repeat(value.length);
  return value.slice(0, 6) + "…" + "*".repeat(4);
}

/**
 * Scan raw text against the rule set. Exported for direct unit testing.
 * Returns one finding per unique (ruleId, value, line).
 */
export function scanText(text: string, file: string, rules: Rule[]): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const lines = text.split(/\r?\n/);

  lines.forEach((lineContent, index) => {
    for (const rule of rules) {
      // fresh regex per line avoids lastIndex pitfalls; the `d` flag exposes
      // capture-group spans for precise code-frame anchoring
      const re = new RegExp(
        rule.pattern.source,
        rule.pattern.flags.replace("g", "").replace("d", "") + "dg",
      );
      let match: RegExpExecArray | null;
      while ((match = re.exec(lineContent)) !== null) {
        if (match[0].length === 0) {
          re.lastIndex++;
          continue;
        }
        const value = (match[1] ?? match[0]) as string;
        const indices = match.indices as Array<[number, number]> | undefined;
        const span = indices?.[1] ?? indices?.[0];
        const column = span ? span[0] + 1 : match.index + 1;
        const length = span ? span[1] - span[0] : match[0].length;
        if (rule.knownSamples?.some((sample) => sample.toLowerCase() === value.toLowerCase())) {
          continue;
        }
        const key = `${rule.id}\u0000${value}\u0000${index}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          ruleId: rule.id,
          severity: rule.severity,
          category: rule.category,
          file,
          line: index + 1,
          column,
          length,
          preview: redact(value),
        });
      }
    }
  });

  return findings;
}

function emptyCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

/**
 * Walk `root` and evaluate every rule against text files, exposing scanned
 * file contents so reporters can render code frames without re-reading.
 */
export async function scanDirectoryDetailed(
  root: string,
  options: ScanOptions = {},
): Promise<{ report: ScanReport; contents: Map<string, string> }> {
  const rules = options.rules ?? [];
  const maxBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;

  const filePaths: string[] = [];
  const contents = new Map<string, string>();
  const findings: Finding[] = [];

  const stack: string[] = [root];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: Dirent[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) stack.push(full);
        continue;
      }
      if (!entry.isFile()) continue;
      const dot = entry.name.lastIndexOf(".");
      const ext = dot === -1 ? "" : entry.name.slice(dot).toLowerCase();
      if (!TEXT_EXTENSIONS.has(ext)) continue;

      try {
        if ((await stat(full)).size > maxBytes) continue;
        const buffer = await readFile(full);
        // crude binary detection: NUL byte within the first 1KB
        if (buffer.subarray(0, 1024).includes(0)) continue;

        const rel = relative(root, full).split(sep).join("/");
        const text = buffer.toString("utf8");
        filePaths.push(rel);
        contents.set(rel, text);
        findings.push(...scanText(text, rel, rules));
      } catch {
        // unreadable during walk — ignore and keep scanning
      }
    }
  }

  findings.push(...sourcemapFindings(filePaths, contents));

  const bySeverity = emptyCounts();
  for (const f of findings) bySeverity[f.severity]++;

  findings.sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );

  return {
    report: { scannedFiles: filePaths.length, findings, bySeverity },
    contents,
  };
}

/**
 * Convenience wrapper for programmatic use: returns just the report.
 */
export async function scanDirectory(root: string, options: ScanOptions = {}): Promise<ScanReport> {
  const { report } = await scanDirectoryDetailed(root, options);
  return report;
}
