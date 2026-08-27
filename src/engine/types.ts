import type { Severity } from './severity'

export interface Rule {
  /** Stable identifier, e.g. `aws-access-key-id`. */
  id: string
  severity: Severity
  category: 'credential' | 'exposure'
  /** One-line description shown in reports. */
  description: string
  /** Why a match is dangerous — printed in the report. */
  why: string
  /** How to remediate — printed in the report. */
  fix: string
  reference?: string
  /**
   * Detection pattern. The secret itself must be capture group 1 when the
   * pattern includes context around it; otherwise group 0 is used.
   */
  pattern: RegExp
  /**
   * Public documentation sample values published by vendors themselves.
   * A match equal to one of these is not reported (case-insensitive).
   */
  knownSamples?: string[]
  /** True for registry entries emitted by analyzers rather than matched textually. */
  synthetic?: boolean
}

export interface Finding {
  ruleId: string
  severity: Severity
  category: Rule['category']
  file: string
  line: number
  /** 1-based column of the match on its line (code frames anchor here). */
  column: number
  /** Length of the matched secret span (for caret width + redaction). */
  length: number
  /** Redacted preview of the match — secrets are never echoed in full. */
  preview: string
}

export interface ScanReport {
  scannedFiles: number
  findings: Finding[]
  bySeverity: Record<Severity, number>
}
