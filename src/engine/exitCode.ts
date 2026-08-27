import type { Severity } from './severity'

const ORDER: readonly string[] = ['info', 'low', 'medium', 'high', 'critical']

/**
 * CI gate semantics: 0 when no finding reaches `threshold`,
 * 1 when it does, throwing on an unknown level (caller exits 2).
 */
export function computeExitCode(
  findings: readonly { severity: string }[],
  threshold: string,
): 0 | 1 {
  const rank = ORDER.indexOf(threshold)
  if (rank === -1) {
    throw new Error(`unknown fail-on level: ${threshold}`)
  }
  return findings.some(finding => ORDER.indexOf(finding.severity) >= rank)
    ? 1
    : 0
}

export const SEVERITY_LADDER: readonly Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
]
