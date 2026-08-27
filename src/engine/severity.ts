export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export const SEVERITY_ORDER: readonly Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
]

const RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
}

/** Higher = more severe. */
export function severityRank(severity: Severity): number {
  return RANK[severity]
}

/**
 * True when `severity` is at or above `threshold`
 * (e.g. high threshold fires on critical and high).
 */
export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return severityRank(severity) >= severityRank(threshold)
}
