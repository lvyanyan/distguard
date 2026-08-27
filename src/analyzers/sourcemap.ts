import type { Finding } from '../engine/types'

/**
 * Derive source-map exposure findings from already-scanned `.map` files.
 *
 * - restorable: `sourcesContent` contains at least one non-null entry —
 *   original source code ships to every visitor (medium)
 * - exposed: a bare `.map` without sources content still discloses file
 *   layout, original identifiers and build paths (low)
 *
 * One summary finding per class; `file` points at a representative path
 * and the count rides along inside the preview.
 */
export function sourcemapFindings(
  files: string[],
  contents: Map<string, string>,
): Finding[] {
  const maps = files.filter(file => file.endsWith('.map'))
  if (maps.length === 0) return []

  const restorable: string[] = []
  const bare: string[] = []

  for (const file of maps) {
    try {
      const parsed = JSON.parse(contents.get(file)!) as {
        sourcesContent?: unknown[]
      }
      const hasSources =
        Array.isArray(parsed.sourcesContent) &&
        parsed.sourcesContent.some(entry => typeof entry === 'string')
      ;(hasSources ? restorable : bare).push(file)
    } catch {
      // unparseable map still leaks its own path/structure
      bare.push(file)
    }
  }

  const findings: Finding[] = []
  if (restorable.length > 0) {
    findings.push({
      ruleId: 'sourcemap-restorable-sources',
      severity: 'medium',
      category: 'exposure',
      file: restorable[0]!,
      line: 1,
      column: 1,
      length: 0,
      preview: `${restorable.length} map(s) ship original sources`,
    })
  }
  if (bare.length > 0) {
    findings.push({
      ruleId: 'sourcemap-exposed',
      severity: 'low',
      category: 'exposure',
      file: bare[0]!,
      line: 1,
      column: 1,
      length: 0,
      preview: `${bare.length} map(s) published`,
    })
  }
  return findings
}
