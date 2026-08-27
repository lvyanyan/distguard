import { rmSync } from 'node:fs'
import { afterEach, describe, expect, it } from 'vitest'
import { scanDirectory } from '../src/engine/scan'
import { RULES } from '../src/rules'
import { makeFixtureDist } from './helpers/makeFixtures'

let distRoot: string

afterEach(() => {
  if (distRoot) rmSync(distRoot, { recursive: true, force: true })
})

describe('directory scanning with sourcemap analysis', () => {
  it('collects credential findings and excludes whitelisted samples', async () => {
    distRoot = makeFixtureDist()
    const report = await scanDirectory(distRoot, { rules: RULES })

    expect(report.scannedFiles).toBeGreaterThanOrEqual(5)

    const awsFindings = report.findings.filter(f => f.ruleId === 'aws-access-key-id')
    expect(awsFindings).toHaveLength(1)
    expect(awsFindings[0]!.preview).toContain('AKIAAB')

    const ruleIds = new Set(report.findings.map(f => f.ruleId))
    for (const id of [
      'aws-access-key-id',
      'stripe-live-secret-key',
      'private-key-block',
      'google-api-key',
      'hardcoded-jwt',
      'firebase-database-url',
      'internal-network-url',
      'sourcemap-restorable-sources',
      'sourcemap-exposed',
    ]) {
      expect(ruleIds, `missing ${id}`).toContain(id)
    }
  })

  it('flags restorable maps at medium and bare maps at low', async () => {
    distRoot = makeFixtureDist()
    const report = await scanDirectory(distRoot, { rules: RULES })
    const restorable = report.findings.find(f => f.ruleId === 'sourcemap-restorable-sources')!
    const exposed = report.findings.find(f => f.ruleId === 'sourcemap-exposed')!
    expect(restorable.severity).toBe('medium')
    expect(exposed.severity).toBe('low')
  })

  it('aggregates severity counters consistently', async () => {
    distRoot = makeFixtureDist()
    const report = await scanDirectory(distRoot, { rules: RULES })
    const sum = Object.values(report.bySeverity).reduce((a, b) => a + b, 0)
    expect(sum).toBe(report.findings.length)
  })

  it('resolves relative paths portably for code frames', async () => {
    distRoot = makeFixtureDist()
    const report = await scanDirectory(distRoot, { rules: RULES })
    for (const finding of report.findings) {
      expect(finding.file.includes('\\')).toBe(false)
      expect(finding.file.startsWith('/')).toBe(false)
    }
  })
})
