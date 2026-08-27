import { describe, expect, it } from 'vitest'
import { computeExitCode } from '../src/engine/exitCode'

describe('computeExitCode', () => {
  const none = [] as { severity: string }[]
  const low = [{ severity: 'low' }]
  const medium = [{ severity: 'medium' }]
  const high = [{ severity: 'high' }]
  const critical = [{ severity: 'critical' }]

  it('is clean when below threshold', () => {
    expect(computeExitCode(none, 'high')).toBe(0)
    expect(computeExitCode(low, 'high')).toBe(0)
    expect(computeExitCode(medium, 'high')).toBe(0)
  })

  it('fails once threshold is reached', () => {
    expect(computeExitCode(high, 'high')).toBe(1)
    expect(computeExitCode(critical, 'high')).toBe(1)
    expect(computeExitCode(critical, 'critical')).toBe(1)
    expect(computeExitCode(medium, 'medium')).toBe(1)
    expect(computeExitCode(low, 'info')).toBe(1)
  })

  it('throws on unknown levels', () => {
    expect(() => computeExitCode(high, 'severe')).toThrow()
  })
})
