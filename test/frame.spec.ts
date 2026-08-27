import { describe, expect, it } from 'vitest'
import { buildCodeFrame } from '../src/report/frame'

describe('buildCodeFrame', () => {
  it('masks only the secret span', () => {
    // fragment-assembled per repo fixture policy
    const awsId = ['AKIA', 'ABCD', 'EFGH', 'IJKL', 'MNOP'].join('')
    const line = `const key = '${awsId}'`
    const column = line.indexOf(awsId) + 1
    const frame = buildCodeFrame(line, column, awsId.length)

    expect(frame.maskedSource.startsWith(`const key = '`)).toBe(true)
    // the id is masked with equal-width asterisks
    expect(frame.maskedSource).toContain('*'.repeat(awsId.length))
    expect(frame.maskedSource).not.toContain(awsId)
    // tail after the span survives
    expect(frame.maskedSource.endsWith(`'`)).toBe(true)
  })

  it('draws carets matching the masked width', () => {
    const stripe = 'sk_live_' + 'a'.repeat(32)
    const line = `x = "${stripe}"`
    const column = line.indexOf(stripe) + 1
    const frame = buildCodeFrame(line, column, stripe.length)
    expect(frame.carets.trim()).toBe('^'.repeat(stripe.length))
  })

  it('clamps gracefully on out-of-range input', () => {
    const frame = buildCodeFrame('short', 100, 50)
    expect(frame.maskedSource).toBe('short')
    expect(frame.carets.includes('^')).toBe(true)
  })
})
