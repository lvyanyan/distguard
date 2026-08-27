import { describe, expect, it } from 'vitest'
import { scanText } from '../src/engine/scan'
import { RULES } from '../src/rules'

const byId = new Map(RULES.map(rule => [rule.id, rule]))

/**
 * Fixture policy: credential values are ALWAYS assembled from fragments so
 * this repository never contains a byte-level match for secret scanners
 * (GitHub push protection included). Runtime values stay structurally valid
 * for the rules under test.
 */
const AWS_SAMPLE = ['AKIA', 'IOSFODNN7', 'EXAMPLE'].join('')
const AWS_FAKE_1 = ['AKIA', 'ABCD', 'EFGH', 'IJKL', 'MNOP'].join('')
const ASIA_FAKE = ['ASIA', 'QRSTUVWX', 'YZ123456'].join('')

function hitPreviews(ruleId: string, text: string): string[] {
  const rule = byId.get(ruleId)!
  return scanText(text, 'fixture.js', [rule]).map(finding => finding.preview)
}

describe('rule: aws-access-key-id', () => {
  it('fires on structurally valid access key ids', () => {
    expect(hitPreviews('aws-access-key-id', `k="${AWS_FAKE_1}"`)).toHaveLength(1)
    expect(hitPreviews('aws-access-key-id', `k="${ASIA_FAKE}"`)).toHaveLength(1)
  })

  it('suppresses the vendor documented sample', () => {
    expect(hitPreviews('aws-access-key-id', `k="${AWS_SAMPLE}"`)).toHaveLength(0)
  })

  it('ignores malformed ids', () => {
    expect(hitPreviews('aws-access-key-id', 'k="AKIA123"')).toHaveLength(0)
    expect(hitPreviews('aws-access-key-id', 'k="akiaabcdefghijklmnop"')).toHaveLength(0)
  })
})

describe('rule: stripe-live-secret-key', () => {
  it('fires on live keys but not test keys', () => {
    expect(
      hitPreviews('stripe-live-secret-key', ['k="sk_live_', 'a'.repeat(24), '"'].join('')),
    ).toHaveLength(1)
    expect(
      hitPreviews('stripe-live-secret-key', ['k="sk_test_', 'a'.repeat(24), '"'].join('')),
    ).toHaveLength(0)
  })

  it('requires the full key body length', () => {
    expect(hitPreviews('stripe-live-secret-key', 'k="sk_live_shortshortshort"')).toHaveLength(0)
  })
})

describe('rule: google-api-key', () => {
  it('fires on format-valid keys', () => {
    const valid = 'AIza' + 'a'.repeat(35)
    expect(hitPreviews('google-api-key', `key=${JSON.stringify(valid)}`)).toHaveLength(1)
  })

  it('rejects wrong lengths', () => {
    expect(hitPreviews('google-api-key', `"AIza${'a'.repeat(34)}"`)).toHaveLength(0)
    expect(hitPreviews('google-api-key', `"AIza${'a'.repeat(36)}"`)).toHaveLength(0)
  })
})

describe('rule: private-key-block', () => {
  it('fires on begin markers across key types', () => {
    const rsaBegin = ['x="-----BEGIN ', 'RSA PRIVATE KEY-----"'].join('')
    const opensshBegin = ['x="-----BEGIN ', 'OPENSSH PRIVATE KEY-----"'].join('')
    expect(hitPreviews('private-key-block', rsaBegin)).toHaveLength(1)
    expect(hitPreviews('private-key-block', opensshBegin)).toHaveLength(1)
  })

  it('does not fire on end markers', () => {
    expect(hitPreviews('private-key-block', 'x="-----END PRIVATE KEY-----"')).toHaveLength(0)
  })
})

describe('rules: github / npm / google oauth client secret', () => {
  it('github-token fires on all prefixes and correct length', () => {
    for (const prefix of ['ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_']) {
      expect(
        hitPreviews('github-token', `t="${prefix}${'A9'.repeat(18)}"`),
      ).toHaveLength(1)
    }
    expect(hitPreviews('github-token', `t="ghp_${'A'.repeat(20)}"`)).toHaveLength(0)
  })

  it('npm-access-token exact length discipline', () => {
    expect(hitPreviews('npm-access-token', `t="npm_${'A'.repeat(36)}"`)).toHaveLength(1)
    expect(hitPreviews('npm-access-token', `t="npm_${'A'.repeat(35)}"`)).toHaveLength(0)
  })

  it('google-oauth-client-secret detection', () => {
    expect(hitPreviews('google-oauth-client-secret', `t="GOCSPX-${'a'.repeat(28)}"`)).toHaveLength(1)
    expect(hitPreviews('google-oauth-client-secret', 't="GOCSPX-short"')).toHaveLength(0)
  })
})

describe('rules: openai / slack / sendgrid / twilio / shopify', () => {
  it('openai-secret-key ignores stripe-prefixed values', () => {
    expect(hitPreviews('openai-secret-key', `t="${'sk-'}${'x'.repeat(40)}"`)).toHaveLength(1)
    expect(hitPreviews('openai-secret-key', `t="sk-proj-${'y'.repeat(40)}"`)).toHaveLength(1)
    // stripe format must not trip the openai rule
    const stripeStyle = 'sk_' + 'x'.repeat(40)
    expect(hitPreviews('openai-secret-key', `t="${stripeStyle}"`)).toHaveLength(0)
  })

  it('slack-token matches known token families only', () => {
    expect(hitPreviews('slack-token', `t="xoxb-${'1'.repeat(10)}abcdef"`)).toHaveLength(1)
    expect(hitPreviews('slack-token', 't="xoxn-not-a-family"')).toHaveLength(0)
  })

  it('sendgrid-api-key enforces both segments', () => {
    const valid = `SG.${'a'.repeat(22)}.${'b'.repeat(43)}`
    expect(hitPreviews('sendgrid-api-key', `t="${valid}"`)).toHaveLength(1)
    const broken = `SG.${'a'.repeat(21)}.${'b'.repeat(43)}`
    expect(hitPreviews('sendgrid-api-key', `t="${broken}"`)).toHaveLength(0)
  })

  it('twilio-api-key requires 32 hex chars after SK', () => {
    const hex32 = 'abcdef0123456789abcdef0123456789'
    expect(hitPreviews('twilio-api-key', `t="SK${hex32}"`)).toHaveLength(1)
    expect(hitPreviews('twilio-api-key', `t="SK${hex32.slice(0, 31)}"`)).toHaveLength(0)
    expect(hitPreviews('twilio-api-key', 't="SKzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"')).toHaveLength(0)
  })

  it('shopify-custom-app-token demands hex body', () => {
    const hex32 = '0123456789abcdef0123456789abcdef'
    expect(hitPreviews('shopify-custom-app-token', `t="shpat_${hex32}"`)).toHaveLength(1)
    expect(hitPreviews('shopify-custom-app-token', `t="shpat_${'g'.repeat(32)}"`)).toHaveLength(0)
  })
})

describe('rules: exposure family', () => {
  it('basic-auth-url catches inline credentials and spares clean urls', () => {
    expect(hitPreviews('basic-auth-url', 'fetch("https://user:secret@example.com/v1")')).toHaveLength(1)
    expect(hitPreviews('basic-auth-url', 'fetch("https://example.com/v1")')).toHaveLength(0)
  })

  it('hardcoded-jwt needs three full segments', () => {
    // canonical jwt.io example token, fragment-assembled
    const jwt = [
      'eyJhbGciOiJIUzI1NiJ9',
      'eyJzdWIiOiIxMjM0NTY3ODkwIn0',
      'SflKxwRJSMeKKF2QT4fWMeqRWfPj3aaa',
    ].join('.')
    expect(hitPreviews('hardcoded-jwt', `t="${jwt}"`)).toHaveLength(1)
    expect(hitPreviews('hardcoded-jwt', 't="eyJhbGciOiJIUzI1NiJ9.only-one-dot-left"')).toHaveLength(0)
  })

  it('firebase-database-url covers both host generations', () => {
    expect(hitPreviews('firebase-database-url', 'cfg="https://my-app.firebaseio.com"')).toHaveLength(1)
    expect(hitPreviews('firebase-database-url', 'cfg="https://my-app.firebasedatabase.app"')).toHaveLength(1)
    expect(hitPreviews('firebase-database-url', 'cfg="https://example.com"')).toHaveLength(0)
  })

  it('internal-network-url scopes to private hosts', () => {
    expect(hitPreviews('internal-network-url', 'api="http://192.168.1.5:8080/admin"')).toHaveLength(1)
    expect(hitPreviews('internal-network-url', 'api="https://grafana.internal/"')).toHaveLength(1)
    expect(hitPreviews('internal-network-url', 'api="http://example.com/192.168.0.1"')).toHaveLength(0)
  })
})

describe('scanText mechanics', () => {
  const rule = byId.get('aws-access-key-id')!

  it('reports accurate line numbers', () => {
    const findings = scanText(`a\nb\nc = "${AWS_FAKE_1}"`, 'f.js', [rule])
    expect(findings[0]!.line).toBe(3)
    expect(findings[0]!.severity).toBe('critical')
  })

  it('redacts matched secrets in previews', () => {
    const findings = scanText('"sk_live_' + 'z'.repeat(30) + '"', 'f.js', [
      byId.get('stripe-live-secret-key')!,
    ])
    const preview = findings[0]!.preview
    expect(preview.startsWith('sk_liv')).toBe(true)
    expect(preview.includes('*')).toBe(true)
    expect(preview).not.toContain('zzzz')
  })
})
