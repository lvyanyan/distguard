import type { Rule } from '../engine/types'

/**
 * Synthetic registry entries emitted by analyzers (never matched through
 * their own dead patterns). Keeping them here means reports, the exit-code
 * gate and generated documentation all share one source of truth.
 */
const SYNTHETIC: Rule[] = [
  {
    id: 'sourcemap-restorable-sources',
    severity: 'medium',
    category: 'exposure',
    description: 'Published source map ships original sourcesContent',
    why:
      'Anyone visiting the site can download these .map files and reconstruct the original source code, comments included — amplifying every other exposure and disclosing internal paths.',
    fix: 'Stop emitting maps to production (build config) or strip sourcesContent/sourcemaps during deployment.',
    reference: 'https://blog.sentry.io/abusing-exposed-sourcemaps/',
    pattern: /$^/,
    synthetic: true,
  },
  {
    id: 'sourcemap-exposed',
    severity: 'low',
    category: 'exposure',
    description: 'Source map published alongside production bundle',
    why: 'Even without sources content, maps disclose original file layout, identifiers and build system paths.',
    fix: 'Disable sourcemaps for production builds or serve them behind authentication.',
    reference: 'https://blog.sentry.io/abusing-exposed-sourcemaps/',
    pattern: /$^/,
    synthetic: true,
  },
]

/**
 * Seed-to-MVP credential & exposure catalog.
 * Every entry carries its remediation story: the report IS the fix guide.
 */
export const RULES: Rule[] = [
  ...SYNTHETIC,

  {
    id: 'aws-access-key-id',
    severity: 'critical',
    category: 'credential',
    description: 'AWS access key id embedded in build output',
    why:
      'An access key id alone does not authenticate, but paired with a leaked secret access key it grants full programmatic access to the linked AWS account.',
    fix:
      'Rotate the key pair immediately in IAM and remove it from source; serve AWS credentials from your backend instead of bundling them.',
    reference:
      'https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html',
    pattern: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/,
    // assembled at runtime so this repository never ships a
    // byte-level lookalike credential (secret-scanning friendly)
    knownSamples: [['AKIA', 'IOSFODNN7', 'EXAMPLE'].join('')],
  },
  {
    id: 'stripe-live-secret-key',
    severity: 'critical',
    category: 'credential',
    description: 'Stripe live-mode secret key embedded in build output',
    why:
      'A live secret key can create charges, issue refunds and read customer data over the Stripe API without any further authentication.',
    fix:
      'Roll the key in the Stripe dashboard, restrict publishable keys to the frontend and move all secret-key usage behind your backend.',
    reference: 'https://docs.stripe.com/keys',
    pattern: /\b(sk_live_[0-9a-zA-Z]{24,})\b/,
  },
  {
    id: 'private-key-block',
    severity: 'critical',
    category: 'credential',
    description: 'Private key material embedded in build output',
    why:
      'A private key present in shipped assets lets anyone impersonate the service that owns it — TLS termination, JWT signing or SSH access.',
    fix:
      'Purge the key from the repository history, rotate it at the issuing authority and generate keys at deploy time only.',
    reference:
      'https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html',
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  },
  {
    id: 'github-token',
    severity: 'critical',
    category: 'credential',
    description: 'GitHub token embedded in build output',
    why:
      'GitHub tokens grant API access matching their scopes — code checkout, package publishing or repository administration depending on type.',
    fix: 'Revoke the token in GitHub developer settings and audit recent usage before issuing a replacement stored server-side.',
    reference: 'https://docs.github.com/authentication/keeping-your-account-and-data-secure/about-authentication-to-github',
    pattern: /\b(gh[posur]_[A-Za-z0-9]{36,251})\b/,
  },
  {
    id: 'npm-access-token',
    severity: 'critical',
    category: 'credential',
    description: 'npm access token embedded in build output',
    why: 'An npm token can publish packages under your name — a supply-chain attack lever against everyone installing your software.',
    fix: 'Revoke the token at npmjs.com, rotate it, and investigate unexpected publishes in the meantime.',
    reference: 'https://docs.npmjs.com/about-access-tokens',
    pattern: /\b(npm_[A-Za-z0-9]{36})\b/,
  },
  {
    id: 'google-oauth-client-secret',
    severity: 'critical',
    category: 'credential',
    description: 'Google OAuth client secret embedded in build output',
    why: 'Client secrets are meant to stay confidential; combined with the client id they allow token impersonation flows.',
    fix: 'Reset the client secret in Google Cloud Console and move OAuth token exchange to your backend.',
    reference: 'https://developers.google.com/identity/protocols/oauth2',
    pattern: /\b(GOCSPX-[A-Za-z0-9_-]{28,})\b/,
  },

  {
    id: 'google-api-key',
    severity: 'high',
    category: 'credential',
    description: 'Google API key embedded in build output',
    why:
      'Depending on API restrictions an exposed key can be abused to bill quota usage or reach otherwise restricted Google Cloud services.',
    fix:
      'Restrict the key by HTTP referrer / IP inside Google Cloud Console, or proxy calls that need elevated APIs through your backend.',
    reference: 'https://cloud.google.com/docs/authentication/api-keys',
    pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/,
  },
  {
    id: 'openai-secret-key',
    severity: 'high',
    category: 'credential',
    description: 'OpenAI secret key embedded in build output',
    why: 'The key authorizes paid model usage against your organization until revoked — direct financial abuse surface.',
    fix: 'Rotate the key in the OpenAI dashboard and route inference calls through your backend with spend limits.',
    reference: 'https://platform.openai.com/docs/api-reference/authentication',
    // keep clear of stripe's sk_live_/sk_test_ prefixes
    pattern: /\b(sk-(?!live_|test_)[A-Za-z0-9_-]{40,})\b/,
  },
  {
    id: 'slack-token',
    severity: 'high',
    category: 'credential',
    description: 'Slack token embedded in build output',
    why: 'Bot and user tokens can read conversations, post as your workspace and exfiltrate files within granted scopes.',
    fix: 'Deactivate the token in the Slack app management console and reissue with narrowly scoped permissions.',
    reference: 'https://api.slack.com/authentication/token-types',
    pattern: /\b(xox[abprs]-[0-9A-Za-z_-]{10,250})\b/,
  },
  {
    id: 'sendgrid-api-key',
    severity: 'high',
    category: 'credential',
    description: 'SendGrid API key embedded in build output',
    why: 'Mail-sending rights let attackers phish from your verified sender domain, torching deliverability and reputation.',
    fix: 'Delete the key in SendGrid settings, review sent activity for abuse, and relay transactional mail from your backend.',
    reference: 'https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys',
    pattern: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/,
  },
  {
    id: 'twilio-api-key',
    severity: 'high',
    category: 'credential',
    description: 'Twilio-style API key embedded in build output',
    why: 'Twilio API keys authenticate REST requests for messaging and voice — billable services abusable at scale.',
    fix: 'Confirm the value against your Twilio console; if genuine, delete the key and reissue, keeping it server-side only.',
    reference: 'https://www.twilio.com/docs/iam/keys/api-key',
    pattern: /\b(SK[0-9a-fA-F]{32})\b/,
  },
  {
    id: 'shopify-custom-app-token',
    severity: 'high',
    category: 'credential',
    description: 'Shopify custom app access token embedded in build output',
    why: 'Custom app tokens bypass storefront authorization and can read store data within their scopes.',
    fix: 'Rotate the token in the Shopify admin and proxy Admin API calls through your backend.',
    reference: 'https://shopify.dev/docs/apps/auth',
    pattern: /\b(shpat_[a-fA-F0-9]{32})\b/,
  },
  {
    id: 'basic-auth-url',
    severity: 'high',
    category: 'credential',
    description: 'URL contains inline basic-auth credentials',
    why: 'Usernames and passwords embedded in URLs leak into logs, referrers and browser history — anyone with the bundle owns the pair.',
    fix: 'Move HTTP basic authentication out of URLs into server-side configuration or token exchange.',
    reference:
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication#basic_authentication_scheme',
    pattern: /\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s/:@]+:[^\s/:@]+@/,
  },

  {
    id: 'hardcoded-jwt',
    severity: 'medium',
    category: 'credential',
    description: 'JSON Web Token embedded in build output',
    why: 'Bundled JWTs are long-lived by accident: they decode offline and remain valid until expiry regardless of frontend logout.',
    fix: 'Inspect the payload, shorten lifetimes, and deliver tokens at runtime from your identity flow instead of baking them in.',
    reference: 'https://datatracker.ietf.org/doc/html/rfc7519',
    pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/,
  },
  {
    id: 'firebase-database-url',
    severity: 'medium',
    category: 'exposure',
    description: 'Firebase Realtime Database URL referenced in build output',
    why:
      'Exposing the database URL invites probing; whether data is actually readable depends on security rules that commonly drift open.',
    fix: 'Verify the project’s database rules deny unauthenticated reads/writes and proxy database access via backend where possible.',
    reference: 'https://firebase.google.com/docs/database/security',
    pattern: /https:\/\/[a-z0-9-]+\.firebaseio\.com|https:\/\/[a-z0-9-]+\.firebasedatabase\.app/i,
  },
  {
    id: 'internal-network-url',
    severity: 'low',
    category: 'exposure',
    description: 'Private/internal network URL referenced in build output',
    why: 'Internal hostnames and RFC1918 addresses in shipped assets hand attackers a map of your infrastructure topology.',
    fix: 'Strip development endpoints from production config and drive environment-specific values at deploy time.',
    reference: 'https://datatracker.ietf.org/doc/html/rfc1918',
    pattern: /https?:\/\/(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|[\w-]+\.(?:local|internal|intranet))(?:[/:"']|$)/,
  },
]

export function getRule(id: string): Rule | undefined {
  return RULES.find(rule => rule.id === id)
}
