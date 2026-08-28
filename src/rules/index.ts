import type { Rule } from "../engine/types";

/**
 * Synthetic registry entries emitted by analyzers (never matched through
 * their own dead patterns). Keeping them here means reports, the exit-code
 * gate and generated documentation all share one source of truth.
 */
const SYNTHETIC: Rule[] = [
  {
    id: "sourcemap-restorable-sources",
    severity: "medium",
    category: "exposure",
    description: "Published source map ships original sourcesContent",
    why: "Anyone visiting the site can download these .map files and reconstruct the original source code, comments included — amplifying every other exposure and disclosing internal paths.",
    fix: "Stop emitting maps to production (build config) or strip sourcesContent/sourcemaps during deployment.",
    reference: "https://blog.sentry.io/abusing-exposed-sourcemaps/",
    pattern: /$^/,
    synthetic: true,
  },
  {
    id: "sourcemap-exposed",
    severity: "low",
    category: "exposure",
    description: "Source map published alongside production bundle",
    why: "Even without sources content, maps disclose original file layout, identifiers and build system paths.",
    fix: "Disable sourcemaps for production builds or serve them behind authentication.",
    reference: "https://blog.sentry.io/abusing-exposed-sourcemaps/",
    pattern: /$^/,
    synthetic: true,
  },
];

/**
 * Seed-to-MVP credential & exposure catalog.
 * Every entry carries its remediation story: the report IS the fix guide.
 */
export const RULES: Rule[] = [
  ...SYNTHETIC,

  {
    id: "aws-access-key-id",
    severity: "critical",
    category: "credential",
    description: "AWS access key id embedded in build output",
    why: "An access key id alone does not authenticate, but paired with a leaked secret access key it grants full programmatic access to the linked AWS account.",
    fix: "Rotate the key pair immediately in IAM and remove it from source; serve AWS credentials from your backend instead of bundling them.",
    reference: "https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html",
    pattern: /\b((?:AKIA|ASIA)[0-9A-Z]{16})\b/,
    // assembled at runtime so this repository never ships a
    // byte-level lookalike credential (secret-scanning friendly)
    knownSamples: [["AKIA", "IOSFODNN7", "EXAMPLE"].join("")],
  },
  {
    id: "stripe-live-secret-key",
    severity: "critical",
    category: "credential",
    description: "Stripe live-mode secret key embedded in build output",
    why: "A live secret key can create charges, issue refunds and read customer data over the Stripe API without any further authentication.",
    fix: "Roll the key in the Stripe dashboard, restrict publishable keys to the frontend and move all secret-key usage behind your backend.",
    reference: "https://docs.stripe.com/keys",
    pattern: /\b(sk_live_[0-9a-zA-Z]{24,})\b/,
  },
  {
    id: "private-key-block",
    severity: "critical",
    category: "credential",
    description: "Private key material embedded in build output",
    why: "A private key present in shipped assets lets anyone impersonate the service that owns it — TLS termination, JWT signing or SSH access.",
    fix: "Purge the key from the repository history, rotate it at the issuing authority and generate keys at deploy time only.",
    reference: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  },
  {
    id: "github-token",
    severity: "critical",
    category: "credential",
    description: "GitHub token embedded in build output",
    why: "GitHub tokens grant API access matching their scopes — code checkout, package publishing or repository administration depending on type.",
    fix: "Revoke the token in GitHub developer settings and audit recent usage before issuing a replacement stored server-side.",
    reference:
      "https://docs.github.com/authentication/keeping-your-account-and-data-secure/about-authentication-to-github",
    pattern: /\b(gh[posur]_[A-Za-z0-9]{36,251})\b/,
  },
  {
    id: "npm-access-token",
    severity: "critical",
    category: "credential",
    description: "npm access token embedded in build output",
    why: "An npm token can publish packages under your name — a supply-chain attack lever against everyone installing your software.",
    fix: "Revoke the token at npmjs.com, rotate it, and investigate unexpected publishes in the meantime.",
    reference: "https://docs.npmjs.com/about-access-tokens",
    pattern: /\b(npm_[A-Za-z0-9]{36})\b/,
  },
  {
    id: "google-oauth-client-secret",
    severity: "critical",
    category: "credential",
    description: "Google OAuth client secret embedded in build output",
    why: "Client secrets are meant to stay confidential; combined with the client id they allow token impersonation flows.",
    fix: "Reset the client secret in Google Cloud Console and move OAuth token exchange to your backend.",
    reference: "https://developers.google.com/identity/protocols/oauth2",
    pattern: /\b(GOCSPX-[A-Za-z0-9_-]{28,})\b/,
  },
  {
    id: "azure-storage-account-key",
    severity: "critical",
    category: "credential",
    description: "Azure Storage account key embedded in build output",
    why: "The account key grants full control of the storage account — blobs, queues, tables and file shares — without any further authentication.",
    fix: "Regenerate the key in the Azure portal, prefer SAS tokens or managed identity, and keep storage access server-side.",
    reference: "https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage",
    // 64-byte keys render as exactly 88 base64 chars ending in '=='
    pattern: /AccountKey=[A-Za-z0-9+/]{86}==/,
  },
  {
    id: "alibaba-accesskey-id",
    severity: "critical",
    category: "credential",
    description: "Alibaba Cloud access key id embedded in build output",
    why: "An AccessKey id alone does not authenticate, but paired with a leaked AccessKey secret it grants full programmatic access to the linked Alibaba Cloud account.",
    fix: "Rotate the key pair in the RAM console and remove it from source; serve cloud credentials from your backend instead of bundling them.",
    reference: "https://help.aliyun.com/zh/ram/user-guide/create-an-accesskeypair",
    pattern: /\bLTAI[0-9A-Za-z]{12,20}\b/,
  },
  {
    id: "gitlab-pat",
    severity: "critical",
    category: "credential",
    description: "GitLab personal access token embedded in build output",
    why: "Depending on its scopes a GitLab PAT can read private repositories, publish packages or administer the instance — a direct supply-chain lever.",
    fix: "Revoke the token in GitLab user settings, audit recent usage, and reissue with minimal scopes stored in CI variables.",
    reference: "https://docs.gitlab.com/user/profile/personal_access_tokens/",
    pattern: /\bglpat-[0-9A-Za-z_-]{20,}\b/,
  },

  {
    id: "google-api-key",
    severity: "high",
    category: "credential",
    description: "Google API key embedded in build output",
    why: "Depending on API restrictions an exposed key can be abused to bill quota usage or reach otherwise restricted Google Cloud services.",
    fix: "Restrict the key by HTTP referrer / IP inside Google Cloud Console, or proxy calls that need elevated APIs through your backend.",
    reference: "https://cloud.google.com/docs/authentication/api-keys",
    pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/,
  },
  {
    id: "openai-secret-key",
    severity: "high",
    category: "credential",
    description: "OpenAI secret key embedded in build output",
    why: "The key authorizes paid model usage against your organization until revoked — direct financial abuse surface.",
    fix: "Rotate the key in the OpenAI dashboard and route inference calls through your backend with spend limits.",
    reference: "https://platform.openai.com/docs/api-reference/authentication",
    // keep clear of stripe's sk_live_/sk_test_ prefixes and anthropic's sk-ant-
    pattern: /\bsk-(?!live_|test_|ant-)[A-Za-z0-9_-]{40,}\b/,
  },
  {
    id: "anthropic-api-key",
    severity: "high",
    category: "credential",
    description: "Anthropic API key embedded in build output",
    why: "The key authorizes paid model usage against your Anthropic organization until revoked — direct financial abuse surface.",
    fix: "Rotate the key in the Anthropic console and route inference calls through your backend with spend limits.",
    reference: "https://docs.anthropic.com/en/api/getting-started",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{24,}\b/,
  },

  {
    id: "slack-token",
    severity: "high",
    category: "credential",
    description: "Slack token embedded in build output",
    why: "Bot and user tokens can read conversations, post as your workspace and exfiltrate files within granted scopes.",
    fix: "Deactivate the token in the Slack app management console and reissue with narrowly scoped permissions.",
    reference: "https://api.slack.com/authentication/token-types",
    pattern: /\b(xox[abprs]-[0-9A-Za-z_-]{10,250})\b/,
  },
  {
    id: "sendgrid-api-key",
    severity: "high",
    category: "credential",
    description: "SendGrid API key embedded in build output",
    why: "Mail-sending rights let attackers phish from your verified sender domain, torching deliverability and reputation.",
    fix: "Delete the key in SendGrid settings, review sent activity for abuse, and relay transactional mail from your backend.",
    reference: "https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys",
    pattern: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/,
  },
  {
    id: "twilio-api-key",
    severity: "high",
    category: "credential",
    description: "Twilio-style API key embedded in build output",
    why: "Twilio API keys authenticate REST requests for messaging and voice — billable services abusable at scale.",
    fix: "Confirm the value against your Twilio console; if genuine, delete the key and reissue, keeping it server-side only.",
    reference: "https://www.twilio.com/docs/iam/keys/api-key",
    pattern: /\b(SK[0-9a-fA-F]{32})\b/,
  },
  {
    id: "shopify-custom-app-token",
    severity: "high",
    category: "credential",
    description: "Shopify custom app access token embedded in build output",
    why: "Custom app tokens bypass storefront authorization and can read store data within their scopes.",
    fix: "Rotate the token in the Shopify admin and proxy Admin API calls through your backend.",
    reference: "https://shopify.dev/docs/apps/auth",
    pattern: /\b(shpat_[a-fA-F0-9]{32})\b/,
  },
  {
    id: "telegram-bot-token",
    severity: "high",
    category: "credential",
    description: "Telegram bot token embedded in build output",
    why: "A bot token lets anyone drive the bot over the Bot API — reading messages sent to it, posting as it and exfiltrating files.",
    fix: "Revoke the token via @BotFather (/revoke) and deliver it to the bot process at runtime instead of bundling it.",
    reference: "https://core.telegram.org/bots/api",
    // the fixed 'AA' marker opens the 35-char secret section of every token
    pattern: /\b[0-9]{8,10}:AA[A-Za-z0-9_-]{33}\b/,
  },
  {
    id: "discord-bot-token",
    severity: "high",
    category: "credential",
    description: "Discord bot token embedded in build output",
    why: "Bot tokens authenticate the full Discord gateway and REST API — an attacker can read channels, send messages as the bot and dump guild data.",
    fix: "Reset the token in the Discord developer portal, enable privileged-intent allowlists, and load it from server-side config.",
    reference: "https://discord.com/developers/docs/reference#authentication",
    // base64 snowflake.id.timestamp, three segments with fixed lengths
    pattern: /\b[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b/,
  },
  {
    id: "digitalocean-token",
    severity: "high",
    category: "credential",
    description: "DigitalOcean personal access token embedded in build output",
    why: "A full-scope token manages droplets, databases and object storage — billable infrastructure an attacker can mine or destroy.",
    fix: "Revoke the token in the DigitalOcean API settings and scope replacements to custom token scopes stored in CI variables.",
    reference: "https://docs.digitalocean.com/reference/api/rest-api/",
    pattern: /\bdop_v1_[a-f0-9]{64}\b/,
  },
  {
    id: "basic-auth-url",
    severity: "high",
    category: "credential",
    description: "URL contains inline basic-auth credentials",
    why: "Usernames and passwords embedded in URLs leak into logs, referrers and browser history — anyone with the bundle owns the pair.",
    fix: "Move HTTP basic authentication out of URLs into server-side configuration or token exchange.",
    reference:
      "https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication#basic_authentication_scheme",
    pattern: /\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s/:@]+:[^\s/:@]+@/,
  },

  {
    id: "hardcoded-jwt",
    severity: "medium",
    category: "credential",
    description: "JSON Web Token embedded in build output",
    why: "Bundled JWTs are long-lived by accident: they decode offline and remain valid until expiry regardless of frontend logout.",
    fix: "Inspect the payload, shorten lifetimes, and deliver tokens at runtime from your identity flow instead of baking them in.",
    reference: "https://datatracker.ietf.org/doc/html/rfc7519",
    pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/,
  },
  {
    id: "firebase-database-url",
    severity: "medium",
    category: "exposure",
    description: "Firebase Realtime Database URL referenced in build output",
    why: "Exposing the database URL invites probing; whether data is actually readable depends on security rules that commonly drift open.",
    fix: "Verify the project’s database rules deny unauthenticated reads/writes and proxy database access via backend where possible.",
    reference: "https://firebase.google.com/docs/database/security",
    pattern: /https:\/\/[a-z0-9-]+\.firebaseio\.com|https:\/\/[a-z0-9-]+\.firebasedatabase\.app/i,
  },
  {
    id: "huggingface-token",
    severity: "medium",
    category: "credential",
    description: "Hugging Face access token embedded in build output",
    why: "Tokens can read private models and datasets, and fine-grained write tokens can publish artifacts under your organization's name.",
    fix: "Revoke the token in your Hugging Face settings, prefer fine-grained read-only tokens, and inject them at runtime.",
    reference: "https://huggingface.co/docs/hub/security-tokens",
    pattern: /\bhf_[A-Za-z0-9]{34,}\b/,
  },
  {
    id: "internal-network-url",
    severity: "low",
    category: "exposure",
    description: "Private/internal network URL referenced in build output",
    why: "Internal hostnames and RFC1918 addresses in shipped assets hand attackers a map of your infrastructure topology.",
    fix: "Strip development endpoints from production config and drive environment-specific values at deploy time.",
    reference: "https://datatracker.ietf.org/doc/html/rfc1918",
    pattern:
      /https?:\/\/(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|[\w-]+\.(?:local|internal|intranet))(?:[/:"']|$)/,
  },
];

export function getRule(id: string): Rule | undefined {
  return RULES.find((rule) => rule.id === id);
}
