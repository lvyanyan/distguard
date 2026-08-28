# distguard

[![test](https://github.com/lvyanyan/distguard/actions/workflows/ci.yml/badge.svg)](https://github.com/lvyanyan/distguard/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/distguard.svg)](https://www.npmjs.com/package/distguard)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

> **Security gate for your build output.**
> Find leaked credentials and exposed source maps in `dist/` **before you ship** — not after someone else finds them.

Your SPA ships every byte of JavaScript to every visitor. Whatever secrets sit in your source end up in the bundle — [a scan of 5 million apps found 42k+ leaked tokens](https://www.intruder.io/research/secrets-detection-javascript). distguard is the pre-flight check that stops them at build time.

```bash
npx distguard ./dist                 # risk-ranked terminal report
npx distguard ./dist --json          # machine-readable for CI
npx distguard ./dist --fail-on high  # red-light the pipeline on high+ findings
```

<p align="center">
  <img src=".github/assets/demo.gif" alt="distguard scanning a demo build output — 9 findings across 4 severity tiers, exit code 1" width="720">
</p>

## What it detects

26 rules across three severity tiers — full catalog with remediation guidance in [RULES.md](./RULES.md):

| tier | examples |
| --- | --- |
| **critical** | AWS / Alibaba Cloud access keys · Azure storage account keys · Stripe live secret keys · private key blocks · GitHub / npm / GitLab / GCP-OAuth tokens |
| **high** | Google / OpenAI / Anthropic API keys · Slack / Telegram / Discord tokens · SendGrid / Twilio / Shopify / DigitalOcean credentials · inline basic-auth URLs |
| **medium / low** | hardcoded JWTs · Hugging Face tokens · Firebase database URLs · internal network addresses · restorable & bare source maps |

Every finding is **redacted**, anchored to `file:line:column` with a masked code frame, and explained: *why it's dangerous → how to fix it → authoritative reference*.

## Why distguard

- ** CI-first**: meaningful exit codes (`0` clean · `1` findings ≥ threshold · `2` runtime error) and JSON output make it a drop-in pipeline gate
- **low noise by design**: vendor documentation samples are whitelisted, formats strictly validated, duplicates collapsed per file
- **zero-dependency mindset**: a single tiny runtime dep (arg parser); a security tool should not widen your attack surface to audit you
- **framework agnostic**: scans whatever folder you point it at

## How it compares

| tool | lane | notes |
| --- | --- | --- |
| gitleaks | git repositories (source) | complementary — run both |
| trufflehog | git history / many sources | same lane as gitleaks |
| mapxtractor | offensive recon (hunters) | extracts, doesn't gate builds |
| Jsmon | commercial SaaS monitoring | paid, closed |
| **distguard** | **built artifacts, free, CI gate** | this gap |

## Configure

Drop a `.distguardrc.json` next to where you run it:

```json
{
  "allowlist": ["vendor/", "test/fixtures/"],
  "ignoreRules": ["internal-network-url"]
}
```

## Roadmap

SRI integrity checks · security header audit · SARIF output for GitHub Code Scanning · CSP generation from build output.

## Development

```bash
pnpm install
pnpm test          # vitest suite
pnpm lint          # oxlint + oxfmt
pnpm rules:doc     # regenerate RULES.md from rule metadata
pnpm build         # tsdown
```

Fixture policy: credential values in tests are assembled at runtime from fragments so this repository never contains byte-level lookalike secrets.

MIT © [lvyanyan](https://github.com/lvyanyan)
