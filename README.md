# distguard

> Security gate for your build output.
> Find leaked credentials and exposed source maps in `dist/` **before you ship**, not after someone else finds them.

Work in progress — engine and CLI skeleton are functional, rule catalog is being expanded.

```bash
npx distguard scan ./dist          # risk-ranked report
npx distguard ./dist --json        # machine-readable for CI
npx distguard ./dist --fail-on high   # red-light the build on high+ findings
```

Full documentation, rule catalog (RULES.md) and comparison land with v0.1.

MIT © lvyanyan
