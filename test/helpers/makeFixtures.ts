import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Builds the scanner fixtures as a temporary directory AT RUNTIME instead of
 * committing lookalike credentials to the repository — GitHub push protection
 * and every other secret scanner cannot distinguish our fabricated values
 * from real ones by structure alone, so the safest fixture is one that never
 * exists on disk until tests run.
 *
 * All credential bytes are assembled here from concatenated fragments.
 */
export function makeFixtureDist(): string {
  const root = mkdtempSync(join(tmpdir(), "distguard-fixtures-"));

  const awsSample = ["AKIA", "IOSFODNN7", "EXAMPLE"].join(""); // AWS docs example
  const awsFabricated = "AKIA" + "ABCD" + "EFGH" + "IJKL" + "MNOP";
  const stripeLive = "sk_live_" + "a".repeat(32);
  const googleKey = "AIza" + "Sy" + "B".repeat(33);
  const pemHeader = "-----BEGIN " + "RSA PRIVATE KEY-----";

  const appJs = [
    `// runtime-synthesized fixture`,
    `const whitelistedAwsSample = ${JSON.stringify(awsSample)}`,
    `const fabricatedAwsKey = ${JSON.stringify(awsFabricated)}`,
    `const fabricatedStripeLiveKey = ${JSON.stringify(stripeLive)}`,
    `const privateKeyHeader = ${JSON.stringify(pemHeader)}`,
  ].join("\n");

  const chunkJs = `// runtime-synthesized fixture\nconst googleApiKey = ${JSON.stringify(googleKey)}\n`;

  // canonical jwt.io example token, assembled from fragments
  const jwt =
    "eyJhbGciOiJIUzI1NiJ9." +
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
    "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
  const miscJs = [
    `// runtime-synthesized fixture`,
    `const sessionJwt = ${JSON.stringify(jwt)}`,
    `const adminPanelUrl = 'http://192.168.10.24:8080/admin'`,
    `const legacyFirebaseUrl = 'https://my-prod-app.firebaseio.com/.json'`,
  ].join("\n");

  const restorableMap = JSON.stringify({
    version: 3,
    file: "app.js",
    sources: ["../src/app.ts"],
    sourcesContent: ["export const greeting = 'hello from original source'\n"],
    names: [],
    mappings: "AAAA",
  });
  const bareMap = JSON.stringify({
    version: 3,
    file: "bare.js",
    sources: ["webpack://bare/./x.js"],
  });

  writeFileSync(join(root, "app.js"), appJs);
  writeFileSync(join(root, "chunk.js"), chunkJs);
  writeFileSync(join(root, "misc.js"), miscJs);
  writeFileSync(join(root, "app.js.map"), restorableMap);
  writeFileSync(join(root, "bare.map"), bareMap);

  return root;
}
