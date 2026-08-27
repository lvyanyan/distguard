/**
 * ESLint `codeframe`-style excerpt with the matched secret masked in place:
 * the source line shows `****` over the span, carets underline its width.
 * Pure and exported for unit testing.
 */
export interface CodeFrame {
  /** Source line with the secret span replaced by asterisks. */
  maskedSource: string;
  /** Gutter/caret lines that go right below the source line. */
  carets: string;
}

export function buildCodeFrame(lineText: string, column: number, length: number): CodeFrame {
  const col = Math.max(1, column); // 1-based
  const start = col - 1;
  const end = Math.min(lineText.length, start + length);

  const masked =
    lineText.slice(0, start) + "*".repeat(Math.max(0, end - start)) + lineText.slice(end);

  const gutter = " ".repeat(String(col).length);
  const carets = `${gutter} ${"^".repeat(Math.max(1, Math.min(length, 60)))}`;

  return { maskedSource: masked, carets };
}
