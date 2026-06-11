/**
 * Minimal line diff (LCS-based) for config-drift display. Inputs are tiny
 * (one server's pretty-printed config block), so the O(n*m) DP is fine.
 *
 * Output is a unified-style line list:
 *   "- <line>"  removed (present before, gone now)
 *   "+ <line>"  added   (present now, absent before)
 *   "  <line>"  context (unchanged)
 *
 * Coloring is the reporter's job — this module emits plain strings so the
 * diff can ride along in JSON output without ANSI noise.
 */
export function diffLines(before: string[], after: string[]): string[] {
  const n = before.length;
  const m = after.length;

  // lcs[i][j] = length of LCS of before[i..] and after[j..]
  const lcs: number[][] = Array.from({ length: n + 1 }, () =>
    new Array<number>(m + 1).fill(0),
  );
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i][j] =
        before[i] === after[j]
          ? lcs[i + 1][j + 1] + 1
          : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }

  const out: string[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (before[i] === after[j]) {
      out.push(`  ${before[i]}`);
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      out.push(`- ${before[i]}`);
      i++;
    } else {
      out.push(`+ ${after[j]}`);
      j++;
    }
  }
  while (i < n) out.push(`- ${before[i++]}`);
  while (j < m) out.push(`+ ${after[j++]}`);
  return out;
}
