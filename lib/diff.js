"use strict";
// Terminal rendering helpers — the two trickiest pure algorithms in the CLI, so
// they get their own tested module:
//  frameDiff: line-level reconciler — during streaming only the rows that changed
//             are rewritten, so a growing reply emits ~2 line updates, not a full redraw.
//  wordHi:    word-level intra-line diff — highlight exactly which words changed
//             between two lines (GitHub-style), instead of a flat red/green pair.
const DEFAULT_COLOR = process.stdout.isTTY && !process.env.NO_COLOR;

function frameDiff(prev, next, ESC) {
  if (!prev || prev.length !== next.length) {
    let s = ESC + "[H";
    for (let i = 0; i < next.length; i++) s += next[i] + ESC + "[K" + (i < next.length - 1 ? "\r\n" : "");
    return s + ESC + "[J";
  }
  let s = "";
  for (let i = 0; i < next.length; i++) if (next[i] !== prev[i]) s += ESC + "[" + (i + 1) + ";1H" + next[i] + ESC + "[K";
  return s;
}
function diffTokens(s) { return String(s).match(/\s+|[A-Za-z0-9_]+|[^\sA-Za-z0-9_]/g) || []; }
function wordHi(a, b, useColor) {
  if (useColor === undefined) useColor = DEFAULT_COLOR;
  if (!useColor) return [a, b];
  const at = diffTokens(a), bt = diffTokens(b), n = at.length, m = bt.length;
  const dp = []; for (let i = 0; i <= n; i++) dp.push(new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = at[i] === bt[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const af = new Array(n).fill(true), bf = new Array(m).fill(true); // true = carried over (common)
  let i = 0, j = 0;
  while (i < n && j < m) { if (at[i] === bt[j]) { i++; j++; } else if (dp[i + 1][j] >= dp[i][j + 1]) { af[i++] = false; } else { bf[j++] = false; } }
  while (i < n) af[i++] = false; while (j < m) bf[j++] = false;
  const build = (toks, flags, common, changed) => { let s = ""; for (let k = 0; k < toks.length; k++) s += "\x1b[0m" + (flags[k] ? common : changed) + toks[k]; return s + "\x1b[0m"; };
  return [build(at, af, "\x1b[2;31m", "\x1b[1;4;31m"), build(bt, bf, "\x1b[2;32m", "\x1b[1;4;32m")]; // dim=carried, bold+underline=changed
}
module.exports = { frameDiff, diffTokens, wordHi };
