// Characterization tests for the LCS-based line differ (src/diff.ts).
//
// These lock in the CURRENT observed behavior of diffLines so future
// refactors of the diff algorithm are caught if they change the emitted
// unified-style output. They assert exactly what the implementation
// produces today, including its tie-breaking and ordering conventions —
// they are not a specification of "ideal" diff output.
//
// Output convention (from diff.ts):
//   "  <line>"  context (unchanged)
//   "- <line>"  removed
//   "+ <line>"  added

import { describe, it, expect } from "vitest";
import { diffLines } from "../src/diff.js";

describe("diffLines — degenerate inputs", () => {
  it("two empty inputs produce an empty diff", () => {
    expect(diffLines([], [])).toEqual([]);
  });

  it("identical inputs are all context lines, prefixed with two spaces", () => {
    expect(diffLines(["a", "b"], ["a", "b"])).toEqual(["  a", "  b"]);
  });

  it("adding to an empty 'before' marks every line as added", () => {
    expect(diffLines([], ["x", "y"])).toEqual(["+ x", "+ y"]);
  });

  it("clearing to an empty 'after' marks every line as removed", () => {
    expect(diffLines(["x", "y"], [])).toEqual(["- x", "- y"]);
  });
});

describe("diffLines — single-line edits", () => {
  it("a changed middle line emits the removal before the addition", () => {
    expect(diffLines(["a", "b", "c"], ["a", "B", "c"])).toEqual([
      "  a",
      "- b",
      "+ B",
      "  c",
    ]);
  });

  it("an inserted middle line shows as a single addition with surrounding context", () => {
    expect(diffLines(["a", "c"], ["a", "b", "c"])).toEqual([
      "  a",
      "+ b",
      "  c",
    ]);
  });

  it("a deleted middle line shows as a single removal with surrounding context", () => {
    expect(diffLines(["a", "b", "c"], ["a", "c"])).toEqual([
      "  a",
      "- b",
      "  c",
    ]);
  });
});

describe("diffLines — tie-breaking and structural conventions", () => {
  it("on a pure substitution of one line, deletion is emitted before addition", () => {
    // When LCS lengths tie (lcs[i+1][j] >= lcs[i][j+1]), diff.ts prefers the
    // deletion branch — this pins that bias down.
    expect(diffLines(["a"], ["b"])).toEqual(["- a", "+ b"]);
  });

  it("a reorder is expressed as a delete + retained-context + re-add, not two swaps", () => {
    // ["a","b"] -> ["b","a"] keeps "b" as common context (the LCS) and treats
    // the moved "a" as removed-then-added.
    expect(diffLines(["a", "b"], ["b", "a"])).toEqual(["- a", "  b", "+ a"]);
  });

  it("collapsing a duplicated line keeps the first occurrence and removes the second", () => {
    expect(diffLines(["x", "x"], ["x"])).toEqual(["  x", "- x"]);
  });
});

describe("diffLines — invariants over the emitted output", () => {
  it("context lines exactly reconstruct the longest common subsequence in order", () => {
    const before = ["import a", "const x = 1", "const y = 2", "export x"];
    const after = ["import a", "const x = 1", "const y = 99", "export x"];
    const out = diffLines(before, after);
    const context = out
      .filter((l) => l.startsWith("  "))
      .map((l) => l.slice(2));
    expect(context).toEqual(["import a", "const x = 1", "export x"]);
  });

  it("stripping +/- markers and applying them reconstructs 'before' and 'after'", () => {
    const before = ["a", "b", "c", "d"];
    const after = ["a", "x", "c", "d", "e"];
    const out = diffLines(before, after);
    // 'before' = context + removed lines, in order.
    const reconstructedBefore = out
      .filter((l) => l.startsWith("  ") || l.startsWith("- "))
      .map((l) => l.slice(2));
    // 'after' = context + added lines, in order.
    const reconstructedAfter = out
      .filter((l) => l.startsWith("  ") || l.startsWith("+ "))
      .map((l) => l.slice(2));
    expect(reconstructedBefore).toEqual(before);
    expect(reconstructedAfter).toEqual(after);
  });

  it("every emitted line carries exactly one of the three two-char prefixes", () => {
    const out = diffLines(["a", "b"], ["b", "c"]);
    for (const line of out) {
      expect(line).toMatch(/^(\s\s|- |\+ )/);
    }
  });
});
