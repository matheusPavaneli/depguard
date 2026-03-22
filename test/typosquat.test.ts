import { describe, expect, it } from "vitest";
import {
  findTyposquatTarget,
  levenshtein,
  normalizedSimilarity,
} from "../src/typosquat.js";

const popular = ["lodash", "express", "react"];

describe("levenshtein / normalizedSimilarity", () => {
  it("known edit distance", () => {
    expect(levenshtein("kitten", "sitting")).toBe(3);
  });

  it("similarity 1 for equal names (case-insensitive)", () => {
    expect(normalizedSimilarity("React", "react")).toBe(1);
  });
});

describe("findTyposquatTarget", () => {
  it("does not flag canonical package name", () => {
    expect(findTyposquatTarget("lodash", popular)).toBeNull();
  });

  it("flags lodash typo", () => {
    const m = findTyposquatTarget("lodas", popular, 0.75);
    expect(m).not.toBeNull();
    expect(m!.canonical).toBe("lodash");
  });

  it("flags express typo", () => {
    const m = findTyposquatTarget("expres", popular, 0.75);
    expect(m).not.toBeNull();
    expect(m!.canonical).toBe("express");
  });
});
