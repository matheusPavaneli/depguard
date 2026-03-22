import { describe, expect, it } from "vitest";
import { precisionRecallF1, predictAlert } from "../src/metrics.js";
import type { PackageRiskResult } from "../src/types.js";

function result(score: number, flagIds: string[]): PackageRiskResult {
  return {
    name: "p",
    version: "1.0.0",
    score,
    flags: flagIds.map((id) => ({
      id,
      severity: id === "osv-known-vulnerability" ? ("high" as const) : ("info" as const),
      message: id,
    })),
  };
}

describe("predictAlert", () => {
  it("alerts when score is below threshold", () => {
    expect(predictAlert(result(40, []), 58)).toBe(true);
  });

  it("no alert when score is high and no OSV flag", () => {
    expect(predictAlert(result(90, []), 58)).toBe(false);
  });

  it("alerts on OSV flag even with high score", () => {
    expect(predictAlert(result(85, ["osv-known-vulnerability"]), 58)).toBe(true);
  });
});

describe("precisionRecallF1", () => {
  it("perfect scores for TP=1 FP=0 TN=1 FN=0", () => {
    const m = precisionRecallF1({ tp: 1, fp: 0, tn: 1, fn: 0 });
    expect(m.precision).toBe(1);
    expect(m.recall).toBe(1);
    expect(m.f1).toBe(1);
  });

  it("handles zero division safely", () => {
    const m = precisionRecallF1({ tp: 0, fp: 0, tn: 1, fn: 0 });
    expect(Number.isFinite(m.precision)).toBe(true);
    expect(Number.isFinite(m.recall)).toBe(true);
    expect(Number.isFinite(m.f1)).toBe(true);
  });
});
