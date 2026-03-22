import type { PackageRiskResult } from "./types.js";

export function predictAlert(
  result: PackageRiskResult,
  warnThreshold: number,
): boolean {
  if (result.score < warnThreshold) return true;
  return result.flags.some((f) => f.id === "osv-known-vulnerability");
}

export interface ConfusionCounts {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}

export function precisionRecallF1(counts: ConfusionCounts): {
  precision: number;
  recall: number;
  f1: number;
} {
  const { tp, fp, fn } = counts;
  const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
  const f1 =
    precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { precision, recall, f1 };
}
