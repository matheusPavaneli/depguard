import { writeFileSync } from "node:fs";
import { DEFAULT_CONFIG } from "./config.js";
import type { DepGuardConfig, PackageRiskResult } from "./types.js";
import { readDepguardVersion } from "./version.js";

export interface FeedbackPayload {
  depguardVersion: string;
  generatedAt: string;
  projectRoot: string;
  minScore: number;
  warnThreshold: number;
  blockThreshold: number;
  includeOsv: boolean;
  packages: Array<{
    name: string;
    version: string;
    score: number;
    flagIds: string[];
    severities: string[];
  }>;
}

export function buildFeedbackPayload(
  cwd: string,
  results: PackageRiskResult[],
  minScore: number,
  cfg: DepGuardConfig,
): FeedbackPayload {
  const warnThreshold = cfg.warnThreshold ?? DEFAULT_CONFIG.warnThreshold;
  const blockThreshold = cfg.blockThreshold ?? DEFAULT_CONFIG.blockThreshold;
  const includeOsv = cfg.includeOsv !== false;

  return {
    depguardVersion: readDepguardVersion(),
    generatedAt: new Date().toISOString(),
    projectRoot: cwd,
    minScore,
    warnThreshold,
    blockThreshold,
    includeOsv,
    packages: results.map((r) => ({
      name: r.name,
      version: r.version,
      score: r.score,
      flagIds: r.flags.map((f) => f.id),
      severities: r.flags.map((f) => f.severity),
    })),
  };
}

export function writeFeedbackFile(path: string, payload: FeedbackPayload): void {
  writeFileSync(path, JSON.stringify(payload, null, 2), "utf8");
}
