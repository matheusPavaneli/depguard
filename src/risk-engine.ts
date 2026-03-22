import { analyzeLifecycleScripts, hasLifecycleScripts } from "./dangerous-scripts.js";
import { findTyposquatTarget } from "./typosquat.js";
import type { PackageMetadata, PackageRiskResult, RiskFlag } from "./types.js";

const CAP_AGE = 20;
const CAP_DOWNLOADS = 20;
const CAP_MAINTAINERS = 10;
const CAP_SCRIPT_HIGH = 30;
const CAP_SCRIPT_WARN = 16;
const CAP_TYPOSQUAT = 40;
const CAP_OSV = 30;

function daysSince(date: Date): number {
  return (Date.now() - date.getTime()) / (1000 * 60 * 60 * 24);
}

function agePenalty(
  publishedAt: Date | null,
  weeklyDownloads: number | null,
): { penalty: number; flag?: RiskFlag } {
  if (!publishedAt) return { penalty: 0 };
  const days = daysSince(publishedAt);
  if (days >= 30) return { penalty: 0 };

  const base = CAP_AGE * (1 - days / 30);
  let factor = 1;
  if (weeklyDownloads !== null && weeklyDownloads >= 8000) {
    factor = 0.25;
  } else if (weeklyDownloads !== null && weeklyDownloads >= 3000) {
    factor = 0.55;
  }

  const penalty = Math.round(Math.min(CAP_AGE, base) * factor);
  if (penalty <= 0) return { penalty: 0 };
  return {
    penalty,
    flag: {
      id: "young-version",
      severity: days < 7 && factor >= 0.55 ? "warn" : "info",
      message: `Version published ~${Math.max(0, Math.floor(days))} days ago (very new releases increase risk)`,
    },
  };
}

function downloadPenalty(weekly: number | null): { penalty: number; flag?: RiskFlag } {
  if (weekly == null) return { penalty: 0 };
  if (weekly >= 5000) return { penalty: 0 };
  const penalty = Math.round(CAP_DOWNLOADS * (1 - Math.min(weekly, 5000) / 5000));
  if (penalty <= 0) return { penalty: 0 };
  return {
    penalty: Math.min(CAP_DOWNLOADS, penalty),
    flag: {
      id: "low-downloads",
      severity: weekly < 500 ? "warn" : "info",
      message: `Last-week downloads: ${weekly.toLocaleString("en-US")} (low adoption may indicate an obscure package)`,
    },
  };
}

function maintainerPenalty(count: number): { penalty: number; flag?: RiskFlag } {
  if (count !== 1) return { penalty: 0 };
  return {
    penalty: Math.min(CAP_MAINTAINERS, 8),
    flag: {
      id: "single-maintainer",
      severity: "info",
      message: "Only one maintainer listed for this version in the manifest",
    },
  };
}

function osvPenalty(meta: PackageMetadata): { penalty: number; flags: RiskFlag[] } {
  const vulns = meta.osvVulns;
  if (!vulns?.length) return { penalty: 0, flags: [] };
  const penalty = Math.min(CAP_OSV, 10 + vulns.length * 6);
  const ids = vulns
    .slice(0, 6)
    .map((v) => v.id)
    .join(", ");
  const flags: RiskFlag[] = [
    {
      id: "osv-known-vulnerability",
      severity: "high",
      message: `OSV: ${vulns.length} known vulnerability/vulnerabilities for this npm version`,
      detail: ids + (vulns.length > 6 ? "..." : ""),
    },
  ];
  return { penalty, flags };
}

export interface EvaluateOptions {
  trusted: boolean;
  typosquatThreshold?: number;
}

export function evaluatePackageRisk(
  meta: PackageMetadata,
  opts: EvaluateOptions,
): PackageRiskResult {
  const flags: RiskFlag[] = [];
  let score = 100;
  let scriptHigh = 0;
  let scriptWarn = 0;

  if (meta.isPrivate) {
    flags.push({
      id: "private-package",
      severity: "info",
      message: "Package belongs to a private/scoped registry — metadata checks skipped",
    });
  } else if (meta.fetchError) {
    flags.push({
      id: "fetch-error",
      severity: "warn",
      message: meta.fetchError,
    });
    score -= 5;
  }

  const osv = osvPenalty(meta);
  score -= osv.penalty;
  flags.push(...osv.flags);

  if (!opts.trusted) {
    const a = agePenalty(meta.publishedAt, meta.weeklyDownloads);
    score -= a.penalty;
    if (a.flag) flags.push(a.flag);

    const d = downloadPenalty(meta.weeklyDownloads);
    score -= d.penalty;
    if (d.flag) flags.push(d.flag);

    const m = maintainerPenalty(meta.maintainersCount);
    score -= m.penalty;
    if (m.flag) flags.push(m.flag);

    const typo = findTyposquatTarget(meta.name, undefined, opts.typosquatThreshold);
    if (typo) {
      let penalty = 0;
      if (typo.similarity >= 0.92) penalty = CAP_TYPOSQUAT;
      else if (typo.similarity >= 0.85) penalty = 28;
      else penalty = 20;
      penalty = Math.min(CAP_TYPOSQUAT, penalty);
      score -= penalty;
      flags.push({
        id: "typosquatting",
        severity: typo.similarity >= 0.9 ? "high" : "warn",
        message: `Name very similar to "${typo.canonical}" (possible typosquatting)`,
        detail: `Similarity ~${(typo.similarity * 100).toFixed(0)}%`,
      });
    }
  }

  const scriptFindings = analyzeLifecycleScripts(meta.scripts);
  for (const f of scriptFindings) {
    if (f.severity === "high") {
      scriptHigh += 15;
      flags.push({
        id: f.id,
        severity: "high",
        message: f.message,
        detail: `${f.scriptKey}: ${f.snippet ?? ""}`,
      });
    } else {
      scriptWarn += 8;
      flags.push({
        id: f.id,
        severity: "warn",
        message: f.message,
        detail: `${f.scriptKey}: ${f.snippet ?? ""}`,
      });
    }
  }
  score -= Math.min(CAP_SCRIPT_HIGH, scriptHigh);
  score -= Math.min(CAP_SCRIPT_WARN, scriptWarn);

  if (hasLifecycleScripts(meta.scripts) && scriptFindings.length === 0) {
    flags.push({
      id: "lifecycle-present",
      severity: "info",
      message: "Lifecycle scripts (install/postinstall) present — review content on the registry",
    });
    score -= 5;
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  return {
    name: meta.name,
    version: meta.version,
    score,
    flags,
  };
}

export function worstScore(results: PackageRiskResult[]): number {
  if (results.length === 0) return 100;
  return Math.min(...results.map((r) => r.score));
}
