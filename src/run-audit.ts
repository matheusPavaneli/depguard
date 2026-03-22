import { mergeConfig, loadConfig, DEFAULT_CONFIG } from "./config.js";
import { predictAlert } from "./metrics.js";
import { loadAllMetadata } from "./registry.js";
import { attachOsvToMetadata } from "./osv.js";
import { evaluatePackageRisk, worstScore } from "./risk-engine.js";
import { resolvePackages } from "./resolve-deps.js";
import type { DepGuardConfig, PackageRiskResult } from "./types.js";

export interface AuditRunOptions {
  cwd: string;
  config?: DepGuardConfig;
  onProgress?: (done: number, total: number) => void;
}

export interface AuditRunResult {
  results: PackageRiskResult[];
  minScore: number;
  config: DepGuardConfig;
  strictFailed: boolean;
}

export async function runAudit(opts: AuditRunOptions): Promise<AuditRunResult> {
  const cfg = mergeConfig(opts.config ?? loadConfig(opts.cwd), {});

  const blockThreshold = cfg.blockThreshold ?? DEFAULT_CONFIG.blockThreshold;
  const warnThreshold = cfg.warnThreshold ?? DEFAULT_CONFIG.warnThreshold;
  const concurrency = cfg.concurrency ?? DEFAULT_CONFIG.concurrency;
  const osvConcurrency = cfg.osvConcurrency ?? DEFAULT_CONFIG.osvConcurrency;
  const includeDev = cfg.includeDevDependencies ?? DEFAULT_CONFIG.includeDevDependencies;
  const includeOptional = cfg.includeOptional ?? DEFAULT_CONFIG.includeOptional;
  const includePeer = cfg.includePeer ?? DEFAULT_CONFIG.includePeer;
  const includeOsv = cfg.includeOsv ?? DEFAULT_CONFIG.includeOsv;
  const trusted = new Set(
    (cfg.trustedPackages ?? []).map((s) => s.toLowerCase()),
  );
  const typosquatThreshold = cfg.typosquatThreshold ?? DEFAULT_CONFIG.typosquatThreshold;

  const packages = await resolvePackages({
    cwd: opts.cwd,
    includeDev,
    includeOptional,
    includePeer,
  });

  const total = packages.length;
  const metas = await loadAllMetadata(packages, {
    concurrency,
    signal: undefined,
  });

  if (includeOsv) {
    await attachOsvToMetadata(metas, {
      concurrency: osvConcurrency,
      signal: undefined,
    });
  }

  const results: PackageRiskResult[] = [];
  for (let i = 0; i < metas.length; i++) {
    const meta = metas[i]!;
    const trustedPkg = trusted.has(meta.name.toLowerCase());
    results.push(evaluatePackageRisk(meta, { trusted: trustedPkg, typosquatThreshold }));
    opts.onProgress?.(i + 1, total);
  }

  results.sort((a, b) => a.score - b.score);
  const minScore = worstScore(results);
  const strictFailed =
    Boolean(cfg.strict) && results.some((r) => predictAlert(r, warnThreshold));

  return {
    results,
    minScore,
    config: { ...cfg, blockThreshold, warnThreshold },
    strictFailed,
  };
}

export function shouldBlockInstall(
  results: PackageRiskResult[],
  blockThreshold: number,
): boolean {
  return results.some((r) => r.score < blockThreshold);
}
