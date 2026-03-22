import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import type { DepGuardConfig } from "./types.js";

const CONFIG_NAMES = ["guard.config.json", "depguard.config.json"];

export const DEFAULT_CONFIG: Required<
  Pick<
    DepGuardConfig,
    | "blockThreshold"
    | "warnThreshold"
    | "includeDevDependencies"
    | "includeOptional"
    | "includePeer"
    | "concurrency"
    | "osvConcurrency"
    | "includeOsv"
    | "typosquatThreshold"
  >
> & { strict: boolean } = {
  blockThreshold: 40,
  warnThreshold: 58,
  strict: false,
  includeDevDependencies: true,
  includeOptional: true,
  includePeer: false,
  concurrency: 10,
  osvConcurrency: 8,
  includeOsv: true,
  typosquatThreshold: 0.82,
};

function validateConfig(cfg: DepGuardConfig, filePath: string): DepGuardConfig {
  const out: DepGuardConfig = { ...cfg };

  for (const key of ["blockThreshold", "warnThreshold"] as const) {
    const val = cfg[key];
    if (val !== undefined) {
      if (typeof val !== "number" || val < 0 || val > 100) {
        console.warn(
          `[depguard] config warning in ${filePath}: "${key}" must be a number between 0 and 100 (got ${JSON.stringify(val)}). Using default.`,
        );
        delete out[key];
      }
    }
  }

  for (const key of ["concurrency", "osvConcurrency"] as const) {
    const val = cfg[key];
    if (val !== undefined) {
      if (typeof val !== "number" || val < 1 || !Number.isInteger(val)) {
        console.warn(
          `[depguard] config warning in ${filePath}: "${key}" must be a positive integer (got ${JSON.stringify(val)}). Using default.`,
        );
        delete out[key];
      }
    }
  }

  if (cfg.typosquatThreshold !== undefined) {
    const val = cfg.typosquatThreshold;
    if (typeof val !== "number" || val <= 0 || val > 1) {
      console.warn(
        `[depguard] config warning in ${filePath}: "typosquatThreshold" must be a number between 0 and 1 (got ${JSON.stringify(val)}). Using default.`,
      );
      delete out.typosquatThreshold;
    }
  }

  return out;
}

export function loadConfig(cwd: string): DepGuardConfig {
  for (const name of CONFIG_NAMES) {
    const p = join(cwd, name);
    if (!existsSync(p)) continue;
    try {
      const raw = readFileSync(p, "utf8");
      const parsed = JSON.parse(raw) as DepGuardConfig;
      return validateConfig(parsed, p);
    } catch (err) {
      console.warn(
        `[depguard] failed to parse config file "${p}": ${err instanceof Error ? err.message : String(err)}. Config will be ignored.`,
      );
      return {};
    }
  }
  return {};
}

export function mergeConfig(
  file: DepGuardConfig,
  overrides: DepGuardConfig,
): DepGuardConfig {
  return { ...file, ...overrides };
}
