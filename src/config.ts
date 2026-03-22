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
    | "includeOsv"
  >
> & { strict: boolean } = {
  blockThreshold: 40,
  warnThreshold: 58,
  strict: false,
  includeDevDependencies: true,
  includeOptional: true,
  includePeer: false,
  concurrency: 10,
  includeOsv: true,
};

export function loadConfig(cwd: string): DepGuardConfig {
  for (const name of CONFIG_NAMES) {
    const p = join(cwd, name);
    if (!existsSync(p)) continue;
    try {
      const raw = readFileSync(p, "utf8");
      const parsed = JSON.parse(raw) as DepGuardConfig;
      return { ...parsed };
    } catch {
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
