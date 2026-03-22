import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import pacote from "pacote";
import type { ResolvedPackage } from "./types.js";

type Json = Record<string, unknown>;

function isRecord(v: unknown): v is Json {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

interface LockDep {
  version?: string;
  dependencies?: Record<string, LockDep>;
}

function walkLockV1V2(deps: Record<string, LockDep> | undefined, out: ResolvedPackage[]) {
  if (!deps) return;
  for (const [name, dep] of Object.entries(deps)) {
    if (dep.version && typeof dep.version === "string") {
      out.push({ name, version: dep.version });
    }
    if (dep.dependencies) walkLockV1V2(dep.dependencies, out);
  }
}

function parseNameFromNodeModulesKey(key: string): string | null {
  if (key === "") return null;
  if (!key.startsWith("node_modules/")) return null;
  const rest = key.slice("node_modules/".length);
  const idx = rest.lastIndexOf("/node_modules/");
  const tail = idx >= 0 ? rest.slice(idx + "/node_modules/".length) : rest;
  return tail || null;
}

function collectFromLockV3(packages: Record<string, Json>): ResolvedPackage[] {
  const out: ResolvedPackage[] = [];
  for (const [key, entry] of Object.entries(packages)) {
    if (!isRecord(entry)) continue;
    const version = entry.version;
    if (typeof version !== "string") continue;
    let name = typeof entry.name === "string" ? entry.name : null;
    if (!name) name = parseNameFromNodeModulesKey(key);
    if (!name) continue;
    out.push({ name, version });
  }
  return out;
}

export function parsePackageLock(lockPath: string): ResolvedPackage[] {
  const raw = readFileSync(lockPath, "utf8");
  const data = JSON.parse(raw) as Json;
  const lv = data.lockfileVersion;
  const num = typeof lv === "number" ? lv : 0;

  if (num >= 3 && isRecord(data.packages)) {
    return collectFromLockV3(data.packages as Record<string, Json>);
  }

  if (isRecord(data.dependencies)) {
    const out: ResolvedPackage[] = [];
    walkLockV1V2(data.dependencies as Record<string, LockDep>, out);
    return out;
  }

  return [];
}

export interface PackageJsonDeps {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}

export function readPackageJson(cwd: string): PackageJsonDeps {
  const p = join(cwd, "package.json");
  const raw = readFileSync(p, "utf8");
  return JSON.parse(raw) as PackageJsonDeps;
}

function uniquePackages(list: ResolvedPackage[]): ResolvedPackage[] {
  const seen = new Set<string>();
  const out: ResolvedPackage[] = [];
  for (const pkg of list) {
    const k = `${pkg.name}@${pkg.version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(pkg);
  }
  return out;
}

export interface ResolveOptions {
  cwd: string;
  includeDev: boolean;
  includeOptional: boolean;
  includePeer: boolean;
}

export async function resolvePackages(opts: ResolveOptions): Promise<ResolvedPackage[]> {
  const { cwd, includeDev, includeOptional, includePeer } = opts;
  const lockPath = join(cwd, "package-lock.json");

  if (existsSync(lockPath)) {
    const fromLock = parsePackageLock(lockPath);
    return uniquePackages(fromLock);
  }

  const pj = readPackageJson(cwd);
  const specs: Array<{ name: string; range: string }> = [];

  const add = (rec?: Record<string, string>) => {
    if (!rec) return;
    for (const [name, range] of Object.entries(rec)) {
      specs.push({ name, range });
    }
  };

  add(pj.dependencies);
  if (includeDev) add(pj.devDependencies);
  if (includeOptional) add(pj.optionalDependencies);
  if (includePeer) add(pj.peerDependencies);

  const resolved: ResolvedPackage[] = [];
  for (const { name, range } of specs) {
    const spec = range.startsWith("workspace:") ? name : `${name}@${range}`;
    try {
      const mani = await pacote.manifest(spec, {
        where: cwd,
        fullMetadata: false,
      });
      const v = mani.version;
      if (typeof v === "string") resolved.push({ name, version: v });
    } catch {
      resolved.push({ name, version: range });
    }
  }

  return uniquePackages(resolved);
}
