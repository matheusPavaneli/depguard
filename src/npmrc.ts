import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Parses a raw .npmrc file content into key-value pairs.
 * Handles comments (#, ;) and ignores blank lines.
 */
function parseNpmrcContent(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const raw of content.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const eqIdx = line.indexOf("=");
    if (eqIdx < 0) continue;
    const key = line.slice(0, eqIdx).trim();
    const val = line.slice(eqIdx + 1).trim();
    if (key) result[key] = val;
  }
  return result;
}

/** Expands ${VAR} environment variable references in a string. */
function expandEnv(val: string): string {
  return val.replace(/\$\{([^}]+)\}/g, (_, name: string) => process.env[name] ?? "");
}

/**
 * Reads one or more .npmrc file paths and returns the merged set of
 * private scopes (e.g. "@mycompany") found via `@scope:registry=URL` entries.
 *
 * Local .npmrc takes precedence over global ~/.npmrc for duplicate scopes.
 */
function collectPrivateScopesFromFiles(paths: string[]): Set<string> {
  const scopes = new Set<string>();
  for (const p of paths) {
    if (!existsSync(p)) continue;
    try {
      const entries = parseNpmrcContent(readFileSync(p, "utf8"));
      for (const [key, val] of Object.entries(entries)) {
        // Match @scope:registry=URL — the URL must differ from the default npm registry
        if (!key.endsWith(":registry")) continue;
        const scope = key.slice(0, -":registry".length);
        if (!scope.startsWith("@")) continue;
        const registryUrl = expandEnv(val);
        if (registryUrl && !registryUrl.includes("registry.npmjs.org")) {
          scopes.add(scope.toLowerCase());
        }
      }
    } catch {
      // Silently ignore unreadable .npmrc files
    }
  }
  return scopes;
}

/**
 * Loads private scopes from `.npmrc` files in the given project directory
 * and the global `~/.npmrc`. Returns a Set of lowercase scope strings
 * (e.g. `Set { "@mycompany", "@internal" }`).
 */
export function loadPrivateScopesFromNpmrc(cwd: string): Set<string> {
  return collectPrivateScopesFromFiles([
    join(cwd, ".npmrc"),
    join(homedir(), ".npmrc"),
  ]);
}

/**
 * Returns true if the given package name belongs to one of the provided
 * private scopes.
 */
export function isPrivateScope(name: string, privateScopes: Set<string>): boolean {
  if (privateScopes.size === 0) return false;
  if (!name.startsWith("@")) return false;
  const scope = name.split("/")[0]!.toLowerCase();
  return privateScopes.has(scope);
}
