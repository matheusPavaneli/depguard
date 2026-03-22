import { readFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export function readDepguardVersion(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [join(here, "..", "package.json"), join(here, "..", "..", "package.json")];
  for (const p of candidates) {
    if (!existsSync(p)) continue;
    try {
      const j = JSON.parse(readFileSync(p, "utf8")) as { name?: string; version?: string };
      if (
        typeof j.version === "string" &&
        j.name &&
        (j.name === "depguard" || j.name.endsWith("/depguard"))
      )
        return j.version;
    } catch {}
  }
  return "0.0.0";
}
