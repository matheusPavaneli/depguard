import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { POPULAR_PACKAGE_NAMES_RAW } from "../src/data/popular-packages.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outFile = join(root, "src", "data", "popular-packages.ts");

const KEYWORDS = [
  "web",
  "api",
  "cli",
  "util",
  "data",
  "http",
  "json",
  "tool",
  "react",
  "vue",
  "test",
  "lint",
  "build",
  "dom",
  "node",
  "css",
  "auth",
  "db",
  "log",
];

async function searchNpm(keyword: string, size: number): Promise<string[]> {
  const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(keyword)}&size=${size}`;
  const res = await fetch(url);
  if (!res.ok) return [];
  const data = (await res.json()) as {
    objects?: Array<{ package: { name: string } }>;
  };
  const names: string[] = [];
  for (const o of data.objects ?? []) {
    const n = o.package?.name;
    if (typeof n === "string" && n.length) names.push(n.toLowerCase());
  }
  return names;
}

async function main() {
  const names = new Set<string>(POPULAR_PACKAGE_NAMES_RAW.map((s) => s.toLowerCase()));

  for (const k of KEYWORDS) {
    const found = await searchNpm(k, 80);
    for (const n of found) names.add(n);
    await new Promise((r) => setTimeout(r, 120));
  }

  const sorted = [...names].sort((a, b) => a.localeCompare(b));
  const lines = sorted.map((s) => JSON.stringify(s));
  const body = `export const POPULAR_PACKAGE_NAMES_RAW: string[] = [\n  ${lines.join(",\n  ")},\n];
`;

  writeFileSync(outFile, body, "utf8");
  console.log(`Wrote ${outFile} (${sorted.length} names).`);
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
