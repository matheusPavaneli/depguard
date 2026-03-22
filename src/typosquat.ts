import { POPULAR_PACKAGE_NAMES_RAW } from "./data/popular-packages.js";

let cachedPopular: string[] | null = null;

export function loadPopularPackages(): string[] {
  if (cachedPopular) return cachedPopular;
  const arr = POPULAR_PACKAGE_NAMES_RAW;
  cachedPopular = [...new Set(arr.map((s) => s.trim().toLowerCase()).filter(Boolean))];
  return cachedPopular;
}

export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const row = new Uint32Array(n + 1);
  for (let j = 0; j <= n; j++) row[j] = j;
  for (let i = 1; i <= m; i++) {
    let prev = row[0];
    row[0] = i;
    for (let j = 1; j <= n; j++) {
      const tmp = row[j];
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      row[j] = Math.min(row[j] + 1, row[j - 1] + 1, prev + cost);
      prev = tmp;
    }
  }
  return row[n];
}

export function normalizedSimilarity(a: string, b: string): number {
  const aa = a.toLowerCase();
  const bb = b.toLowerCase();
  if (aa === bb) return 1;
  const dist = levenshtein(aa, bb);
  const maxLen = Math.max(aa.length, bb.length, 1);
  return 1 - dist / maxLen;
}

export interface TyposquatMatch {
  canonical: string;
  similarity: number;
}

const DEFAULT_THRESHOLD = 0.82;

export function findTyposquatTarget(
  packageName: string,
  popularList?: string[],
  threshold = DEFAULT_THRESHOLD,
): TyposquatMatch | null {
  const list = popularList ?? loadPopularPackages();
  const lower = packageName.toLowerCase();
  if (list.includes(lower)) return null;

  let best: TyposquatMatch | null = null;
  for (const canonical of list) {
    if (canonical === lower) continue;
    const sim = normalizedSimilarity(lower, canonical);
    if (sim < threshold) continue;
    if (!best || sim > best.similarity) {
      best = { canonical, similarity: sim };
    }
  }
  if (!best) return null;
  if (best.canonical === lower) return null;
  return best;
}
