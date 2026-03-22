import pLimit from "p-limit";
import type { OsvVulnSummary, PackageMetadata } from "./types.js";

const OSV_QUERY = "https://api.osv.dev/v1/query";
const REQUEST_TIMEOUT_MS = 10_000;
const MAX_RETRIES = 3;

export interface OsvQueryResponse {
  vulns?: Array<{ id: string; summary?: string }>;
}

async function fetchOsvWithRetry(
  body: string,
  signal: AbortSignal | undefined,
  retries = MAX_RETRIES,
): Promise<Response> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    signal?.addEventListener("abort", () => controller.abort(), { once: true });

    try {
      const res = await fetch(OSV_QUERY, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json" },
        body,
        signal: controller.signal,
      });
      clearTimeout(timer);
      return res;
    } catch (err) {
      clearTimeout(timer);
      if (signal?.aborted) throw err;
      if (attempt === retries) throw err;
      await new Promise((r) => setTimeout(r, 200 * 2 ** (attempt - 1)));
    }
  }
  throw new Error("fetchOsvWithRetry: exhausted retries");
}

export async function queryOsvForPackage(
  name: string,
  version: string,
  signal?: AbortSignal,
): Promise<OsvVulnSummary[]> {
  try {
    const body = JSON.stringify({ package: { name, ecosystem: "npm" }, version });
    const res = await fetchOsvWithRetry(body, signal);
    if (!res.ok) return [];
    const data = (await res.json()) as OsvQueryResponse;
    const vulns = data.vulns;
    if (!Array.isArray(vulns)) return [];
    return vulns.map((v) => ({ id: v.id, summary: v.summary }));
  } catch {
    return [];
  }
}

export async function attachOsvToMetadata(
  metas: PackageMetadata[],
  opts: { concurrency?: number; signal?: AbortSignal },
): Promise<void> {
  const limit = pLimit(Math.max(1, opts.concurrency ?? 8));
  await Promise.all(
    metas.map((meta, i) =>
      limit(async () => {
        if (meta.fetchError) return;
        const vulns = await queryOsvForPackage(meta.name, meta.version, opts.signal);
        metas[i]!.osvVulns = vulns;
      }),
    ),
  );
}
