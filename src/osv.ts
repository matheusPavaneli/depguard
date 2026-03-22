import pLimit from "p-limit";
import type { OsvVulnSummary, PackageMetadata } from "./types.js";

const OSV_QUERY = "https://api.osv.dev/v1/query";

export interface OsvQueryResponse {
  vulns?: Array<{ id: string; summary?: string }>;
}

export async function queryOsvForPackage(
  name: string,
  version: string,
  signal?: AbortSignal,
): Promise<OsvVulnSummary[]> {
  try {
    const res = await fetch(OSV_QUERY, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        package: { name, ecosystem: "npm" },
        version,
      }),
      signal,
    });
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
