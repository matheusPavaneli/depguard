import pLimit from "p-limit";
import type { NpmPackument, PackageMetadata } from "./types.js";

const REGISTRY = "https://registry.npmjs.org";
const DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-week";

export interface FetchRegistryOptions {
  concurrency?: number;
  signal?: AbortSignal;
}

export class RegistryClient {
  private packumentCache = new Map<string, NpmPackument | null | "error">();
  private downloadsCache = new Map<string, number | null | "error">();

  async fetchPackument(name: string, signal?: AbortSignal): Promise<NpmPackument | null> {
    const key = name.toLowerCase();
    if (this.packumentCache.has(key)) {
      const c = this.packumentCache.get(key);
      if (c === "error") return null;
      return c ?? null;
    }
    const url = `${REGISTRY}/${encodeURIComponent(name)}`;
    try {
      const res = await fetch(url, {
        signal,
        headers: { accept: "application/json" },
      });
      if (res.status === 404) {
        this.packumentCache.set(key, null);
        return null;
      }
      if (!res.ok) {
        this.packumentCache.set(key, "error");
        return null;
      }
      const data = (await res.json()) as NpmPackument;
      this.packumentCache.set(key, data);
      return data;
    } catch {
      this.packumentCache.set(key, "error");
      return null;
    }
  }

  async fetchWeeklyDownloads(name: string, signal?: AbortSignal): Promise<number | null> {
    const key = name.toLowerCase();
    if (this.downloadsCache.has(key)) {
      const c = this.downloadsCache.get(key);
      if (c === "error") return null;
      return typeof c === "number" || c === null ? c : null;
    }
    const url = `${DOWNLOADS_API}/${encodeURIComponent(name)}`;
    try {
      const res = await fetch(url, { signal });
      if (!res.ok) {
        this.downloadsCache.set(key, null);
        return null;
      }
      const data = (await res.json()) as { downloads?: number };
      const n = typeof data.downloads === "number" ? data.downloads : null;
      this.downloadsCache.set(key, n);
      return n;
    } catch {
      this.downloadsCache.set(key, "error");
      return null;
    }
  }

  async loadMetadata(pkg: { name: string; version: string }, signal?: AbortSignal): Promise<PackageMetadata> {
    const packument = await this.fetchPackument(pkg.name, signal);
    if (!packument) {
      return {
        name: pkg.name,
        version: pkg.version,
        publishedAt: null,
        maintainersCount: 0,
        scripts: {},
        weeklyDownloads: null,
        fetchError: "Package not found on the public registry (private or removed)",
      };
    }

    const ver = packument.versions?.[pkg.version];
    const scripts = ver?.scripts && typeof ver.scripts === "object" ? { ...ver.scripts } : {};

    let maintainersCount = 0;
    const m = ver?.maintainers;
    if (Array.isArray(m)) maintainersCount = m.length;
    else {
      const rootM = (packument as { maintainers?: unknown[] }).maintainers;
      if (Array.isArray(rootM)) maintainersCount = rootM.length;
    }

    let publishedAt: Date | null = null;
    const t = packument.time?.[pkg.version];
    if (typeof t === "string") {
      const d = new Date(t);
      if (!Number.isNaN(d.getTime())) publishedAt = d;
    }

    const weeklyDownloads = await this.fetchWeeklyDownloads(pkg.name, signal);

    return {
      name: pkg.name,
      version: pkg.version,
      publishedAt,
      maintainersCount,
      scripts,
      weeklyDownloads,
    };
  }
}

export async function loadAllMetadata(
  packages: { name: string; version: string }[],
  opts: FetchRegistryOptions,
): Promise<PackageMetadata[]> {
  const limit = pLimit(Math.max(1, opts.concurrency ?? 10));
  const client = new RegistryClient();
  return Promise.all(
    packages.map((p) => limit(() => client.loadMetadata(p, opts.signal))),
  );
}
