import pLimit from "p-limit";
import type { NpmPackument, PackageMetadata } from "./types.js";

const REGISTRY = "https://registry.npmjs.org";
const DOWNLOADS_API = "https://api.npmjs.org/downloads/point/last-week";

const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const REQUEST_TIMEOUT_MS = 10_000; // 10 seconds
const MAX_RETRIES = 3;

export interface FetchRegistryOptions {
  concurrency?: number;
  signal?: AbortSignal;
}

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

function makeTtlCache<K, V>() {
  const map = new Map<K, CacheEntry<V>>();
  return {
    get(key: K): V | undefined {
      const entry = map.get(key);
      if (!entry) return undefined;
      if (Date.now() > entry.expiresAt) {
        map.delete(key);
        return undefined;
      }
      return entry.value;
    },
    set(key: K, value: V, ttlMs = CACHE_TTL_MS) {
      map.set(key, { value, expiresAt: Date.now() + ttlMs });
    },
    has(key: K): boolean {
      const entry = map.get(key);
      if (!entry) return false;
      if (Date.now() > entry.expiresAt) {
        map.delete(key);
        return false;
      }
      return true;
    },
  };
}

async function fetchWithTimeoutAndRetry(
  url: string,
  init: RequestInit,
  retries = MAX_RETRIES,
  timeoutMs = REQUEST_TIMEOUT_MS,
): Promise<Response> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    // Merge caller's signal with timeout signal
    const callerSignal = init.signal as AbortSignal | undefined;
    if (callerSignal?.aborted) {
      clearTimeout(timer);
      throw new DOMException("Aborted", "AbortError");
    }
    callerSignal?.addEventListener("abort", () => controller.abort(), { once: true });

    try {
      const res = await fetch(url, { ...init, signal: controller.signal });
      clearTimeout(timer);
      return res;
    } catch (err) {
      clearTimeout(timer);
      // Don't retry on caller-initiated abort
      if (callerSignal?.aborted) throw err;
      const isAbort = err instanceof Error && err.name === "AbortError";
      const isLast = attempt === retries;
      if (isLast) throw err;
      // Exponential backoff: 200ms, 400ms, 800ms...
      const delay = isAbort ? 0 : 200 * 2 ** (attempt - 1);
      await new Promise((r) => setTimeout(r, delay));
    }
  }
  // Should never reach here
  throw new Error("fetchWithTimeoutAndRetry: exhausted retries");
}

export class RegistryClient {
  private packumentCache = makeTtlCache<string, NpmPackument | null | "error">();
  private downloadsCache = makeTtlCache<string, number | null | "error">();

  async fetchPackument(name: string, signal?: AbortSignal): Promise<NpmPackument | null> {
    const key = name.toLowerCase();
    if (this.packumentCache.has(key)) {
      const c = this.packumentCache.get(key);
      if (c === "error") return null;
      return (c as NpmPackument | null | undefined) ?? null;
    }
    const url = `${REGISTRY}/${encodeURIComponent(name)}`;
    try {
      const res = await fetchWithTimeoutAndRetry(url, {
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
      return typeof c === "number" || c === null ? (c as number | null) : null;
    }
    const url = `${DOWNLOADS_API}/${encodeURIComponent(name)}`;
    try {
      const res = await fetchWithTimeoutAndRetry(url, { signal });
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
