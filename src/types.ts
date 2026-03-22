export type Severity = "info" | "warn" | "high";

export interface RiskFlag {
  id: string;
  severity: Severity;
  message: string;
  detail?: string;
}

export interface ResolvedPackage {
  name: string;
  version: string;
}

export interface PackageRiskResult {
  name: string;
  version: string;
  score: number;
  flags: RiskFlag[];
}

export interface RegistryVersionManifest {
  name?: string;
  version?: string;
  scripts?: Record<string, string>;
  maintainers?: Array<{ name?: string; email?: string }>;
}

export interface NpmPackument {
  time?: Record<string, string>;
  versions?: Record<string, RegistryVersionManifest>;
}

export interface OsvVulnSummary {
  id: string;
  summary?: string;
}

export interface PackageMetadata {
  name: string;
  version: string;
  publishedAt: Date | null;
  maintainersCount: number;
  scripts: Record<string, string>;
  weeklyDownloads: number | null;
  fetchError?: string;
  osvVulns?: OsvVulnSummary[];
}

export interface DepGuardConfig {
  blockThreshold?: number;
  warnThreshold?: number;
  strict?: boolean;
  trustedPackages?: string[];
  includeDevDependencies?: boolean;
  includeOptional?: boolean;
  includePeer?: boolean;
  concurrency?: number;
  /** Max concurrent OSV API requests (default: 8) */
  osvConcurrency?: number;
  includeOsv?: boolean;
  /** Levenshtein similarity threshold for typosquatting detection (0–1, default: 0.82) */
  typosquatThreshold?: number;
}
