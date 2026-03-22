import {
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import { extname, join, relative } from "node:path";
import { tmpdir } from "node:os";
import pacote from "pacote";
import type { RiskFlag } from "./types.js";

const JS_EXTENSIONS = new Set([".js", ".cjs", ".mjs"]);

/** Files larger than this are skipped (likely minified bundles with little signal-to-noise). */
const MAX_FILE_BYTES = 512 * 1024; // 512 KB

/** Max total score penalty applied from deep-scan findings. */
export const CAP_DEEP_SCAN = 30;

export interface DeepScanResult {
  flags: RiskFlag[];
  /** Score penalty to subtract (already capped at CAP_DEEP_SCAN). */
  penalty: number;
}

const DEEP_PATTERNS: Array<{
  id: string;
  severity: "warn" | "high";
  message: string;
  regex: RegExp;
}> = [
  {
    id: "deep-token-exfil",
    severity: "high",
    message:
      "Credential/token environment variable possibly sent to external server",
    // Detects env vars with sensitive names used near network calls
    regex:
      /process\.env\.(?:NPM_TOKEN|NPM_AUTH_TOKEN|GITHUB_TOKEN|AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|PRIVATE_KEY|SECRET_KEY|PASSWORD|API_KEY|AUTH_TOKEN)[^\n]{0,200}(?:fetch|https?|request|axios|got)\s*\(/is,
  },
  {
    id: "deep-write-npmrc",
    severity: "high",
    message: "Writes to .npmrc — could silently redirect the npm registry",
    regex: /(?:writeFile|appendFile)(?:Sync)?\s*\([^)]*\.npmrc/i,
  },
  {
    id: "deep-write-shell-profile",
    severity: "high",
    message:
      "Writes to shell profile (.bashrc, .zshrc, .profile) — possible persistence mechanism",
    regex:
      /(?:writeFile|appendFile)(?:Sync)?\s*\([^)]*(?:\.bashrc|\.zshrc|\.bash_profile|\.profile|\.bash_login)/i,
  },
  {
    id: "deep-read-ssh-keys",
    severity: "high",
    message: "Reads SSH private keys or credentials",
    regex:
      /(?:readFile|createReadStream)(?:Sync)?\s*\([^)]*(?:\.ssh[/\\](?:id_rsa|id_ed25519|id_ecdsa|identity)|\.aws[/\\]credentials)/i,
  },
  {
    id: "deep-dynamic-eval-encoded",
    severity: "high",
    message:
      "Executes dynamically decoded/encoded content (possible obfuscation)",
    // eval( Buffer.from('...','base64').toString() ) — common malware pattern
    regex:
      /eval\s*\(\s*(?:Buffer\.from|atob)\s*\(\s*['"][A-Za-z0-9+/=]{40,}['"]/i,
  },
  {
    id: "deep-remote-exec",
    severity: "high",
    message: "Fetches remote content and passes it to a command executor",
    regex:
      /(?:exec|execSync|spawn|spawnSync)\s*\([^;)]{0,300}(?:fetch|https?\.(?:get|request)|require\s*\(\s*['"]https?)/is,
  },
  {
    id: "deep-obfuscated-base64",
    severity: "warn",
    message:
      "Large base64-encoded string decoded at runtime — review for hidden payloads",
    // Long base64 blobs decoded via Buffer.from/atob (not inside a comment)
    regex:
      /(?:Buffer\.from|atob)\s*\(\s*['"][A-Za-z0-9+/=]{200,}['"]\s*(?:,\s*['"]base64['"]\s*)?\)\s*\.toString/i,
  },
];

interface FileFinding {
  id: string;
  severity: "warn" | "high";
  message: string;
  relPath: string;
}

function scanFile(filePath: string, rootDir: string): FileFinding[] {
  try {
    const stat = statSync(filePath);
    if (stat.size > MAX_FILE_BYTES) return [];
    const content = readFileSync(filePath, "utf8");
    const relPath = relative(rootDir, filePath);
    return DEEP_PATTERNS.filter((p) => p.regex.test(content)).map((p) => ({
      id: p.id,
      severity: p.severity,
      message: p.message,
      relPath,
    }));
  } catch {
    return [];
  }
}

function walkJsFiles(dir: string, out: string[]): void {
  try {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === "node_modules") continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walkJsFiles(full, out);
      } else if (entry.isFile() && JS_EXTENSIONS.has(extname(entry.name))) {
        out.push(full);
      }
    }
  } catch {
    // ignore unreadable dirs
  }
}

/**
 * Downloads and scans the tarball content of a package for supply-chain attack
 * patterns. Returns flags and the total score penalty to apply.
 *
 * This is intentionally opt-in (`--deep` flag) due to the network and I/O cost.
 */
export async function deepScanPackage(
  name: string,
  version: string,
): Promise<DeepScanResult> {
  const tmpDir = mkdtempSync(join(tmpdir(), "depguard-deep-"));
  try {
    await pacote.extract(`${name}@${version}`, tmpDir, {
      fullMetadata: false,
    });

    const jsFiles: string[] = [];
    walkJsFiles(tmpDir, jsFiles);

    const seen = new Set<string>();
    const flags: RiskFlag[] = [];
    let rawPenalty = 0;

    for (const file of jsFiles) {
      for (const f of scanFile(file, tmpDir)) {
        // One flag per pattern id across all files (deduplicated)
        if (seen.has(f.id)) continue;
        seen.add(f.id);
        flags.push({
          id: f.id,
          severity: f.severity,
          message: f.message,
          detail: `Found in ${f.relPath}`,
        });
        rawPenalty += f.severity === "high" ? 15 : 8;
      }
    }

    return { flags, penalty: Math.min(CAP_DEEP_SCAN, rawPenalty) };
  } catch {
    return { flags: [], penalty: 0 };
  } finally {
    try {
      rmSync(tmpDir, { recursive: true, force: true });
    } catch {
      // ignore cleanup errors
    }
  }
}
