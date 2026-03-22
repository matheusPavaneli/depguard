import { parse as shellParse } from "shell-quote";

export interface ScriptFinding {
  id: string;
  severity: "warn" | "high";
  message: string;
  scriptKey: string;
  snippet?: string;
}

// ---------------------------------------------------------------------------
// Token-based detection helpers (shell-quote)
// ---------------------------------------------------------------------------

type ShellToken = string | { op: string } | { comment: string };

function tokenize(cmd: string): ShellToken[] | null {
  try {
    return shellParse(cmd) as ShellToken[];
  } catch {
    return null;
  }
}

function isOp(t: ShellToken): t is { op: string } {
  return typeof t === "object" && "op" in t;
}

/**
 * Returns the indices in `tokens` where a new command starts
 * (position 0, and positions immediately after a shell operator).
 */
function commandStartIndices(tokens: ShellToken[]): number[] {
  const positions: number[] = [];
  let expectCmd = true;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (expectCmd && typeof t === "string") {
      positions.push(i);
      expectCmd = false;
    } else if (isOp(t)) {
      expectCmd = true;
    }
  }
  return positions;
}

/**
 * Detects `| sh` or `| bash` as actual shell pipe operators in the token stream,
 * not as text inside string arguments (e.g. inside an `echo "..."`).
 */
function hasPipeToShell(tokens: ShellToken[]): boolean {
  for (let i = 0; i + 1 < tokens.length; i++) {
    const t = tokens[i]!;
    const next = tokens[i + 1]!;
    if (
      isOp(t) &&
      t.op === "|" &&
      typeof next === "string" &&
      /^(?:ba)?sh$/i.test(next)
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Detects curl/wget/fetch appearing as an actual command token (not as a
 * string argument to echo/printf/etc.), followed by a URL argument before
 * the next shell operator.
 */
function hasRemoteDownloadCommand(tokens: ShellToken[]): boolean {
  for (const start of commandStartIndices(tokens)) {
    const cmd = tokens[start];
    if (typeof cmd !== "string" || !/^(?:curl|wget|fetch)$/i.test(cmd)) {
      continue;
    }
    for (let j = start + 1; j < tokens.length; j++) {
      const arg = tokens[j]!;
      if (isOp(arg)) break;
      if (typeof arg === "string" && /^https?:\/\//i.test(arg)) return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Regex-based fallback (and for patterns not covered by token analysis)
// ---------------------------------------------------------------------------

const BENIGN_BUILD = /node-gyp|prebuild-install|electron-rebuild|cmake-js|node-pre-gyp/i;

/** Patterns that are still regex-only (they match JS code inside `node -e`, not shell structure). */
const REGEX_PATTERNS: Array<{
  id: string;
  severity: "warn" | "high";
  message: string;
  regex: RegExp;
}> = [
  {
    id: "script-eval",
    severity: "high",
    message: "eval or equivalent in script",
    regex: /(?<![.\w])eval\s*\(|new\s+Function\s*\(|(?<![.\w])Function\s*\(\s*["'`]/i,
  },
  {
    id: "script-powershell-remote",
    severity: "warn",
    message: "PowerShell with possible remote execution",
    regex: /powershell[^&]*(-enc|IEX|Invoke-Expression|DownloadString)/i,
  },
  {
    id: "script-child-process",
    severity: "warn",
    message: "child_process / exec / spawn in lifecycle — verify source",
    regex:
      /require\s*\(\s*['"`]child_process['"`]\s*\)|from\s+['"`]child_process['"`]|\.exec\s*\(|\.spawn\s*\(|\.execFile\s*\(/i,
  },
  {
    id: "script-node-inline",
    severity: "warn",
    message: "node -e / -r with inline code — hard to audit",
    regex: /\bnode\s+(?:-[er]\s+|\s+-e\s+)/i,
  },
];

// ---------------------------------------------------------------------------
// Lifecycle key set
// ---------------------------------------------------------------------------

const LIFECYCLE_KEYS = new Set([
  "preinstall",
  "install",
  "postinstall",
  "preprepare",
  "prepare",
  "postprepare",
  "prepublish",
  "prepublishOnly",
  "prepack",
  "postpack",
]);

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export function analyzeLifecycleScripts(
  scripts: Record<string, string> | undefined,
): ScriptFinding[] {
  if (!scripts) return [];
  const findings: ScriptFinding[] = [];

  for (const key of LIFECYCLE_KEYS) {
    const value = scripts[key];
    if (!value || typeof value !== "string") continue;

    const trimmed = value.trim();
    if (!trimmed) continue;

    const looksBenignBuild = BENIGN_BUILD.test(trimmed);
    const tokens = tokenize(trimmed);

    // --- Token-based checks (more accurate, fewer false positives) ---

    if (tokens !== null) {
      // Pipe to shell: only flag if `| sh/bash` appears as an actual operator
      if (hasPipeToShell(tokens)) {
        if (!looksBenignBuild) {
          findings.push({
            id: "script-pipe-shell",
            severity: "high",
            message: "Shell pipe (curl|wget ... | sh) — high supply-chain risk",
            scriptKey: key,
            snippet: trimmed.length > 120 ? `${trimmed.slice(0, 117)}...` : trimmed,
          });
        }
      }

      // Remote download: only flag if curl/wget is an actual command, not in a string literal
      if (hasRemoteDownloadCommand(tokens)) {
        if (!looksBenignBuild) {
          findings.push({
            id: "script-remote-download",
            severity: "high",
            message: "Remote download (curl/wget/fetch) in lifecycle script",
            scriptKey: key,
            snippet: trimmed.length > 120 ? `${trimmed.slice(0, 117)}...` : trimmed,
          });
        }
      }
    } else {
      // Fallback to regex when shell-quote tokenization fails
      const pipeFallback = /\|\s*(?:ba)?sh\b|\bcurl\b[^|]*\|/i;
      const dlFallback = /\b(curl|wget|fetch)\b.+(https?:\/\/|ftp:\/\/)/i;

      if (pipeFallback.test(trimmed) && !looksBenignBuild) {
        findings.push({
          id: "script-pipe-shell",
          severity: "high",
          message: "Shell pipe (curl|wget ... | sh) — high supply-chain risk",
          scriptKey: key,
          snippet: trimmed.length > 120 ? `${trimmed.slice(0, 117)}...` : trimmed,
        });
      }
      if (dlFallback.test(trimmed) && !looksBenignBuild) {
        findings.push({
          id: "script-remote-download",
          severity: "high",
          message: "Remote download (curl/wget/fetch) in lifecycle script",
          scriptKey: key,
          snippet: trimmed.length > 120 ? `${trimmed.slice(0, 117)}...` : trimmed,
        });
      }
    }

    // --- Regex-based checks (not affected by shell structure ambiguity) ---

    for (const p of REGEX_PATTERNS) {
      if (!p.regex.test(trimmed)) continue;
      if (
        looksBenignBuild &&
        p.severity === "high" &&
        !/\b(curl|wget)\b/i.test(trimmed)
      ) {
        continue;
      }
      findings.push({
        id: p.id,
        severity: p.severity,
        message: p.message,
        scriptKey: key,
        snippet: trimmed.length > 120 ? `${trimmed.slice(0, 117)}...` : trimmed,
      });
    }
  }

  return dedupeFindings(findings);
}

function dedupeFindings(findings: ScriptFinding[]): ScriptFinding[] {
  const seen = new Set<string>();
  const out: ScriptFinding[] = [];
  for (const f of findings) {
    const k = `${f.scriptKey}:${f.id}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(f);
  }
  return out;
}

export function hasLifecycleScripts(scripts: Record<string, string> | undefined): boolean {
  if (!scripts) return false;
  for (const key of LIFECYCLE_KEYS) {
    const v = scripts[key];
    if (typeof v === "string" && v.trim()) return true;
  }
  return false;
}
