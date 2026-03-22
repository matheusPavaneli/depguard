export interface ScriptFinding {
  id: string;
  severity: "warn" | "high";
  message: string;
  scriptKey: string;
  snippet?: string;
}

const BENIGN_BUILD = /node-gyp|prebuild-install|electron-rebuild|cmake-js|node-pre-gyp/i;

const PATTERNS: Array<{
  id: string;
  severity: "warn" | "high";
  message: string;
  regex: RegExp;
}> = [
  {
    id: "script-pipe-shell",
    severity: "high",
    message: "Shell pipe (curl|wget ... | sh) — high supply-chain risk",
    regex: /\|\s*(?:ba)?sh\b|\bcurl\b[^|]*\|/i,
  },
  {
    id: "script-remote-download",
    severity: "high",
    message: "Remote download (curl/wget/fetch) in lifecycle script",
    regex: /\b(curl|wget|fetch)\b.+(https?:\/\/|ftp:\/\/)/i,
  },
  {
    id: "script-eval",
    severity: "high",
    message: "eval or equivalent in script",
    // Match eval(...) as a call (not as a property access like obj.eval), new Function(), or Function() constructor
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
    // Require child_process to appear as a module reference (require/import), not in arbitrary strings
    regex: /require\s*\(\s*['"`]child_process['"`]\s*\)|from\s+['"`]child_process['"`]|\.exec\s*\(|\.spawn\s*\(|\.execFile\s*\(/i,
  },
  {
    id: "script-node-inline",
    severity: "warn",
    message: "node -e / -r with inline code — hard to audit",
    regex: /\bnode\s+(?:-[er]\s+|\s+-e\s+)/i,
  },
];

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

    for (const p of PATTERNS) {
      if (!p.regex.test(trimmed)) continue;
      if (looksBenignBuild && p.severity === "high" && !/\b(curl|wget)\b/i.test(trimmed)) {
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
