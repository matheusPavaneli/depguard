# depguard

**depguard** is a Node.js CLI that scores npm dependencies on a **0–100 trust scale** using public data only. It complements reactive tools such as `npm audit` and Dependabot by highlighting *risk signals before a CVE exists*: very new releases, low download counts, suspicious `postinstall` scripts, names similar to popular packages (typosquatting), and **known vulnerabilities** from the [Open Source Vulnerabilities (OSV)](https://osv.dev/) database.

It does **not** prove that a package is malware. It helps teams prioritize manual review and safer install workflows with clear, structured reasons for each flag.

---

## Features

| Capability | Description |
|------------|-------------|
| **Dependency resolution** | Reads `package.json` and prefers **`package-lock.json`** (v2/v3) for exact versions; without a lockfile, resolves ranges via **pacote** (network). |
| **Registry metadata** | Version publish time, maintainer count, weekly download estimate (npm downloads API). |
| **Lifecycle script heuristics** | Scans `preinstall` / `install` / `postinstall` / related fields for patterns such as remote download + shell, `eval`, risky PowerShell usage, etc., with allowances for common native build tools. |
| **Typosquatting** | Normalized string similarity (Levenshtein-based) against a curated list of popular package names; list can be **regenerated** from npm search (`npm run generate:popular`). |
| **OSV integration** | Per `name@version`, queries `https://api.osv.dev/v1/query` for the npm ecosystem; results add a dedicated flag and score penalty. |
| **Configurable thresholds** | `warnThreshold`, `blockThreshold`, `strict` mode, `trustedPackages`, optional OSV disable. |
| **Install guard** | `depguard install` runs the audit first and can **prompt** (or abort with `--yes`) when scores fall below `blockThreshold`. |
| **Feedback export** | `--export-feedback` writes anonymized JSON for GitHub issues ([template](.github/ISSUE_TEMPLATE/false-positive.yml)). |
| **Eval harness** | `fixtures/eval-dataset.csv` + `npm run eval-metrics` for precision/recall/F1 on a small public labeled set (optional `STRICT_EVAL=1`). |

---

## Requirements

- **Node.js 18+**

---

## Installation

```bash
npm install -g depguard
```

Or run without global install:

```bash
npx depguard@latest audit
```

From a clone of this repository:

```bash
npm install
npm run build
node dist/cli.js audit --cwd /path/to/your/project
```

---

## Usage

```bash
depguard audit
depguard audit --cwd ./my-app
depguard audit --strict
depguard audit --json
depguard audit --no-osv
depguard audit --export-feedback
depguard audit --export-feedback ./report.json

depguard install
depguard install -- --legacy-peer-deps
```

### Commands

- **`audit`** — Resolve dependencies, fetch metadata (+ OSV unless disabled), print scores and human-readable flags (or JSON with `--json`).
- **`install`** — Same audit pipeline, then spawns `npm install` with remaining arguments. If any package is below `blockThreshold`, the CLI asks for confirmation unless `--yes` is set (in which case it **exits without installing**).

### Exit codes

- **`audit`**: `0` normally; `1` if `--strict` and any package matches the internal **alert rule** (low score *or* OSV flag present).
- **`install`**: inherits npm’s exit code after a successful audit path, or `1` when aborted by policy or strict audit failure.

---

## How scoring works

1. Start from **100**.
2. Apply **capped** penalties per category (age of the resolved version, downloads, single maintainer, typosquat similarity, script findings, OSV hits). Caps avoid driving every package to zero.
3. **Young version** penalties are **scaled down** when weekly downloads are high (to reduce false positives on legitimate releases of popular packages).
4. **`trustedPackages`** (case-insensitive names) skips metadata and typosquat penalties only; **OSV and script analysis still apply**.

Default thresholds are defined in [`src/config.ts`](src/config.ts) (`warnThreshold: 58`, `blockThreshold: 40`) and were tuned against [`fixtures/eval-dataset.csv`](fixtures/eval-dataset.csv).

---

## Configuration

Optional files at the project root: **`guard.config.json`** or **`depguard.config.json`**.

```json
{
  "blockThreshold": 40,
  "warnThreshold": 58,
  "strict": false,
  "trustedPackages": ["my-internal-scope-pkg"],
  "includeDevDependencies": true,
  "includeOptional": true,
  "includePeer": false,
  "includeOsv": true,
  "concurrency": 10
}
```

| Field | Role |
|-------|------|
| `blockThreshold` | Below this score, `depguard install` prompts (or fails with `--yes`). |
| `warnThreshold` | Used for `--strict` and for the eval script’s `predictAlert` baseline. |
| `trustedPackages` | Suppresses registry “noise” rules for listed names; **not** OSV or dangerous scripts. |
| `includeOsv` | Set `false` or use `--no-osv` to skip OSV HTTP calls (offline / faster runs). |

---

## Evaluation metrics (optional)

Labeled rows live in [`fixtures/eval-dataset.csv`](fixtures/eval-dataset.csv). With network access:

```bash
npm run eval:metrics
STRICT_EVAL=1 npm run eval:metrics
```

A GitHub Actions workflow ([`.github/workflows/eval.yml`](.github/workflows/eval.yml)) can run the same check on demand.

---

## Regenerating the popular-package list

```bash
npm run generate:popular
```

Merges npm `/-/v1/search` results (keyword batching with a short delay) into [`src/data/popular-packages.ts`](src/data/popular-packages.ts).

---

## Limitations

- **False positives** are expected for legitimate young packages or benign `postinstall` steps; tune thresholds and `trustedPackages`.
- **Typosquat detection** is only as good as the embedded or regenerated name list.
- **Private registries** or missing public packuments produce fetch errors and reduced signal.
- **No tarball/static analysis** in this version; unknown malware without manifest signals may not be flagged.

---

## Development

```bash
npm install
npm run build
npm test
```

- **Build**: `tsup` bundles the CLI to `dist/cli.js` (ESM) with external runtime deps (`cac`, `chalk`, `p-limit`, `pacote`, `semver`).
- **Tests**: `vitest` + `msw` for HTTP mocks.

---

## License

MIT
