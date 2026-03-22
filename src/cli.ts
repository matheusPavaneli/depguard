import { spawn } from "node:child_process";
import { createInterface } from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { join, resolve } from "node:path";
import { cac } from "cac";
import chalk from "chalk";
import { loadConfig, DEFAULT_CONFIG, mergeConfig } from "./config.js";
import { buildFeedbackPayload, writeFeedbackFile } from "./feedback-export.js";
import { runAudit, shouldBlockInstall } from "./run-audit.js";
import type { PackageRiskResult } from "./types.js";

function formatRow(r: PackageRiskResult, colorize: boolean): string {
  const scoreStr = `${r.score}/100`;
  const colored =
    !colorize
      ? scoreStr
      : r.score < 40
        ? chalk.red(scoreStr)
        : r.score < 60
          ? chalk.yellow(scoreStr)
          : chalk.green(scoreStr);
  return `${colored}  ${r.name}@${r.version}`;
}

function printDetails(results: PackageRiskResult[], onlyRisky: boolean) {
  const filtered = onlyRisky ? results.filter((r) => r.flags.length > 0) : results;
  for (const r of filtered) {
    if (r.flags.length === 0) continue;
    console.log("");
    console.log(chalk.bold(`${r.name}@${r.version}`) + chalk.dim(` — score ${r.score}/100`));
    for (const f of r.flags) {
      const sev =
        f.severity === "high"
          ? chalk.red("[high]")
          : f.severity === "warn"
            ? chalk.yellow("[warn]")
            : chalk.blue("[info]");
      console.log(`  ${sev} ${f.message}`);
      if (f.detail) console.log(chalk.dim(`         ${f.detail}`));
    }
  }
}

async function confirm(message: string): Promise<boolean> {
  const rl = createInterface({ input, output });
  try {
    const ans = await rl.question(`${message} (y/n) `);
    return /^y(es)?$/i.test(ans.trim());
  } finally {
    rl.close();
  }
}

function extractNpmArgs(argv: string[]): string[] {
  const i = argv.indexOf("install");
  if (i < 0) return [];
  const rest = argv.slice(i + 1);
  const dash = rest.indexOf("--");
  if (dash !== -1) return rest.slice(dash + 1);
  const out: string[] = [];
  for (let j = 0; j < rest.length; j++) {
    const a = rest[j]!;
    if (a === "--cwd") {
      j++;
      continue;
    }
    if (a.startsWith("--cwd=")) continue;
    if (a === "--strict" || a === "--yes") continue;
    out.push(a);
  }
  return out;
}

async function main() {
  const app = cac("depguard");
  app.version("0.1.0");

  app
    .command("audit", "Analyze dependencies and print trust scores")
    .option("--cwd <dir>", "Project directory", { default: process.cwd() })
    .option("--strict", "Exit with code 1 if any package triggers the alert rule")
    .option("--no-color", "Disable ANSI colors")
    .option("--json", "Print JSON output")
    .option("--no-osv", "Skip OSV lookups (api.osv.dev)")
    .option(
      "--export-feedback [file]",
      "Write anonymized JSON (scores/flags) for GitHub issues",
    )
    .action(async (options) => {
      const cwd = resolve(String(options.cwd));
      const file = loadConfig(cwd);
      const cfg = mergeConfig(file, {});
      if (options.strict === true) cfg.strict = true;
      if (options["no-osv"] === true) cfg.includeOsv = false;

      const colorize = !options["no-color"] && !options.json;

      const { results, minScore, strictFailed } = await runAudit({
        cwd,
        config: cfg,
        onProgress:
          options.json || !process.stderr.isTTY
            ? undefined
            : (done, total) => {
                if (total > 20) {
                  process.stderr.write(chalk.dim(`\rMetadata ${done}/${total}   `));
                }
              },
      });
      if (!options.json && process.stderr.isTTY) {
        process.stderr.write("\r" + " ".repeat(24) + "\r");
      }

      if (options.exportFeedback !== undefined && options.exportFeedback !== false) {
        const dest =
          typeof options.exportFeedback === "string" && options.exportFeedback.length > 0
            ? resolve(options.exportFeedback)
            : join(cwd, "depguard-feedback.json");
        const payload = buildFeedbackPayload(cwd, results, minScore, cfg);
        writeFeedbackFile(dest, payload);
        if (!options.json) {
          console.log(chalk.dim(`\nFeedback written to: ${dest}\n`));
        }
      }

      if (options.json) {
        console.log(
          JSON.stringify(
            {
              minScore,
              warnThreshold: cfg.warnThreshold ?? DEFAULT_CONFIG.warnThreshold,
              blockThreshold: cfg.blockThreshold ?? DEFAULT_CONFIG.blockThreshold,
              packages: results,
            },
            null,
            2,
          ),
        );
      } else {
        console.log(chalk.bold("\ndepguard — preventive dependency audit\n"));
        console.log(
          chalk.dim(
            `Thresholds: warn < ${cfg.warnThreshold ?? DEFAULT_CONFIG.warnThreshold} | suggested block < ${cfg.blockThreshold ?? DEFAULT_CONFIG.blockThreshold}`,
          ),
        );
        console.log(chalk.dim(`Lowest score: ${minScore}/100\n`));
        for (const r of results) {
          console.log(formatRow(r, colorize));
        }
        printDetails(results, true);
        console.log("");
      }

      if (strictFailed) {
        process.exitCode = 1;
      }
    });

  app
    .command("install", "Audit then run npm install (prompt if high risk)")
    .option("--cwd <dir>", "Project directory", { default: process.cwd() })
    .option("--strict", "Fail if strict audit rule fails")
    .option("--yes", "No prompt; exit 1 if install would be blocked by score")
    .option("--no-osv", "Skip OSV during audit")
    .allowUnknownOptions()
    .action(async (options) => {
      const cwd = resolve(String(options.cwd));
      const file = loadConfig(cwd);
      const cfg = mergeConfig(file, {});
      if (options.strict === true) cfg.strict = true;
      if (options["no-osv"] === true) cfg.includeOsv = false;
      const blockThreshold = cfg.blockThreshold ?? DEFAULT_CONFIG.blockThreshold;

      const npmArgs = extractNpmArgs(process.argv);

      const { results, strictFailed } = await runAudit({
        cwd,
        config: cfg,
      });

      if (strictFailed && options.strict) {
        process.exitCode = 1;
        return;
      }

      const risky = shouldBlockInstall(results, blockThreshold);
      if (risky && options.yes) {
        console.error(chalk.red("High risk: --yes aborts without installing."));
        process.exitCode = 1;
        return;
      }
      if (risky && !options.yes) {
        console.log(
          chalk.yellow(
            `\nOne or more packages scored below ${blockThreshold}/100. Installation may be risky.\n`,
          ),
        );
        const ok = await confirm("Continue with npm install anyway?");
        if (!ok) {
          console.log(chalk.dim("Aborted."));
          process.exitCode = 1;
          return;
        }
      }

      await new Promise<void>((res, rej) => {
        const child = spawn("npm", ["install", ...npmArgs], {
          cwd,
          stdio: "inherit",
          shell: true,
        });
        child.on("error", rej);
        child.on("close", (code) => {
          process.exitCode = code ?? 0;
          res();
        });
      });
    });

  app.help();
  app.parse(process.argv, { run: false });

  if (!app.matchedCommand) {
    app.outputHelp();
    process.exitCode = 1;
    return;
  }

  await app.runMatchedCommand();
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exitCode = 1;
});
