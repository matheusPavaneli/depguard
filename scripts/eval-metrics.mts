import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_CONFIG } from "../src/config.js";
import { evaluatePackageRisk } from "../src/risk-engine.js";
import { predictAlert, precisionRecallF1 } from "../src/metrics.js";
import { queryOsvForPackage } from "../src/osv.js";
import { RegistryClient } from "../src/registry.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const csvPath = join(root, "fixtures", "eval-dataset.csv");

interface Row {
  name: string;
  version: string;
  expected: "benign" | "should_alert";
  note: string;
}

function parseCsv(text: string): Row[] {
  const lines = text.trim().split(/\r?\n/);
  const out: Row[] = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i]!;
    const parts = line.split(",");
    if (parts.length < 3) continue;
    const name = parts[0]!.trim();
    const version = parts[1]!.trim();
    const expected = parts[2]!.trim() as Row["expected"];
    const note = parts.slice(3).join(",").trim();
    if (expected !== "benign" && expected !== "should_alert") continue;
    out.push({ name, version, expected, note });
  }
  return out;
}

async function main() {
  const rows = parseCsv(readFileSync(csvPath, "utf8"));
  const client = new RegistryClient();
  const warnThreshold = DEFAULT_CONFIG.warnThreshold;

  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  const details: string[] = [];

  for (const row of rows) {
    const meta = await client.loadMetadata({ name: row.name, version: row.version });
    const osv = await queryOsvForPackage(row.name, row.version);
    meta.osvVulns = osv;
    const result = evaluatePackageRisk(meta, { trusted: false });
    const pred = predictAlert(result, warnThreshold);
    const wantAlert = row.expected === "should_alert";

    if (wantAlert && pred) tp++;
    else if (!wantAlert && pred) fp++;
    else if (!wantAlert && !pred) tn++;
    else fn++;

    details.push(
      `${row.name}@${row.version} label=${row.expected} predAlert=${pred} score=${result.score} ${row.note}`,
    );
  }

  const { precision, recall, f1 } = precisionRecallF1({ tp, fp, tn, fn });

  console.log("depguard — eval on fixtures/eval-dataset.csv\n");
  console.log(`Samples: ${rows.length} | warnThreshold=${warnThreshold}`);
  console.log(`Confusion: TP=${tp} FP=${fp} TN=${tn} FN=${fn}`);
  console.log(`Precision=${precision.toFixed(3)} Recall=${recall.toFixed(3)} F1=${f1.toFixed(3)}\n`);
  for (const d of details) console.log(d);

  const strict = process.env.STRICT_EVAL === "1";
  if (strict) {
    if (f1 < 0.5 || recall < 0.5) {
      console.error("\nSTRICT_EVAL: metrics below threshold.");
      process.exitCode = 1;
    }
  }
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
