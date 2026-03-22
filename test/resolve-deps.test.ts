import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { describe, expect, it } from "vitest";
import { parsePackageLock, resolvePackages } from "../src/resolve-deps.js";

describe("parsePackageLock", () => {
  it("lockfile v3 packages", () => {
    const dir = mkdtempSync(join(tmpdir(), "dg-lock-"));
    const lock = {
      lockfileVersion: 3,
      packages: {
        "": { name: "app" },
        "node_modules/react": { version: "18.0.0", name: "react" },
        "node_modules/foo/node_modules/bar": { version: "2.0.0", name: "bar" },
      },
    };
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify(lock));
    const pkgs = parsePackageLock(join(dir, "package-lock.json"));
    expect(pkgs).toContainEqual({ name: "react", version: "18.0.0" });
    expect(pkgs).toContainEqual({ name: "bar", version: "2.0.0" });
    rmSync(dir, { recursive: true, force: true });
  });

  it("lockfile v2 dependencies", () => {
    const dir = mkdtempSync(join(tmpdir(), "dg-lock2-"));
    const lock = {
      lockfileVersion: 2,
      dependencies: {
        a: {
          version: "1.0.0",
          dependencies: {
            b: { version: "2.0.0" },
          },
        },
      },
    };
    writeFileSync(join(dir, "package-lock.json"), JSON.stringify(lock));
    const pkgs = parsePackageLock(join(dir, "package-lock.json"));
    expect(pkgs).toContainEqual({ name: "a", version: "1.0.0" });
    expect(pkgs).toContainEqual({ name: "b", version: "2.0.0" });
    rmSync(dir, { recursive: true, force: true });
  });
});

describe("resolvePackages with lockfile", () => {
  it("prefers package-lock without network", async () => {
    const dir = mkdtempSync(join(tmpdir(), "dg-pj-"));
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({
        name: "x",
        dependencies: { react: "^18.0.0" },
      }),
    );
    writeFileSync(
      join(dir, "package-lock.json"),
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "x" },
          "node_modules/react": { name: "react", version: "18.2.0" },
        },
      }),
    );
    const pkgs = await resolvePackages({
      cwd: dir,
      includeDev: false,
      includeOptional: false,
      includePeer: false,
    });
    expect(pkgs).toContainEqual({ name: "react", version: "18.2.0" });
    rmSync(dir, { recursive: true, force: true });
  });
});
