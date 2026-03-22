import { describe, expect, it } from "vitest";
import { buildFeedbackPayload } from "../src/feedback-export.js";

describe("buildFeedbackPayload", () => {
  it("includes packages and thresholds", () => {
    const p = buildFeedbackPayload(
      "/tmp/proj",
      [
        {
          name: "a",
          version: "1.0.0",
          score: 55,
          flags: [{ id: "low-downloads", severity: "info", message: "x" }],
        },
      ],
      55,
      { warnThreshold: 58, blockThreshold: 40, includeOsv: true },
    );
    expect(p.projectRoot).toBe("/tmp/proj");
    expect(p.packages).toHaveLength(1);
    expect(p.packages[0]!.flagIds).toContain("low-downloads");
    expect(p.warnThreshold).toBe(58);
    expect(p.includeOsv).toBe(true);
  });
});
