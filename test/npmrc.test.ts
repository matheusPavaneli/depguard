import { describe, expect, it } from "vitest";
import { isPrivateScope } from "../src/npmrc.js";

describe("isPrivateScope", () => {
  it("returns false for unscoped packages", () => {
    const scopes = new Set(["@mycompany"]);
    expect(isPrivateScope("lodash", scopes)).toBe(false);
  });

  it("returns true for a scoped package matching a private scope", () => {
    const scopes = new Set(["@mycompany"]);
    expect(isPrivateScope("@mycompany/utils", scopes)).toBe(true);
  });

  it("is case-insensitive", () => {
    const scopes = new Set(["@mycompany"]);
    expect(isPrivateScope("@MyCompany/utils", scopes)).toBe(true);
  });

  it("returns false when scope set is empty", () => {
    const scopes = new Set<string>();
    expect(isPrivateScope("@mycompany/utils", scopes)).toBe(false);
  });

  it("returns false for a different scope", () => {
    const scopes = new Set(["@mycompany"]);
    expect(isPrivateScope("@other/pkg", scopes)).toBe(false);
  });
});
