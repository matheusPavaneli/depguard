import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { attachOsvToMetadata, queryOsvForPackage } from "../src/osv.js";
import type { PackageMetadata } from "../src/types.js";

const server = setupServer(
  http.post("https://api.osv.dev/v1/query", async ({ request }) => {
    const body = (await request.json()) as { version?: string };
    if (body.version === "1.2.5") {
      return HttpResponse.json({
        vulns: [{ id: "GHSA-test", summary: "test vuln" }],
      });
    }
    return HttpResponse.json({ vulns: [] });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("queryOsvForPackage", () => {
  it("returns vulnerabilities when API responds", async () => {
    const v = await queryOsvForPackage("minimist", "1.2.5");
    expect(v).toHaveLength(1);
    expect(v[0]!.id).toBe("GHSA-test");
  });

  it("returns empty for version with no vuln", async () => {
    const v = await queryOsvForPackage("minimist", "9.9.9");
    expect(v).toHaveLength(0);
  });
});

describe("attachOsvToMetadata", () => {
  it("fills osvVulns on each metadata object", async () => {
    const metas: PackageMetadata[] = [
      {
        name: "minimist",
        version: "1.2.5",
        publishedAt: null,
        maintainersCount: 1,
        scripts: {},
        weeklyDownloads: null,
      },
    ];
    await attachOsvToMetadata(metas, { concurrency: 2 });
    expect(metas[0]!.osvVulns).toHaveLength(1);
  });
});
