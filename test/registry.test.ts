import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import { RegistryClient } from "../src/registry.js";

const packument = {
  time: { "1.0.0": "2020-01-01T00:00:00.000Z" },
  versions: {
    "1.0.0": {
      name: "fake-pkg",
      version: "1.0.0",
      scripts: { postinstall: "node-gyp rebuild" },
      maintainers: [{ name: "a" }, { name: "b" }],
    },
  },
};

const server = setupServer(
  http.get("https://registry.npmjs.org/*", ({ request }) => {
    const path = new URL(request.url).pathname.replace(/^\//, "");
    const name = decodeURIComponent(path);
    if (name === "fake-pkg") {
      return HttpResponse.json(packument);
    }
    return new HttpResponse(null, { status: 404 });
  }),
  http.get("https://api.npmjs.org/downloads/point/last-week/*", () => {
    return HttpResponse.json({ downloads: 1234 });
  }),
);

beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
afterEach(() => server.resetHandlers());
afterAll(() => server.close());

describe("RegistryClient", () => {
  it("loads aggregated metadata", async () => {
    const c = new RegistryClient();
    const m = await c.loadMetadata({ name: "fake-pkg", version: "1.0.0" });
    expect(m.name).toBe("fake-pkg");
    expect(m.version).toBe("1.0.0");
    expect(m.weeklyDownloads).toBe(1234);
    expect(m.maintainersCount).toBe(2);
    expect(m.publishedAt?.getFullYear()).toBe(2020);
  });

  it("404 yields fetchError", async () => {
    const c = new RegistryClient();
    const m = await c.loadMetadata({ name: "missing-xyz-123", version: "1.0.0" });
    expect(m.fetchError).toBeDefined();
    expect(m.scripts).toEqual({});
  });
});
