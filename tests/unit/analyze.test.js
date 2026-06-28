// Micro-level unit tests for src/routes/analyze.js
//
// Run with:  npm test
//
// Uses Node's built-in test runner (node:test) — no extra dependencies.
//
// The route is an HTTP orchestration layer. Per AGENTS.md it glues together:
//   dependencyScout -> threatAnalyst -> core/graph + core/riskScore
//                   -> businessAdvisor (above threshold only)
//
// We test the route handler directly by stubbing the network and AI layers
// (via the same gemini loader hook used by threatAnalyst.test.js + a
// monkey-patched globalThis.fetch that returns synthetic npm-registry and
// NVD responses). The route module is required, not invoked over a real
// socket, so the test stays fast and hermetic.
//
// Three groups:
//   A. Input resolution (resolveManifest: wrapped/bare/empty -> fixture fallback)
//   B. End-to-end happy path (manifest in -> enriched report out, with
//      blastRadius + riskScore attached, narratives only above threshold)
//   C. Resilience (a thrown downstream error surfaces a 500, not a hang)

import { test, describe, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { register } from "node:module";
import { pathToFileURL, fileURLToPath } from "node:url";
import path from "node:path";

// Reuse the gemini mock from the existing test hook so callGemini is
// controllable from one place.
const geminiMockState = { next: null };
globalThis.__geminiMock = geminiMockState;
register(
  pathToFileURL(
    path.join(path.dirname(fileURLToPath(import.meta.url)), "_geminiLoaderHook.mjs")
  ),
  pathToFileURL("./")
);

// ---------------------------------------------------------------------------
// Fake fetch that returns:
//   - npm registry docs for /{pkg}/{version}
//   - NVD CVE lists for services.nvd.nist.gov
//   - 404 for anything else
// This lets buildDependencyGraph + lookupCves both run end-to-end without
// touching the real network.
// ---------------------------------------------------------------------------

const FAKE_REGISTRY = {
  "express@latest": {
    dependencies: { "body-parser": "^1.20.0" },
  },
  "body-parser@latest": {
    dependencies: { "qs": "^6.11.0" },
  },
  "qs@latest": { dependencies: {} },
  "cors@latest": { dependencies: {} },
};

// Each NVD response is keyed by package name. One CVE per package, with a
// distinct CVSS score so the risk scorer produces predictable outputs.
const FAKE_NVD = {
  express: {
    vulnerabilities: [{
      cve: {
        id: "CVE-2024-EXPRESS",
        descriptions: [{ lang: "en", value: "Express prototype pollution" }],
        metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.5, baseSeverity: "HIGH" } }] },
        published: "2024-01-15T00:00:00.000",
      },
    }],
  },
  qs: {
    vulnerabilities: [{
      cve: {
        id: "CVE-2024-QS",
        descriptions: [{ lang: "en", value: "qs DoS via crafted query" }],
        metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } }] },
        published: "2024-02-20T00:00:00.000",
      },
    }],
  },
  // body-parser and cors return no CVEs.
  "body-parser": { vulnerabilities: [] },
  cors: { vulnerabilities: [] },
};

function makeFakeFetch() {
  return async function fakeFetch(url, options = {}) {
    const u = String(url);
    if (u.startsWith("https://registry.npmjs.org/")) {
      const tail = u.slice("https://registry.npmjs.org/".length);
      const key = tail.replace(/%40/g, "@");
      const body = FAKE_REGISTRY[key];
      if (!body) {
        return new Response("not found", { status: 404 });
      }
      return new Response(JSON.stringify(body), { status: 200 });
    }
    if (u.startsWith("https://services.nvd.nist.gov/")) {
      // Crude parse: ?keywordSearch={name}
      const m = u.match(/keywordSearch=([^&]+)/);
      const name = m ? decodeURIComponent(m[1]) : "";
      const body = FAKE_NVD[name] || { vulnerabilities: [] };
      return new Response(JSON.stringify(body), { status: 200 });
    }
    return new Response("not handled", { status: 404 });
  };
}

const originalFetch = globalThis.fetch;
let fakeFetch;

beforeEach(async () => {
  fakeFetch = makeFakeFetch();
  globalThis.fetch = fakeFetch;
  // Reset the gemini mock between tests so call sequences are predictable.
  geminiMockState.next = null;
  // Each test re-imports analyze.js so any module-level state is fresh.
  // Use a cache-busting query so node ESM re-evaluates the module.
  const mod = await import(
    `../../src/routes/analyze.js?cb=${Date.now()}-${Math.random()}`
  );
  analyzeRouter = mod.default;
});

afterEach(() => {
  globalThis.fetch = originalFetch;
});

let analyzeRouter;

// ---------------------------------------------------------------------------
// Tiny Express shim: the route only uses req.body, res.status().json(), and
// res.status().send() — we don't need real HTTP for these tests.
// ---------------------------------------------------------------------------

function runRoute(router, body) {
  return new Promise((resolve, reject) => {
    // router is a Router with router.post("/analyze", handler). Find the handler.
    const layer = router.stack.find((l) => l.route && l.route.path === "/analyze");
    if (!layer) return reject(new Error("analyze route not registered"));
    const handlers = layer.route.stack.map((s) => s.handle);
    const handler = handlers[handlers.length - 1];

    const req = { body };
    const headers = {};
    const res = {
      _status: 200,
      status(code) { this._status = code; return this; },
      json(payload) { resolve({ status: this._status, body: payload, headers }); return this; },
      send(payload) { resolve({ status: this._status, body: payload, headers }); return this; },
    };

    try {
      handler(req, res, (err) => {
        if (err) reject(err);
        else reject(new Error("handler did not respond"));
      });
    } catch (err) {
      reject(err);
    }
  });
}

// ---------------------------------------------------------------------------
// Group A — input resolution
// ---------------------------------------------------------------------------

describe("analyze route — input resolution (via the response body)", () => {
  test("accepts an explicit { manifest: {...} } wrapper", async () => {
    geminiMockState.next = {
      mode: "return",
      value: JSON.stringify({ exploitabilityInContext: 0.2, rationale: "x" }),
    };
    const res = await runRoute(analyzeRouter, {
      manifest: { name: "demo", version: "1.0.0", dependencies: { express: "^4.0.0" } },
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.inputSource, "request:wrapped");
    assert.ok(Array.isArray(res.body.graph.nodes));
  });

  test("accepts a bare manifest body (no wrapper)", async () => {
    geminiMockState.next = {
      mode: "return",
      value: JSON.stringify({ exploitabilityInContext: 0.2, rationale: "x" }),
    };
    const res = await runRoute(analyzeRouter, {
      name: "bare-demo",
      version: "0.0.1",
      dependencies: { express: "^4.0.0" },
    });
    assert.equal(res.status, 200);
    assert.equal(res.body.inputSource, "request:bare");
  });

  test("falls back to the demo fixture on empty body", async () => {
    geminiMockState.next = {
      mode: "return",
      value: JSON.stringify({ exploitabilityInContext: 0.2, rationale: "x" }),
    };
    const res = await runRoute(analyzeRouter, {});
    assert.equal(res.status, 200);
    // The fixture is supply-chain-observatory-sample, which depends on express + cors.
    assert.equal(res.body.inputSource, "fixture");
    assert.equal(res.body.manifest.name, "supply-chain-observatory-sample");
  });

  test("returns 400 when no manifest can be resolved", async () => {
    // Delete the fixture so the fallback path fails too.
    const fs = await import("node:fs/promises");
    const fixturePath = path.resolve("test-fixtures", "sample-package.json");
    const original = await fs.readFile(fixturePath, "utf8");
    // Move it out of the way for this test.
    const backupPath = fixturePath + ".bak";
    await fs.rename(fixturePath, backupPath);
    try {
      const res = await runRoute(analyzeRouter, { hello: "world" });
      assert.equal(res.status, 400);
      assert.equal(res.body.error, "no_manifest");
    } finally {
      await fs.rename(backupPath, fixturePath);
    }
  });
});

// ---------------------------------------------------------------------------
// Group B — end-to-end happy path
// ---------------------------------------------------------------------------

describe("analyze route — end-to-end pipeline", () => {
  test("enriches every finding with blastRadius + riskScore", async () => {
    geminiMockState.next = {
      mode: "return",
      value: JSON.stringify({ exploitabilityInContext: 0.3, rationale: "moderate" }),
    };
    const res = await runRoute(analyzeRouter, {
      manifest: { name: "x", version: "1.0.0", dependencies: { express: "^4.0.0" } },
    });
    assert.equal(res.status, 200);
    assert.ok(res.body.findings.length > 0, "expected at least one finding from fake NVD");

    for (const f of res.body.findings) {
      assert.ok(f.blastRadius, `finding ${f.cveId} missing blastRadius`);
      assert.equal(typeof f.blastRadius.dependentCount, "number");
      assert.equal(typeof f.blastRadius.criticalPathFlag, "boolean");
      assert.ok(f.riskScore, `finding ${f.cveId} missing riskScore`);
      assert.equal(typeof f.riskScore.score, "number");
      assert.ok(f.riskScore.breakdown, "missing breakdown");
    }
  });

  test("produces a non-truncated graph for the fixture manifest", async () => {
    geminiMockState.next = {
      mode: "return",
      value: JSON.stringify({ exploitabilityInContext: 0.2, rationale: "x" }),
    };
    const res = await runRoute(analyzeRouter, {});
    assert.equal(res.status, 200);
    assert.equal(res.body.truncated, false);
    // express is direct (depth 0). body-parser and qs should appear.
    const names = res.body.graph.nodes.map((n) => n.name);
    assert.ok(names.includes("express"), `expected 'express' in nodes, got ${names.join(", ")}`);
  });

  test("only generates narratives for findings above the threshold", async () => {
    // Mock Gemini with a shim that distinguishes between threat-analyst
    // prompts (look for "exploitabilityInContext") and business-advisor
    // prompts (look for "businessImpactSummary"). The mock hook reads
    // .next.value, so we return one JSON shape and rely on Gemini call
    // count via two .next values, OR install a shim via the geminiMockState
    // `value` being a function. The hook only treats .value as a string,
    // so instead: we set exploitability low (0.1) so all findings stay
    // below 50, and assert no narrative was attached. This is a tighter
    // contract than "narrative implies score>=50" and easier to verify.
    geminiMockState.next = {
      mode: "return",
      value: JSON.stringify({ exploitabilityInContext: 0.1, rationale: "low" }),
    };

    const res = await runRoute(analyzeRouter, {});
    assert.equal(res.status, 200);
    // With exploitability capped at 0.1, no finding should cross the
    // 50-point narrative threshold (qs at CVSS 9.8 contributes 0.392,
    // exploitability 0.1 contributes 0.035, blast radius small, no
    // critical path boost from a non-direct dep, so total ~ 0.45 -> 45).
    const narrated = res.body.findings.filter((f) => f.narrative);
    assert.equal(
      narrated.length,
      0,
      `expected zero narratives when exploitability is pinned low, got ${narrated.length} for ${narrated.map((f) => f.cveId).join(", ")}`
    );

    // The contract we care about: IF a narrative is attached, its finding
    // must have score >= 50. Verify by re-running with a high exploitability
    // and inspecting the structure.
    geminiMockState.next = {
      mode: "return",
      value: JSON.stringify({ exploitabilityInContext: 0.9, rationale: "high" }),
    };
    const res2 = await runRoute(analyzeRouter, {});
    assert.equal(res2.status, 200);
    for (const f of res2.body.findings) {
      if (f.narrative) {
        assert.ok(
          f.riskScore.score >= 50,
          `narrative should only attach to score>=50, got ${f.riskScore.score} for ${f.cveId}`
        );
        assert.ok(typeof f.narrative.businessImpactSummary === "string");
        assert.ok(typeof f.narrative.recommendedAction === "string");
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Group C — resilience
// ---------------------------------------------------------------------------

describe("analyze route — resilience", () => {
  test("returns 500 JSON when the pipeline throws (does not hang)", async () => {
    // Force buildDependencyGraph to throw by giving it a manifest whose
    // `.dependencies` is a Proxy that throws on iteration. dependencyScout
    // catches its own fetch failures but can't recover from this.
    const badManifest = {
      name: "boom",
      version: "0.0.1",
      get dependencies() { throw new Error("intentional manifest failure"); },
    };
    const res = await runRoute(analyzeRouter, { manifest: badManifest });
    assert.equal(res.status, 500);
    assert.equal(res.body.error, "analysis_failed");
    assert.ok(typeof res.body.message === "string" && res.body.message.length > 0);
    assert.equal(typeof res.body.durationMs, "number");
  });

  test("logs pipeline duration on success", async () => {
    geminiMockState.next = {
      mode: "return",
      value: JSON.stringify({ exploitabilityInContext: 0.2, rationale: "x" }),
    };
    const originalLog = console.log;
    const logs = [];
    console.log = (...args) => {
      // Read each arg explicitly — args can be a mix of strings and objects.
      const text = args
        .map((a) => (typeof a === "string" ? a : JSON.stringify(a)))
        .join(" ");
      logs.push(text);
    };
    try {
      await runRoute(analyzeRouter, {});
    } finally {
      console.log = originalLog;
    }
    const joined = logs.join("\n");
    assert.ok(/\[analyze\] .*start manifest=/.test(joined), `expected start log, got: ${joined}`);
    assert.ok(/\[analyze\] done in \d+ms/.test(joined), `expected duration log, got: ${joined}`);
  });
});
