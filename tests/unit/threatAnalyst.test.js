// Micro-level unit tests for src/agents/threatAnalyst.js
//
// Run with:  npm test
//
// Uses Node's built-in test runner (node:test). Two groups:
//   A. Pure-parsing tests for _parseExploitabilityJson (no network, no AI)
//   B. Integration tests for analyzeThreats with stubbed fetch and a
//      controlled Gemini response via a tiny module loader hook.

import { test, describe, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { register } from "node:module";
import { pathToFileURL } from "node:url";
import path from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Module-loader hook: lets a single test override what `callGemini` returns.
// Registered once, behavior controlled by a process-global flag.
// ---------------------------------------------------------------------------

const geminiMockState = {
  // Either { mode: "return", value: "..." } or { mode: "throw", error: Error }
  next: null,
};

// The loader hook reads globalThis.__geminiMock. Initialize it here so the
// hook has a defined object to mutate from the very first call.
globalThis.__geminiMock = geminiMockState;

register(
  // The hook source as a data: URL so we don't need a separate file.
  pathToFileURL(
    path.join(path.dirname(fileURLToPath(import.meta.url)), "_geminiLoaderHook.mjs")
  ),
  pathToFileURL("./")
);

// ---------------------------------------------------------------------------
// Pure-parse tests for _parseExploitabilityJson (no network, no AI)
// ---------------------------------------------------------------------------
describe("threatAnalyst._parseExploitabilityJson — defensive parsing", () => {
  let parse;

  beforeEach(async () => {
    const mod = await import("../../src/agents/threatAnalyst.js");
    parse = mod._parseExploitabilityJson;
  });

  test("parses well-formed strict JSON", () => {
    const r = parse('{"exploitabilityInContext": 0.8, "rationale": "easy RCE"}');
    assert.equal(r.exploitabilityInContext, 0.8);
    assert.equal(r.rationale, "easy RCE");
  });

  test("strips ```json fences before parsing", () => {
    const r = parse('```json\n{"exploitabilityInContext": 0.1, "rationale": "deep dep"}\n```');
    assert.equal(r.exploitabilityInContext, 0.1);
    assert.equal(r.rationale, "deep dep");
  });

  test("strips plain ``` fences without language tag", () => {
    const r = parse('```\n{"exploitabilityInContext": 0.4, "rationale": "ok"}\n```');
    assert.equal(r.exploitabilityInContext, 0.4);
  });

  test("recovers a JSON object embedded in surrounding prose", () => {
    const r = parse(
      'Sure! Here is the result: {"exploitabilityInContext": 0.65, "rationale": "reachable via default config"} — hope this helps.'
    );
    assert.equal(r.exploitabilityInContext, 0.65);
    assert.equal(r.rationale, "reachable via default config");
  });

  test("clamps out-of-range scores to [0, 1]", () => {
    const tooHigh = parse('{"exploitabilityInContext": 1.5, "rationale": "x"}');
    assert.equal(tooHigh.exploitabilityInContext, 1);

    const tooLow = parse('{"exploitabilityInContext": -0.7, "rationale": "x"}');
    assert.equal(tooLow.exploitabilityInContext, 0);
  });

  test("falls back to defaults on completely invalid JSON", () => {
    const r = parse("not json at all");
    assert.equal(r.exploitabilityInContext, 0.5);
    assert.equal(r.rationale, "Unable to assess automatically.");
  });

  test("falls back to defaults on empty string", () => {
    const r = parse("");
    assert.equal(r.exploitabilityInContext, 0.5);
    assert.equal(r.rationale, "Unable to assess automatically.");
  });

  test("falls back to defaults on null/non-string input", () => {
    assert.equal(parse(null).exploitabilityInContext, 0.5);
    assert.equal(parse(undefined).exploitabilityInContext, 0.5);
    assert.equal(parse(42).exploitabilityInContext, 0.5);
  });

  test("uses default score when exploitabilityInContext is missing", () => {
    const r = parse('{"rationale": "no score given"}');
    assert.equal(r.exploitabilityInContext, 0.5);
    assert.equal(r.rationale, "no score given");
  });

  test("uses default rationale when rationale is missing or empty", () => {
    const r1 = parse('{"exploitabilityInContext": 0.3}');
    assert.equal(r1.rationale, "Unable to assess automatically.");

    const r2 = parse('{"exploitabilityInContext": 0.3, "rationale": "   "}');
    assert.equal(r2.rationale, "Unable to assess automatically.");
  });

  test("uses default rationale when rationale is wrong type", () => {
    const r = parse('{"exploitabilityInContext": 0.3, "rationale": 12345}');
    assert.equal(r.rationale, "Unable to assess automatically.");
  });

  test("coerces a numeric-string score to a clamped number", () => {
    const r = parse('{"exploitabilityInContext": "0.42", "rationale": "x"}');
    assert.equal(r.exploitabilityInContext, 0.42);
  });

  test("NaN / non-numeric score falls back to default", () => {
    const r = parse('{"exploitabilityInContext": "not a number", "rationale": "x"}');
    assert.equal(r.exploitabilityInContext, 0.5);
  });
});

// ---------------------------------------------------------------------------
// Integration tests for analyzeThreats (stubbed fetch + loader-mocked Gemini)
// ---------------------------------------------------------------------------
// Serialized because the tests share globalThis.fetch and globalThis.__geminiMock.
// Running them in parallel causes races where one test's afterEach restores
// fetch while another test's call is still in flight.
describe("threatAnalyst.analyzeThreats — integration", { timeout: 30_000, concurrency: false }, () => {
  let analyzeThreats;
  let origFetch;

  beforeEach(async () => {
    const mod = await import("../../src/agents/threatAnalyst.js");
    analyzeThreats = mod.analyzeThreats;
    origFetch = globalThis.fetch;
    geminiMockState.next = null;
    // Make sure no real Gemini key is set in the test environment.
    delete process.env.GEMINI_API_KEY;
    // Give tests a generous rate-limit budget so a multi-test suite with
    // many lookups doesn't queue itself into a stall. Production code is
    // unaffected — it ignores this env var by default.
    process.env.NVD_TEST_MAX_REQUESTS = "10000";
    // Reset the nvdClient module's internal cache + rate-limiter state.
    const nvd = await import("../../src/clients/nvdClient.js");
    nvd._resetNvdClientForTests();
  });

  afterEach(() => {
    globalThis.fetch = origFetch;
    geminiMockState.next = null;
  });

  function stubFetch(handler) {
    globalThis.fetch = handler;
  }

  // Helper: a tiny graph with one direct + two transitive nodes.
  const sampleGraph = {
    nodes: [
      { id: "root-pkg@1.0.0", name: "root-pkg", version: "1.0.0", depth: 0, isDirect: true },
      { id: "deep-pkg@2.0.0", name: "deep-pkg", version: "2.0.0", depth: 2, isDirect: false },
    ],
    edges: [],
    truncated: false,
  };

  test("returns [] for null graph", async () => {
    assert.deepEqual(await analyzeThreats(null), []);
  });

  test("returns [] for graph with empty nodes", async () => {
    assert.deepEqual(await analyzeThreats({ nodes: [], edges: [], truncated: false }), []);
  });

  test("returns [] when NVD finds no CVEs for any package", async () => {
    stubFetch(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ vulnerabilities: [] }),
    }));

    // Force the mock to throw so we can prove parse-fallback is robust too.
    geminiMockState.next = {
      mode: "return",
      value: '{"exploitabilityInContext": 0.5, "rationale": "x"}',
    };

    const out = await analyzeThreats(sampleGraph);
    assert.deepEqual(out, []);
  });

  test("emits one ThreatFinding per (package, CVE) pair with full shape", async () => {
    // Map package -> CVE payload.
    const cveByPackage = {
      "root-pkg": [
        {
          cveId: "CVE-2024-AAA",
          description: "RCE via crafted input",
          cvssScore: 9.8,
          cvssSeverity: "CRITICAL",
          publishedDate: "2024-05-01T00:00:00.000Z",
        },
      ],
      "deep-pkg": [
        {
          cveId: "CVE-2024-BBB",
          description: "minor info leak",
          cvssScore: 3.7,
          cvssSeverity: "LOW",
          publishedDate: "2024-04-01T00:00:00.000Z",
        },
      ],
    };

    stubFetch(async (url) => {
      // Extract the package name from the keywordSearch= query param.
      const u = new URL(url);
      const pkg = u.searchParams.get("keywordSearch");
      const list = cveByPackage[pkg] ?? [];
      return {
        ok: true,
        status: 200,
        json: async () => ({
          vulnerabilities: list.map((c) => ({
            cve: {
              id: c.cveId,
              descriptions: [{ lang: "en", value: c.description }],
              metrics: {
                cvssMetricV31: [
                  { cvssData: { baseScore: c.cvssScore, baseSeverity: c.cvssSeverity } },
                ],
              },
              published: c.publishedDate,
            },
          })),
        }),
      };
    });

    geminiMockState.next = { mode: "return", value: '{"exploitabilityInContext": 0.7, "rationale": "realistic"}' };

    const out = await analyzeThreats(sampleGraph);
    assert.equal(out.length, 2);

    const a = out.find((f) => f.cveId === "CVE-2024-AAA");
    assert.ok(a, "finding A present");
    assert.equal(a.pkgId, "root-pkg@1.0.0");
    assert.equal(a.packageName, "root-pkg");
    assert.equal(a.depth, 0);
    assert.equal(a.isDirect, true);
    assert.equal(a.cvssScore, 9.8);
    assert.equal(a.cvssSeverity, "CRITICAL");
    assert.equal(a.exploitabilityInContext, 0.7);
    assert.equal(a.geminiRationale, "realistic");

    const b = out.find((f) => f.cveId === "CVE-2024-BBB");
    assert.ok(b, "finding B present");
    assert.equal(b.isDirect, false);
    assert.equal(b.depth, 2);
  });

  test("uses fallback exploitability when Gemini returns malformed JSON", async () => {
    stubFetch(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        vulnerabilities: [
          {
            cve: {
              id: "CVE-2024-CCC",
              descriptions: [{ lang: "en", value: "x" }],
              metrics: {},
            },
          },
        ],
      }),
    }));

    geminiMockState.next = { mode: "return", value: "this is not json" };

    const out = await analyzeThreats({
      nodes: [
        { id: "p@1", name: "p", version: "1", depth: 0, isDirect: true },
      ],
      edges: [],
      truncated: false,
    });
    assert.equal(out.length, 1);
    assert.equal(out[0].exploitabilityInContext, 0.5);
    assert.equal(out[0].geminiRationale, "Unable to assess automatically.");
  });

  test("uses fallback exploitability when Gemini throws", async () => {
    stubFetch(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        vulnerabilities: [
          {
            cve: {
              id: "CVE-2024-DDD",
              descriptions: [{ lang: "en", value: "x" }],
              metrics: {},
            },
          },
        ],
      }),
    }));

    geminiMockState.next = { mode: "throw", error: new Error("network down") };

    const out = await analyzeThreats({
      nodes: [
        { id: "p@1", name: "p", version: "1", depth: 0, isDirect: true },
      ],
      edges: [],
      truncated: false,
    });
    assert.equal(out.length, 1);
    assert.equal(out[0].exploitabilityInContext, 0.5);
    assert.equal(out[0].geminiRationale, "Unable to assess automatically.");
  });

  test("packages with no CVEs produce no findings (clean packages are skipped)", async () => {
    // Only one package has CVEs; the other is clean.
    stubFetch(async (url) => {
      const u = new URL(url);
      const pkg = u.searchParams.get("keywordSearch");
      const hasCve = pkg === "root-pkg";
      return {
        ok: true,
        status: 200,
        json: async () => ({
          vulnerabilities: hasCve
            ? [
                {
                  cve: {
                    id: "CVE-2024-EEE",
                    descriptions: [{ lang: "en", value: "x" }],
                    metrics: { cvssMetricV31: [{ cvssData: { baseScore: 5, baseSeverity: "MEDIUM" } }] },
                  },
                },
              ]
            : [],
        }),
      };
    });

    geminiMockState.next = { mode: "return", value: '{"exploitabilityInContext": 0.5, "rationale": "ok"}' };

    const out = await analyzeThreats(sampleGraph);
    assert.equal(out.length, 1);
    assert.equal(out[0].packageName, "root-pkg");
  });

  test("NVD failures (500) are swallowed and pipeline continues", async () => {
    stubFetch(async () => ({ ok: false, status: 500, json: async () => ({}) }));

    geminiMockState.next = { mode: "return", value: '{"exploitabilityInContext": 0.5, "rationale": "x"}' };

    const out = await analyzeThreats(sampleGraph);
    assert.deepEqual(out, []);
  });

  test("runs NVD lookups with bounded concurrency (does not blow up at scale)", async () => {
    // Build a graph with 20 nodes; with concurrency=5 we should still finish
    // promptly and produce one finding per node (mocked).
    const bigGraph = {
      nodes: Array.from({ length: 20 }, (_, i) => ({
        id: `pkg${i}@1.0.0`,
        name: `pkg${i}`,
        version: "1.0.0",
        depth: 0,
        isDirect: true,
      })),
      edges: [],
      truncated: false,
    };

    let inFlight = 0;
    let maxInFlight = 0;
    stubFetch(async () => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      // Yield a bit so concurrency is observable.
      await new Promise((r) => setTimeout(r, 20));
      inFlight -= 1;
      return {
        ok: true,
        status: 200,
        json: async () => ({
          vulnerabilities: [
            {
              cve: {
                id: "CVE-2024-ZZZ",
                descriptions: [{ lang: "en", value: "x" }],
                metrics: {},
              },
            },
          ],
        }),
      };
    });

    geminiMockState.next = { mode: "return", value: '{"exploitabilityInContext": 0.5, "rationale": "ok"}' };

    const out = await analyzeThreats(bigGraph);
    assert.equal(out.length, 20, "one finding per node");
    assert.ok(maxInFlight <= 5, `expected max in-flight <= 5, got ${maxInFlight}`);
    assert.ok(maxInFlight >= 2, "expected at least some parallelism to be exercised");
  });
});

// ---------------------------------------------------------------------------
// mapWithConcurrency is exported for reuse (e.g. analyze.js uses it for
// narrative batched calls). Verify the public API surface stays correct.
// ---------------------------------------------------------------------------
describe("threatAnalyst.mapWithConcurrency — public re-export", () => {
  test("is exported as an async function", async () => {
    const { mapWithConcurrency } = await import("../../src/agents/threatAnalyst.js");
    assert.equal(typeof mapWithConcurrency, "function");
  });

  test("preserves input order in the result array", async () => {
    const { mapWithConcurrency } = await import("../../src/agents/threatAnalyst.js");
    const items = [10, 20, 30, 40, 50];
    const out = await mapWithConcurrency(items, 2, async (n) => n * 2);
    assert.deepEqual(out, [20, 40, 60, 80, 100]);
  });

  test("respects the concurrency limit", async () => {
    const { mapWithConcurrency } = await import("../../src/agents/threatAnalyst.js");
    let inFlight = 0;
    let peak = 0;
    const items = Array.from({ length: 20 }, (_, i) => i);
    const out = await mapWithConcurrency(items, 3, async (n) => {
      inFlight++;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight--;
      return n;
    });
    assert.equal(out.length, items.length);
    assert.ok(peak <= 3, `expected peak <= 3, got ${peak}`);
    assert.ok(peak >= 2, "expected at least some parallelism");
  });

  test("returns [] for empty input without throwing", async () => {
    const { mapWithConcurrency } = await import("../../src/agents/threatAnalyst.js");
    const out = await mapWithConcurrency([], 3, async () => "x");
    assert.deepEqual(out, []);
  });
});
