// Micro-level unit tests for src/agents/dependencyScout.js
//
// Run with:  npm test
//
// Uses Node's built-in test runner (node:test) — no extra dependencies.
// Tests are split into two groups:
//   A. Pure-shape tests (no network) — always run
//   B. Live registry smoke test     — runs against https://registry.npmjs.org
//   C. Resilience test              — mocks fetch to simulate timeouts/failures
//
// Group B is allowed to "succeed-vacuous" if the registry is unreachable: the
// contract is that the pipeline must not crash, and that is what we assert.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { buildDependencyGraph } from "../../src/agents/dependencyScout.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = path.join(__dirname, "..", "..", "test-fixtures", "sample-package.json");

// ---------------------------------------------------------------------------
// Group A — shape of the return value
// ---------------------------------------------------------------------------
describe("dependencyScout.buildDependencyGraph — shape", () => {
  test("empty manifest returns an empty graph with truncated=false", async () => {
    const g = await buildDependencyGraph({});
    assert.deepEqual(g, { nodes: [], edges: [], truncated: false });
  });

  test("manifest with no dependencies returns an empty graph", async () => {
    const g = await buildDependencyGraph({ name: "x", version: "1.0.0" });
    assert.equal(g.nodes.length, 0);
    assert.equal(g.edges.length, 0);
    assert.equal(g.truncated, false);
  });

  test("null manifest is tolerated", async () => {
    const g = await buildDependencyGraph(null);
    assert.equal(g.nodes.length, 0);
  });

  test("devDependencies are ignored for MVP scope", async () => {
    // We use {} dependencies so no network is touched; the devDeps key is
    // present to confirm the function does not look at it.
    const g = await buildDependencyGraph({
      name: "x",
      dependencies: {},
      devDependencies: { leftpad: "^1.0.0" }
    });
    assert.equal(g.nodes.length, 0);
  });

  test("return shape always exposes { nodes, edges, truncated }", async () => {
    const g = await buildDependencyGraph({ name: "y", version: "0.0.0" });
    assert.ok(Array.isArray(g.nodes));
    assert.ok(Array.isArray(g.edges));
    assert.equal(typeof g.truncated, "boolean");
  });
});

// ---------------------------------------------------------------------------
// Group B — live registry smoke test (online; allowed to be vacuous)
// ---------------------------------------------------------------------------
describe("dependencyScout.buildDependencyGraph — live registry smoke", { timeout: 30_000 }, () => {
  test("resolves a real npm package", async () => {
    // 'lodash' is small, well-known, and stable. We don't pin a version to
    // avoid flakiness — 'latest' is the safest registry handle.
    const g = await buildDependencyGraph({
      name: "test",
      version: "0.0.0",
      dependencies: { lodash: "^4.17.21" }
    });

    assert.equal(typeof g.truncated, "boolean");
    assert.ok(Array.isArray(g.nodes));
    assert.ok(Array.isArray(g.edges));

    const lodash = g.nodes.find((n) => n.name === "lodash");
    if (lodash) {
      // Online path exercised
      assert.equal(lodash.isDirect, true);
      assert.equal(lodash.depth, 0);
      assert.match(lodash.id, /^lodash@/);
    } else {
      // Offline / rate-limited path: contract is "no throw, valid shape"
      assert.equal(g.nodes.length, 0);
    }
  });

  test("loads test-fixtures/sample-package.json without throwing", async () => {
    const raw = await readFile(FIXTURE_PATH, "utf8");
    const manifest = JSON.parse(raw);
    const g = await buildDependencyGraph(manifest);
    // express and cors are both well-known. Either resolve or are skipped —
    // both outcomes are acceptable per the defensive-integration contract.
    assert.equal(typeof g.truncated, "boolean");
  });
});

// ---------------------------------------------------------------------------
// Group C — resilience: registry failures must not crash the pipeline
// ---------------------------------------------------------------------------
describe("dependencyScout.buildDependencyGraph — resilience", { timeout: 15_000 }, () => {
  test("fetch timeouts are swallowed; direct nodes are still emitted", async () => {
    const origFetch = globalThis.fetch;
    globalThis.fetch = async (_url, opts) =>
      await new Promise((_resolve, reject) => {
        if (opts && opts.signal) {
          opts.signal.addEventListener("abort", () => {
            const e = new Error("aborted");
            e.name = "AbortError";
            reject(e);
          });
        } else {
          reject(new Error("no signal"));
        }
      });

    try {
      const g = await buildDependencyGraph({
        name: "demo",
        version: "0.0.0",
        dependencies: { express: "^4.0.0", cors: "^2.0.0" }
      });

      assert.equal(g.nodes.length, 2, "direct nodes must be present even when fetch fails");
      assert.ok(g.nodes.find((n) => n.name === "express" && n.isDirect === true));
      assert.ok(g.nodes.find((n) => n.name === "cors" && n.isDirect === true));
      assert.equal(g.edges.length, 0, "no transitive edges when every fetch failed");
      assert.equal(g.truncated, false);
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  test("HTTP 500 responses are swallowed; pipeline continues", async () => {
    const origFetch = globalThis.fetch;
    globalThis.fetch = async () => ({ ok: false, status: 500 });

    try {
      const g = await buildDependencyGraph({
        name: "demo",
        version: "0.0.0",
        dependencies: { express: "^4.0.0" }
      });
      assert.equal(g.nodes.length, 1);
      assert.equal(g.edges.length, 0);
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});
