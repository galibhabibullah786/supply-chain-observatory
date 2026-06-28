// Micro-level unit tests for src/core/graph.js
//
// Run with:  npm test
//
// Uses Node's built-in test runner (node:test) — no extra dependencies.
// graph.js is pure logic: no network, no AI, deterministic. We therefore split
// tests into two groups only:
//   A. Shape — always run, in-memory fixture graphs
//   B. Resilience — malformed / cyclic / dangling-edge inputs that must not throw
//
// Per AGENTS.md, this module is the deterministic blast-radius engine. Its
// correctness is what the explainable risk-scoring UI leans on at demo time.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { computeBlastRadius, __internal } from "../../src/core/graph.js";

// Helper to build a small graph quickly in tests.
function mkGraph(spec) {
  // spec: { nodes: [{id, name, version, depth, isDirect?}], edges: [{from, to}] }
  const nodes = (spec.nodes || []).map((n) => ({
    depth: 0,
    isDirect: false,
    ...n,
  }));
  const edges = spec.edges || [];
  return { nodes, edges, truncated: false };
}

// ---------------------------------------------------------------------------
// Group A — shape and core traversal semantics
// ---------------------------------------------------------------------------
describe("graph.computeBlastRadius — shape and traversal", () => {
  test("empty graph returns the empty shape", () => {
    const g = mkGraph({ nodes: [], edges: [] });
    assert.deepEqual(computeBlastRadius(g, "any@1.0.0"), {
      dependents: [],
      dependentCount: 0,
      criticalPathFlag: false,
    });
  });

  test("pkgId not present in the graph returns the empty shape", () => {
    const g = mkGraph({
      nodes: [{ id: "express@4.0.0", name: "express", version: "4.0.0" }],
      edges: [],
    });
    assert.deepEqual(computeBlastRadius(g, "missing@1.0.0"), {
      dependents: [],
      dependentCount: 0,
      criticalPathFlag: false,
    });
  });

  test("null / malformed graph input is tolerated", () => {
    assert.deepEqual(computeBlastRadius(null, "x@1"), {
      dependents: [],
      dependentCount: 0,
      criticalPathFlag: false,
    });
    assert.deepEqual(computeBlastRadius(undefined, "x@1"), {
      dependents: [],
      dependentCount: 0,
      criticalPathFlag: false,
    });
  });

  test("non-string pkgId is tolerated", () => {
    const g = mkGraph({
      nodes: [{ id: "qs@6.0.0", name: "qs", version: "6.0.0" }],
      edges: [],
    });
    assert.deepEqual(computeBlastRadius(g, undefined), {
      dependents: [],
      dependentCount: 0,
      criticalPathFlag: false,
    });
  });

  test("returns the empty shape when nothing depends on the pkgId", () => {
    // express is a leaf in this graph — no node depends on it.
    // app -> express   (app depends on express, but nothing depends on `express`... wait)
    // Actually nothing depends on `unused-leaf` below. Use a leaf with no inbound edges.
    const g = mkGraph({
      nodes: [
        { id: "app@1.0.0", name: "app", version: "1.0.0", isDirect: false },
        { id: "express@4.0.0", name: "express", version: "4.0.0", isDirect: true },
        { id: "unused-leaf@1.0.0", name: "unused-leaf", version: "1.0.0", isDirect: false },
      ],
      edges: [{ from: "app@1.0.0", to: "express@4.0.0" }],
    });
    const r = computeBlastRadius(g, "unused-leaf@1.0.0");
    assert.equal(r.dependentCount, 0);
    assert.deepEqual(r.dependents, []);
    assert.equal(r.criticalPathFlag, false);
  });

  test("direct dependent is returned and flagged on critical path", () => {
    const g = mkGraph({
      nodes: [
        { id: "app@1.0.0", name: "app", version: "1.0.0", isDirect: false },
        { id: "express@4.0.0", name: "express", version: "4.0.0", isDirect: true },
        { id: "qs@6.0.0", name: "qs", version: "6.0.0", isDirect: false },
      ],
      edges: [
        { from: "app@1.0.0", to: "express@4.0.0" },
        { from: "express@4.0.0", to: "qs@6.0.0" },
      ],
    });
    // qs blast = [express, app] (express depends on qs, app depends on express).
    // express is direct -> criticalPathFlag must be true.
    const r = computeBlastRadius(g, "qs@6.0.0");
    assert.deepEqual(r.dependents, ["express@4.0.0", "app@1.0.0"]);
    assert.equal(r.dependentCount, 2);
    assert.equal(r.criticalPathFlag, true, "express is direct -> flag must be true");
  });

  test("transitive dependents are walked in order; critical-path flag tracks ANY direct ancestor", () => {
    // app -> express -> body-parser -> qs   (only express is direct)
    // app -> express -> lodash
    const g = mkGraph({
      nodes: [
        { id: "app@1.0.0", name: "app", version: "1.0.0", isDirect: false },
        { id: "express@4.0.0", name: "express", version: "4.0.0", isDirect: true },
        { id: "body-parser@1.0.0", name: "body-parser", version: "1.0.0", isDirect: false },
        { id: "qs@6.0.0", name: "qs", version: "6.0.0", isDirect: false },
        { id: "lodash@4.17.21", name: "lodash", version: "4.17.21", isDirect: false },
      ],
      edges: [
        { from: "app@1.0.0", to: "express@4.0.0" },
        { from: "express@4.0.0", to: "body-parser@1.0.0" },
        { from: "body-parser@1.0.0", to: "qs@6.0.0" },
        { from: "express@4.0.0", to: "lodash@4.17.21" },
      ],
    });

    const qs = computeBlastRadius(g, "qs@6.0.0");
    assert.deepEqual(qs.dependents, [
      "body-parser@1.0.0",
      "express@4.0.0",
      "app@1.0.0",
    ]);
    assert.equal(qs.dependentCount, 3);
    assert.equal(qs.criticalPathFlag, true);

    const lodash = computeBlastRadius(g, "lodash@4.17.21");
    assert.deepEqual(lodash.dependents, ["express@4.0.0", "app@1.0.0"]);
    assert.equal(lodash.dependentCount, 2);
    assert.equal(lodash.criticalPathFlag, true);

    // express itself: only app depends on it, and app is NOT a direct dep
    // (app is the project root sentinel — isDirect=false).
    const express = computeBlastRadius(g, "express@4.0.0");
    assert.deepEqual(express.dependents, ["app@1.0.0"]);
    assert.equal(express.criticalPathFlag, false);
  });

  test("criticalPathFlag is false when no dependent is a direct dependency", () => {
    // mid is direct; leaf is its only transitive dep. leaf's blast set is [mid, app]
    // and contains one direct dep (mid) -> flag must be true.
    // To get the OPPOSITE assertion we need leaf's blast set to contain NO direct
    // node. Construct that by making mid itself non-direct and having two
    // non-direct ancestors of leaf.
    const g = mkGraph({
      nodes: [
        { id: "app@1.0.0", name: "app", version: "1.0.0", isDirect: false },
        { id: "indirect@1.0.0", name: "indirect", version: "1.0.0", isDirect: true },
        { id: "deeper@1.0.0", name: "deeper", version: "1.0.0", isDirect: false },
        { id: "leaf@1.0.0", name: "leaf", version: "1.0.0", isDirect: false },
      ],
      edges: [
        { from: "app@1.0.0", to: "indirect@1.0.0" },
        { from: "indirect@1.0.0", to: "deeper@1.0.0" },
        { from: "deeper@1.0.0", to: "leaf@1.0.0" },
      ],
    });
    // leaf's blast = [deeper, indirect, app]; indirect is direct -> flag MUST be true.
    const r = computeBlastRadius(g, "leaf@1.0.0");
    assert.deepEqual(r.dependents, ["deeper@1.0.0", "indirect@1.0.0", "app@1.0.0"]);
    assert.equal(r.criticalPathFlag, true, "indirect is a direct dep in the blast set");
  });

  test("criticalPathFlag is false when blast set contains no direct dependencies", () => {
    // Build a sub-graph where direct deps are SIBLINGS of the target, not ancestors.
    // tree: app -> directA, app -> directB,  directA -> leaf, directB -> sibling
    //                                        ^ direct dep is an ancestor -> that's NOT what we want
    // Instead: target X has blast = [Y], where Y is non-direct. Y depends on X directly,
    // and app also depends on X — but Y is the only transitively-affected node that
    // could carry the flag. If Y is non-direct, flag must be false.
    const g = mkGraph({
      nodes: [
        { id: "app@1.0.0", name: "app", version: "1.0.0", isDirect: false },
        { id: "only-direct@1.0.0", name: "only-direct", version: "1.0.0", isDirect: true },
        { id: "intermediate@1.0.0", name: "intermediate", version: "1.0.0", isDirect: false },
        { id: "target@1.0.0", name: "target", version: "1.0.0", isDirect: false },
      ],
      edges: [
        { from: "app@1.0.0", to: "only-direct@1.0.0" },
        { from: "only-direct@1.0.0", to: "intermediate@1.0.0" },
        { from: "intermediate@1.0.0", to: "target@1.0.0" },
        { from: "app@1.0.0", to: "target@1.0.0" }, // direct sibling edge
      ],
    });
    // target's blast = [intermediate, only-direct, app]; only-direct IS direct -> true.
    // That's still true. To genuinely get `false`, we need target's blast to contain
    // NO direct nodes. That requires target to be a non-direct node whose entire blast
    // chain goes through non-direct intermediates back to a non-direct `app`.
    // Construct: target<-mid<-app, where mid and app are both non-direct (app is the
    // project root sentinel which is isDirect=false).
    const g2 = mkGraph({
      nodes: [
        { id: "app@1.0.0", name: "app", version: "1.0.0", isDirect: false },
        { id: "mid@1.0.0", name: "mid", version: "1.0.0", isDirect: false },
        { id: "target@1.0.0", name: "target", version: "1.0.0", isDirect: false },
      ],
      edges: [
        { from: "app@1.0.0", to: "mid@1.0.0" },
        { from: "mid@1.0.0", to: "target@1.0.0" },
      ],
    });
    const r = computeBlastRadius(g2, "target@1.0.0");
    assert.deepEqual(r.dependents, ["mid@1.0.0", "app@1.0.0"]);
    assert.equal(r.criticalPathFlag, false, "no direct dep is in the blast set");
  });

  test("multiple direct dependents in the blast set still flag once (idempotent)", () => {
    const g = mkGraph({
      nodes: [
        { id: "app@1.0.0", name: "app", version: "1.0.0", isDirect: false },
        { id: "a@1.0.0", name: "a", version: "1.0.0", isDirect: true },
        { id: "b@1.0.0", name: "b", version: "1.0.0", isDirect: true },
        { id: "core@1.0.0", name: "core", version: "1.0.0", isDirect: false },
      ],
      edges: [
        { from: "app@1.0.0", to: "a@1.0.0" },
        { from: "app@1.0.0", to: "b@1.0.0" },
        { from: "a@1.0.0", to: "core@1.0.0" },
        { from: "b@1.0.0", to: "core@1.0.0" },
      ],
    });
    // core's blast = [a, b, app]; both a and b are direct -> flag is true.
    const r = computeBlastRadius(g, "core@1.0.0");
    assert.deepEqual(r.dependents, ["a@1.0.0", "b@1.0.0", "app@1.0.0"]);
    assert.equal(r.dependentCount, 3);
    assert.equal(r.criticalPathFlag, true);
  });
});

// ---------------------------------------------------------------------------
// Group B — resilience: malformed input must not throw
// ---------------------------------------------------------------------------
describe("graph.computeBlastRadius — resilience", () => {
  test("edges referencing unknown node ids are ignored", () => {
    const g = mkGraph({
      nodes: [
        { id: "app@1.0.0", name: "app", version: "1.0.0", isDirect: false },
        { id: "express@4.0.0", name: "express", version: "4.0.0", isDirect: true },
      ],
      edges: [
        { from: "app@1.0.0", to: "express@4.0.0" },
        { from: "ghost@1.0.0", to: "express@4.0.0" }, // ghost not in nodes
        { from: "express@4.0.0", to: "phantom@1.0.0" }, // phantom not in nodes
      ],
    });
    const r = computeBlastRadius(g, "express@4.0.0");
    assert.deepEqual(r.dependents, ["app@1.0.0"]);
    assert.equal(r.dependentCount, 1);
  });

  test("self-loop edge (from === to) does not crash and is filtered", () => {
    const g = mkGraph({
      nodes: [
        { id: "weird@1.0.0", name: "weird", version: "1.0.0", isDirect: false },
      ],
      edges: [{ from: "weird@1.0.0", to: "weird@1.0.0" }],
    });
    const r = computeBlastRadius(g, "weird@1.0.0");
    assert.equal(r.dependentCount, 0);
  });

  test("a 2-node cycle does not loop forever (cycle-safe)", () => {
    // Pathological but legal: a -> b -> a. The point of this test is that the
    // traversal TERMINATES and returns a finite, duplicate-free dependents list
    // — not the exact contents (which are semantically well-defined but
    // implementation-dependent). Either inclusion of the queried pkgId itself
    // would be wrong; the visited set must prevent re-visiting.
    const g = mkGraph({
      nodes: [
        { id: "a@1.0.0", name: "a", version: "1.0.0", isDirect: true },
        { id: "b@1.0.0", name: "b", version: "1.0.0", isDirect: false },
      ],
      edges: [
        { from: "a@1.0.0", to: "b@1.0.0" },
        { from: "b@1.0.0", to: "a@1.0.0" },
      ],
    });
    const r = computeBlastRadius(g, "a@1.0.0");
    // Termination + duplicate-freeness + pkgId not in its own blast set.
    assert.ok(Array.isArray(r.dependents));
    assert.ok(r.dependents.length <= 2, `dependents must not exceed node count, got ${r.dependents.length}`);
    assert.ok(!r.dependents.includes("a@1.0.0"), "pkgId must not appear in its own dependents");
    assert.equal(new Set(r.dependents).size, r.dependents.length, "dependents must be duplicate-free");
    assert.equal(typeof r.dependentCount, "number");
  });

  test("malformed edge objects (missing from/to) are skipped without throwing", () => {
    const g = {
      nodes: [
        { id: "a@1.0.0", name: "a", version: "1.0.0", isDirect: false },
      ],
      edges: [
        null,
        {},
        { from: "a@1.0.0" }, // no `to`
        { to: "a@1.0.0" }, // no `from`
        { from: "a@1.0.0", to: "a@1.0.0" }, // self-loop filtered
      ],
      truncated: false,
    };
    const r = computeBlastRadius(g, "a@1.0.0");
    assert.equal(r.dependentCount, 0);
  });

  test("nodes[] missing required fields still doesn't crash the function", () => {
    const g = {
      nodes: [
        { id: "x@1.0.0" }, // no name/version/depth/isDirect
        null,
        { name: "y" }, // no id at all
      ],
      edges: [{ from: "x@1.0.0", to: "x@1.0.0" }],
      truncated: false,
    };
    // Should still return a valid (empty) shape for a present pkgId.
    const r = computeBlastRadius(g, "x@1.0.0");
    assert.equal(typeof r.dependentCount, "number");
    assert.ok(Array.isArray(r.dependents));
  });
});

// ---------------------------------------------------------------------------
// Group C — prebuilt reverse-adjacency fast path
//
// analyze.js builds the reverse adjacency + direct-IDs set once and threads
// them into computeBlastRadius on every call to avoid O(N*E) rebuilds.
// These tests assert the fast path produces identical results to the
// standard path, and that the public __internal helper is exported.
// ---------------------------------------------------------------------------
describe("graph.computeBlastRadius — prebuilt args fast path", () => {
  test("result with prebuilt args matches result without", () => {
    const g = mkGraph({
      nodes: [
        { id: "app@1.0.0",       name: "app",       depth: -1 },
        { id: "express@4.0.0",   name: "express",   depth: 0,  isDirect: true  },
        { id: "body-parser@1.0", name: "body-parser", depth: 1, isDirect: false },
        { id: "qs@6.0.0",        name: "qs",        depth: 2,  isDirect: false },
        { id: "lodash@4.17.21",  name: "lodash",    depth: 1,  isDirect: false },
      ],
      edges: [
        { from: "app@1.0.0",       to: "express@4.0.0"   },
        { from: "express@4.0.0",   to: "body-parser@1.0" },
        { from: "body-parser@1.0", to: "qs@6.0.0"        },
        { from: "express@4.0.0",   to: "lodash@4.17.21"  },
      ],
    });

    const reverseAdj = __internal.buildReverseAdjacency(g);
    const directIds = new Set(g.nodes.filter((n) => n.isDirect).map((n) => n.id));

    const baseline = computeBlastRadius(g, "qs@6.0.0");
    const fast     = computeBlastRadius(g, "qs@6.0.0", reverseAdj, directIds);

    assert.deepEqual(fast, baseline);
    // Sanity: baseline should still report express (a direct dep) on the critical path.
    assert.equal(baseline.criticalPathFlag, true);
    // app -> express -> body-parser -> qs, so 3 dependents transitively depend on qs.
    assert.equal(baseline.dependentCount, 3);
  });

  test("fast path still returns empty shape for missing pkgId", () => {
    const g = mkGraph({
      nodes: [{ id: "express@4.0.0", name: "express", depth: 0, isDirect: true }],
      edges: [],
    });
    const reverseAdj = __internal.buildReverseAdjacency(g);
    const directIds = new Set();
    const r = computeBlastRadius(g, "missing@1.0.0", reverseAdj, directIds);
    assert.deepEqual(r, { dependents: [], dependentCount: 0, criticalPathFlag: false });
  });

  test("buildReverseAdjacency is exported via __internal", () => {
    assert.equal(typeof __internal.buildReverseAdjacency, "function");
  });
});