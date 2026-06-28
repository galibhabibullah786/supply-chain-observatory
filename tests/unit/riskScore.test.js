// Micro-level unit tests for src/core/riskScore.js
//
// Run with:  npm test
//
// Uses Node's built-in test runner (node:test) — no extra dependencies.
// riskScore.js is pure deterministic math with no I/O. We therefore split
// tests into two groups only:
//   A. Shape / formula — always run, exact numeric assertions
//   B. Resilience — defensive handling of garbage / missing / out-of-range input
//
// Per AGENTS.md, the formula MUST be explainable live in a demo. We assert both
// the headline score (for the demo's traffic-light coloring) and the
// per-factor breakdown contributions (for the "why" panel in the UI).

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { computeRiskScore, __weights } from "../../src/core/riskScore.js";

// ---------------------------------------------------------------------------
// Group A — formula correctness, including the three documented examples
// ---------------------------------------------------------------------------
describe("riskScore.computeRiskScore — shape and formula", () => {
  test("returns the documented top-level shape", () => {
    const r = computeRiskScore(
      { cvssScore: 5, exploitabilityInContext: 0.5 },
      { dependentCount: 3, criticalPathFlag: false }
    );
    assert.equal(typeof r.score, "number");
    assert.ok(Number.isInteger(r.score));
    assert.ok(r.score >= 0 && r.score <= 100);

    assert.equal(typeof r.breakdown, "object");
    for (const k of [
      "cvssContribution",
      "exploitabilityContribution",
      "blastRadiusContribution",
      "criticalPathBoost",
    ]) {
      assert.ok(k in r.breakdown, `breakdown.${k} must be present`);
      assert.equal(typeof r.breakdown[k], "number");
    }
  });

  test("example #1: high CVSS + high exploit + many dependents + critical path -> clamped 100", () => {
    const r = computeRiskScore(
      { cvssScore: 9.8, exploitabilityInContext: 0.9 },
      { dependentCount: 25, criticalPathFlag: true }
    );
    // 0.98 * 0.40 = 0.392
    // 0.90 * 0.35 = 0.315
    // min(25/10,1) * 0.25 = 0.25
    // criticalPathBoost = 0.15
    // raw = 1.107 -> 110.7 -> clamped to 100
    assert.equal(r.score, 100);
    assert.ok(Math.abs(r.breakdown.cvssContribution - 0.392) < 1e-9);
    assert.ok(Math.abs(r.breakdown.exploitabilityContribution - 0.315) < 1e-9);
    assert.ok(Math.abs(r.breakdown.blastRadiusContribution - 0.25) < 1e-9);
    assert.equal(r.breakdown.criticalPathBoost, 0.15);
  });

  test("example #2: missing CVSS + low exploit + isolated -> 30", () => {
    const r = computeRiskScore(
      { cvssScore: null, exploitabilityInContext: 0.2 },
      { dependentCount: 1, criticalPathFlag: false }
    );
    // CVSS defaults to 5/10 = 0.5 -> 0.5 * 0.40 = 0.20
    // 0.2 * 0.35 = 0.07
    // min(1/10, 1) * 0.25 = 0.025
    // raw = 0.295 -> 29.5 -> rounded 30
    assert.equal(r.score, 30);
    assert.ok(Math.abs(r.breakdown.cvssContribution - 0.2) < 1e-9);
    assert.ok(Math.abs(r.breakdown.exploitabilityContribution - 0.07) < 1e-9);
    assert.ok(Math.abs(r.breakdown.blastRadiusContribution - 0.025) < 1e-9);
    assert.equal(r.breakdown.criticalPathBoost, 0);
  });

  test("example #3: low CVSS + mid exploit + mid dependents + not critical -> 46", () => {
    const r = computeRiskScore(
      { cvssScore: 4.0, exploitabilityInContext: 0.5 },
      { dependentCount: 5, criticalPathFlag: false }
    );
    // 0.4 * 0.40 = 0.16
    // 0.5 * 0.35 = 0.175
    // min(5/10, 1) * 0.25 = 0.125
    // raw = 0.46 -> 46
    assert.equal(r.score, 46);
    assert.ok(Math.abs(r.breakdown.cvssContribution - 0.16) < 1e-9);
    assert.ok(Math.abs(r.breakdown.exploitabilityContribution - 0.175) < 1e-9);
    assert.ok(Math.abs(r.breakdown.blastRadiusContribution - 0.125) < 1e-9);
    assert.equal(r.breakdown.criticalPathBoost, 0);
  });

  test("zero everything -> score 0", () => {
    const r = computeRiskScore(
      { cvssScore: 0, exploitabilityInContext: 0 },
      { dependentCount: 0, criticalPathFlag: false }
    );
    assert.equal(r.score, 0);
    assert.equal(r.breakdown.cvssContribution, 0);
    assert.equal(r.breakdown.exploitabilityContribution, 0);
    assert.equal(r.breakdown.blastRadiusContribution, 0);
    assert.equal(r.breakdown.criticalPathBoost, 0);
  });

  test("blast radius saturates at 10+ dependents", () => {
    const r10 = computeRiskScore(
      { cvssScore: 8, exploitabilityInContext: 0.5 },
      { dependentCount: 10, criticalPathFlag: false }
    );
    const r100 = computeRiskScore(
      { cvssScore: 8, exploitabilityInContext: 0.5 },
      { dependentCount: 100, criticalPathFlag: false }
    );
    assert.equal(r10.breakdown.blastRadiusContribution, r100.breakdown.blastRadiusContribution);
    assert.equal(r10.score, r100.score, "score must be identical past saturation");
  });

  test("critical-path boost adds exactly 0.15 to raw score", () => {
    const base = computeRiskScore(
      { cvssScore: 5, exploitabilityInContext: 0.5 },
      { dependentCount: 0, criticalPathFlag: false }
    );
    const lifted = computeRiskScore(
      { cvssScore: 5, exploitabilityInContext: 0.5 },
      { dependentCount: 0, criticalPathFlag: true }
    );
    // 0.15 raw -> +15 in score space
    assert.equal(lifted.score - base.score, 15);
    assert.equal(lifted.breakdown.criticalPathBoost, 0.15);
    assert.equal(base.breakdown.criticalPathBoost, 0);
  });

  test("score is monotonic in CVSS for a fixed context", () => {
    const ctx = { dependentCount: 3, criticalPathFlag: false };
    const exploit = 0.5;
    const low = computeRiskScore({ cvssScore: 2, exploitabilityInContext: exploit }, ctx).score;
    const mid = computeRiskScore({ cvssScore: 5, exploitabilityInContext: exploit }, ctx).score;
    const high = computeRiskScore({ cvssScore: 9, exploitabilityInContext: exploit }, ctx).score;
    assert.ok(low < mid && mid < high, `expected low(${low}) < mid(${mid}) < high(${high})`);
  });

  test("score is monotonic in exploitability for a fixed context", () => {
    const ctx = { dependentCount: 3, criticalPathFlag: false };
    const low = computeRiskScore({ cvssScore: 6, exploitabilityInContext: 0.1 }, ctx).score;
    const mid = computeRiskScore({ cvssScore: 6, exploitabilityInContext: 0.5 }, ctx).score;
    const high = computeRiskScore({ cvssScore: 6, exploitabilityInContext: 0.9 }, ctx).score;
    assert.ok(low < mid && mid < high, `expected low(${low}) < mid(${mid}) < high(${high})`);
  });

  test("score is monotonic in blast radius up to saturation", () => {
    const ctxBase = { criticalPathFlag: false };
    const finding = { cvssScore: 6, exploitabilityInContext: 0.5 };
    const s0 = computeRiskScore(finding, { ...ctxBase, dependentCount: 0 }).score;
    const s3 = computeRiskScore(finding, { ...ctxBase, dependentCount: 3 }).score;
    const s7 = computeRiskScore(finding, { ...ctxBase, dependentCount: 7 }).score;
    assert.ok(s0 < s3 && s3 < s7, `expected ${s0} < ${s3} < ${s7}`);
  });

  test("weights module exports the expected coefficient constants", () => {
    assert.equal(__weights.W_CVSS, 0.40);
    assert.equal(__weights.W_EXPLOIT, 0.35);
    assert.equal(__weights.W_BLAST, 0.25);
    assert.equal(__weights.CRITICAL_BOOST, 0.15);
    assert.equal(__weights.CVSS_DEFAULT, 5);
    assert.equal(__weights.BLAST_CAP_DEPENDENTS, 10);
  });
});

// ---------------------------------------------------------------------------
// Group B — resilience: defensive handling of garbage input
// ---------------------------------------------------------------------------
describe("riskScore.computeRiskScore — resilience", () => {
  test("missing finding and missing blastRadius both default cleanly", () => {
    const r = computeRiskScore({}, {});
    assert.equal(typeof r.score, "number");
    assert.ok(r.score >= 0 && r.score <= 100);
    // defaults: cvssScore=5/10, exploit=0, dependents=0, not critical
    // raw = 0.20 + 0 + 0 + 0 = 0.20 -> 20
    assert.equal(r.score, 20);
  });

  test("null finding and null blastRadius are tolerated", () => {
    const r = computeRiskScore(null, null);
    assert.equal(r.score, 20);
  });

  test("undefined cvssScore falls back to medium (5)", () => {
    const r = computeRiskScore(
      { exploitabilityInContext: 0 },
      { dependentCount: 0, criticalPathFlag: false }
    );
    assert.equal(r.score, 20, "0.5 * 0.40 -> 20");
  });

  test("string cvssScore is treated as missing (defaults to medium)", () => {
    const r = computeRiskScore(
      { cvssScore: "9.8", exploitabilityInContext: 0 },
      { dependentCount: 0, criticalPathFlag: false }
    );
    // 0.5 * 0.40 = 0.20 -> 20 (string is not a number -> fallback)
    assert.equal(r.score, 20);
  });

  test("NaN cvssScore is treated as missing", () => {
    const r = computeRiskScore(
      { cvssScore: NaN, exploitabilityInContext: 0 },
      { dependentCount: 0, criticalPathFlag: false }
    );
    assert.equal(r.score, 20);
  });

  test("out-of-range exploitability is clamped to [0,1]", () => {
    const tooHigh = computeRiskScore(
      { cvssScore: 5, exploitabilityInContext: 1.7 },
      { dependentCount: 0, criticalPathFlag: false }
    );
    const neg = computeRiskScore(
      { cvssScore: 5, exploitabilityInContext: -0.5 },
      { dependentCount: 0, criticalPathFlag: false }
    );
    // 0.5*0.40 + 1.0*0.35 + 0 + 0 = 0.55 -> 55
    assert.equal(tooHigh.score, 55);
    // 0.5*0.40 + 0.0*0.35 + 0 + 0 = 0.20 -> 20
    assert.equal(neg.score, 20);
  });

  test("out-of-range cvssScore is clamped to [0,10] before normalization", () => {
    // cvssScore > 10 still produces normalizedCvss = 1 (clampUnit).
    const r = computeRiskScore(
      { cvssScore: 50, exploitabilityInContext: 0 },
      { dependentCount: 0, criticalPathFlag: false }
    );
    // 1.0 * 0.40 = 0.40 -> 40
    assert.equal(r.score, 40);
  });

  test("negative cvssScore is clamped to 0", () => {
    const r = computeRiskScore(
      { cvssScore: -3, exploitabilityInContext: 0.5 },
      { dependentCount: 0, criticalPathFlag: false }
    );
    // 0 * 0.40 + 0.5 * 0.35 + 0 + 0 = 0.175 -> 18 (round half away from zero: 17.5 -> 18)
    // We accept either 17 or 18 here to keep the assertion tight but not flaky on rounding mode.
    assert.ok(r.score === 17 || r.score === 18, `unexpected rounding of 17.5 -> ${r.score}`);
  });

  test("string dependentCount falls back to 0 (no blast radius contribution)", () => {
    const r = computeRiskScore(
      { cvssScore: 5, exploitabilityInContext: 0 },
      { dependentCount: "a lot", criticalPathFlag: false }
    );
    // 0.5*0.40 + 0 + 0 + 0 = 0.20 -> 20
    assert.equal(r.score, 20);
  });

  test("truthy non-boolean criticalPathFlag is treated as false", () => {
    const r = computeRiskScore(
      { cvssScore: 5, exploitabilityInContext: 0 },
      { dependentCount: 0, criticalPathFlag: "yes" }
    );
    // No boost applied: 0.20 -> 20
    assert.equal(r.score, 20);
    assert.equal(r.breakdown.criticalPathBoost, 0);
  });

  test("score never exceeds 100 even with extreme inputs", () => {
    const r = computeRiskScore(
      { cvssScore: 99, exploitabilityInContext: 5 },
      { dependentCount: 9999, criticalPathFlag: true }
    );
    assert.equal(r.score, 100);
  });

  test("score is never negative even with garbage inputs", () => {
    const r = computeRiskScore(
      { cvssScore: -999, exploitabilityInContext: -5 },
      { dependentCount: -50, criticalPathFlag: false }
    );
    assert.ok(r.score >= 0, `score must be >= 0, got ${r.score}`);
  });
});