// Single responsibility: orchestrate the full analysis pipeline behind POST /analyze.
//
// Robustness notes:
//   - try/catch around the pipeline so a bad manifest or downstream crash returns
//     a clean 500 JSON instead of hanging or spewing a stack trace.
//   - Fixture fallback is server-side so the demo still works when the request
//     body is empty or missing.
import express from "express";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { buildDependencyGraph } from "../agents/dependencyScout.js";
import { analyzeThreats, mapWithConcurrency } from "../agents/threatAnalyst.js";
import { generateNarrative, NARRATIVE_SCORE_THRESHOLD } from "../agents/businessAdvisor.js";
import { computeBlastRadius, __internal as graphInternal } from "../core/graph.js";
import { computeRiskScore } from "../core/riskScore.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Resolved relative to this file so the route works regardless of process.cwd()
// (matters for `npm start` vs `node src/server.js` vs container).
const FIXTURE_PATH = path.join(__dirname, "..", "..", "test-fixtures", "sample-package.json");

// Cap Gemini narrative calls so a wave of high-risk findings doesn't spike the API.
const NARRATIVE_CONCURRENCY = 3;

async function loadFixtureManifest() {
  try {
    const raw = await fs.readFile(FIXTURE_PATH, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    console.warn(`[analyze] could not load fallback fixture at ${FIXTURE_PATH}: ${err?.message ?? err}`);
    return null;
  }
}

async function resolveManifest(body) {
  // Case 1: explicit wrapper { manifest: {...} }
  if (body && typeof body === "object" && body.manifest && typeof body.manifest === "object") {
    return { manifest: body.manifest, source: "request:wrapped" };
  }
  // Case 2: body IS the manifest (has name + dependencies)
  if (
    body &&
    typeof body === "object" &&
    (body.dependencies || body.devDependencies) &&
    typeof body.name === "string"
  ) {
    return { manifest: body, source: "request:bare" };
  }
  // Case 3: nothing useful — use the demo fixture
  const fixture = await loadFixtureManifest();
  if (fixture) return { manifest: fixture, source: "fixture" };
  return { manifest: null, source: "none" };
}

const router = express.Router();

router.post("/analyze", async (req, res) => {
  const startedAt = Date.now();
  const startedIso = new Date(startedAt).toISOString();

  const { manifest, source } = await resolveManifest(req.body);
  if (!manifest) {
    return res.status(400).json({
      error: "no_manifest",
      message:
        "Request body did not contain a valid package.json manifest and the demo fallback fixture could not be loaded.",
    });
  }

  console.log(`[analyze] ${startedIso} start manifest="${manifest.name ?? "(unnamed)"}" source=${source}`);

  try {
    const graph = await buildDependencyGraph(manifest);
    console.log(
      `[analyze] graph built: ${graph.nodes.length} nodes, ${graph.edges.length} edges, truncated=${graph.truncated === true}`
    );

    const rawFindings = await analyzeThreats(graph);
    console.log(`[analyze] threat analysis produced ${rawFindings.length} findings`);

    // Build reverse adjacency + direct-IDs set ONCE; computeBlastRadius would
    // otherwise rebuild them per finding (O(N*E) on a 200-node graph).
    const reverseAdj = graphInternal.buildReverseAdjacency(graph);
    const directIds = new Set(
      (graph.nodes || []).filter((n) => n && n.isDirect).map((n) => n.id)
    );

    const enriched = rawFindings.map((finding) => {
      const blastRadius = computeBlastRadius(graph, finding.pkgId, reverseAdj, directIds);
      const riskScore = computeRiskScore(finding, blastRadius);
      return { ...finding, blastRadius, riskScore };
    });

    // Narrative generation: only for findings above threshold, capped concurrency.
    const highRisk = enriched
      .map((f, i) => ({ f, i }))
      .filter(({ f }) => f.riskScore && f.riskScore.score >= NARRATIVE_SCORE_THRESHOLD);

    if (highRisk.length > 0) {
      console.log(`[analyze] generating narratives for ${highRisk.length} high-risk findings (concurrency=${NARRATIVE_CONCURRENCY})`);
      const narratives = await mapWithConcurrency(highRisk, NARRATIVE_CONCURRENCY, async ({ f }) => {
        return generateNarrative(f, f.blastRadius, f.riskScore);
      });
      for (let k = 0; k < highRisk.length; k++) {
        enriched[highRisk[k].i].narrative = narratives[k];
      }
    }

    const report = {
      graph,
      findings: enriched,
      generatedAt: new Date().toISOString(),
      truncated: graph.truncated === true,
      manifest: { name: manifest.name ?? null, version: manifest.version ?? null },
      inputSource: source,
    };

    const elapsedMs = Date.now() - startedAt;
    console.log(`[analyze] done in ${elapsedMs}ms`);

    return res.status(200).json(report);
  } catch (err) {
    const elapsedMs = Date.now() - startedAt;
    console.error(`[analyze] pipeline failed after ${elapsedMs}ms:`, err);
    return res.status(500).json({
      error: "analysis_failed",
      message: err?.message ?? "Unknown error during analysis pipeline.",
      durationMs: elapsedMs,
    });
  }
});

export default router;