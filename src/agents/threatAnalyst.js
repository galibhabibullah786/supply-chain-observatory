// Single responsibility: walk a DependencyGraph, look up CVEs from NVD for each
// package, and use Gemini to assess context-specific exploitability. Designed
// for live demos: concurrency-capped, defensive against AI hallucinations,
// never crashes the pipeline on a single bad response.

import { lookupCves } from "../clients/nvdClient.js";
import { callGemini } from "../clients/geminiClient.js";

const MAX_CONCURRENT_LOOKUPS = 5;
const DEFAULT_EXPLOITABILITY = 0.5;
const DEFAULT_RATIONALE = "Unable to assess automatically.";

// ---------------------------------------------------------------------------
// Concurrency-limited map over graph nodes. Uses a simple worker-pool pattern:
// up to MAX_CONCURRENT_LOOKUPS promises run at a time, results accumulate.
// ---------------------------------------------------------------------------

async function mapWithConcurrencyLocal(items, limit, fn) {
  const results = new Array(items.length);
  let cursor = 0;

  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (true) {
      const index = cursor++;
      if (index >= items.length) return;
      try {
        results[index] = await fn(items[index], index);
      } catch (err) {
        // fn should never throw (we wrap internally), but just in case:
        console.warn(`[threatAnalyst] worker error at index ${index}: ${err?.message ?? err}`);
        results[index] = [];
      }
    }
  });

  await Promise.all(workers);
  return results;
}

// ---------------------------------------------------------------------------
// Per-package analysis: NVD lookup -> per-CVE Gemini exploitability call.
// ---------------------------------------------------------------------------

async function analyzePackage(node) {
  let cves = [];
  try {
    cves = await lookupCves(node.name, node.version);
  } catch (err) {
    console.warn(`[threatAnalyst] NVD lookup threw for ${node.name}: ${err?.message ?? err}`);
    cves = [];
  }

  if (!Array.isArray(cves) || cves.length === 0) {
    return [];
  }

  // One Gemini call per CVE. We don't parallelize per-CVE because per-package
  // already gives us 5-wide concurrency and we want to conserve API quota.
  const findings = [];
  for (const cve of cves) {
    const finding = await buildFindingForCve(node, cve);
    findings.push(finding);
  }
  return findings;
}

async function buildFindingForCve(node, cve) {
  const { exploitabilityInContext, rationale } = await scoreExploitability(node, cve);
  return {
    pkgId: node.id,                       // matches graph node.id, e.g. "lodash@4.17.20"
    packageName: node.name,
    version: node.version ?? null,        // attached so businessAdvisor prompts can reference it
    depth: node.depth,
    isDirect: node.isDirect,
    cveId: cve.cveId,
    description: cve.description,
    cvssScore: cve.cvssScore,             // 0-10 or null
    cvssSeverity: cve.cvssSeverity,       // "LOW"|"MEDIUM"|"HIGH"|"CRITICAL"|null
    exploitabilityInContext,              // 0-1
    geminiRationale: rationale,
    publishedDate: cve.publishedDate,
  };
}

async function scoreExploitability(node, cve) {
  const depthLabel = node.isDirect
    ? "a DIRECT dependency of the application"
    : `a TRANSITIVE dependency at depth ${node.depth} (not chosen directly by the team)`;

  const prompt = `You are a security analyst assessing whether a known CVE is realistically exploitable in the specific context where the vulnerable package is being used.

PACKAGE CONTEXT
- Package name: ${node.name} (version ${node.version})
- Role in project: ${depthLabel}
- CVE ID: ${cve.cveId}
- CVSS base score: ${cve.cvssScore ?? "unknown"}
- CVSS severity: ${cve.cvssSeverity ?? "unknown"}

CVE DESCRIPTION
${cve.description || "(no description available)"}

TASK
Assess how exploitable this CVE is IN THIS SPECIFIC CONTEXT, considering:
1. Whether the vulnerability typically requires user interaction, network access, local access, or specific configurations
2. Whether the vulnerable code path is likely reachable through how a typical application uses this package
3. Whether being transitive vs direct changes the realistic risk
4. Whether known exploitation in the wild has been reported for this kind of bug

OUTPUT FORMAT — STRICT JSON ONLY, no markdown fences, no commentary before or after:
{
  "exploitabilityInContext": <float between 0.0 and 1.0>,
  "rationale": "<one or two sentences in plain English, no jargon>"
}

IMPORTANT RULES
- Do not invent details. If the CVE description does not give enough information to assess context-specific exploitability, set exploitabilityInContext to 0.5 and say why in the rationale.
- 0.0 means essentially unreachable in this context; 1.0 means trivially exploitable on a typical install.
- Be calibrated: most CVEs in transitive dependencies are NOT trivially exploitable.`;

  try {
    const raw = await callGemini(prompt, {
      model: process.env.GEMINI_MODEL || "gemini-2.0-flash",
      temperature: 0.2,
      responseMimeType: "application/json",
    });
    return parseExploitabilityJson(raw);
  } catch (err) {
    console.warn(`[threatAnalyst] Gemini call failed for ${node.name} ${cve.cveId}: ${err?.message ?? err}`);
    return { exploitabilityInContext: DEFAULT_EXPLOITABILITY, rationale: DEFAULT_RATIONALE };
  }
}

function parseExploitabilityJson(raw) {
  if (typeof raw !== "string" || raw.length === 0) {
    return { exploitabilityInContext: DEFAULT_EXPLOITABILITY, rationale: DEFAULT_RATIONALE };
  }

  // Strip markdown code fences if Gemini returned ```json ... ``` despite our instructions.
  let cleaned = raw.trim();
  const fenceMatch = cleaned.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  if (fenceMatch) {
    cleaned = fenceMatch[1].trim();
  }

  let parsed;
  try {
    parsed = JSON.parse(cleaned);
  } catch {
    // Gemini sometimes wraps JSON in extra prose — try to extract the first {...} block.
    const braceMatch = cleaned.match(/\{[\s\S]*\}/);
    if (braceMatch) {
      try {
        parsed = JSON.parse(braceMatch[0]);
      } catch {
        return { exploitabilityInContext: DEFAULT_EXPLOITABILITY, rationale: DEFAULT_RATIONALE };
      }
    } else {
      return { exploitabilityInContext: DEFAULT_EXPLOITABILITY, rationale: DEFAULT_RATIONALE };
    }
  }

  const rawScore = Number(parsed?.exploitabilityInContext);
  const exploitabilityInContext = Number.isFinite(rawScore)
    ? Math.min(1, Math.max(0, rawScore))
    : DEFAULT_EXPLOITABILITY;

  const rationale =
    typeof parsed?.rationale === "string" && parsed.rationale.trim().length > 0
      ? parsed.rationale.trim()
      : DEFAULT_RATIONALE;

  return { exploitabilityInContext, rationale };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Analyze a dependency graph for CVEs and context-specific exploitability.
 *
 * Input: graph = { nodes: [{ id, name, version, depth, isDirect }], edges: [...] }
 * Output: ThreatFinding[] (empty entries omitted — clean packages produce no findings)
 */
export async function analyzeThreats(graph) {
  if (!graph || !Array.isArray(graph.nodes) || graph.nodes.length === 0) {
    return [];
  }

  console.log(`[threatAnalyst] analyzing ${graph.nodes.length} packages (concurrency=${MAX_CONCURRENT_LOOKUPS})`);

  const perPackage = await mapWithConcurrencyLocal(graph.nodes, MAX_CONCURRENT_LOOKUPS, analyzePackage);

  // Flatten and drop empty results (packages with no CVEs found).
  const findings = perPackage.flat().filter((f) => f && f.cveId);
  console.log(`[threatAnalyst] produced ${findings.length} findings`);

  return findings;
}

// ---------------------------------------------------------------------------
// Test hooks — internal helpers exposed for unit tests only. Not part of the
// public agent API. Prefix with underscore to mark as such.
// ---------------------------------------------------------------------------

/**
 * Parse Gemini's JSON response defensively. Exported only so unit tests can
 * exercise the fallback paths without spinning up a real Gemini client.
 */
export const _parseExploitabilityJson = parseExploitabilityJson;

/**
 * Worker-pool concurrency-capped map. Exported so other modules (e.g. the
 * /analyze orchestration route for batched Gemini narrative calls) can reuse
 * the same pattern instead of re-implementing it.
 */
export const mapWithConcurrency = mapWithConcurrencyLocal;
