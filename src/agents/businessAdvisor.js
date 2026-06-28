// Single responsibility: turn high-risk technical findings into concise
// stakeholder-facing risk narratives using Gemini.
//
// Contract:
//   Input:
//     finding    = ThreatFinding {
//                    pkgId, packageName, cveId, cvssScore, cvssSeverity,
//                    exploitabilityInContext, geminiRationale, depth, isDirect
//                  }
//     blastRadius = { dependents: [pkgId], dependentCount, criticalPathFlag }
//     riskScore  = { score: number 0-100, breakdown: { ... } }   // optional
//   Output:
//     RiskNarrative { businessImpactSummary, recommendedAction }
//     -- OR null -- if riskScore.score < NARRATIVE_THRESHOLD (we conserve
//        Gemini quota and skip narratives for low-risk findings entirely).
//
// Design notes:
//   - Threshold gating happens BEFORE the API call. Low-risk findings get null
//     and no Gemini tokens are burned.
//   - Strict-JSON prompt + defensive parsing mirrors threatAnalyst.js so the
//     two agents feel consistent to the next reader.
//   - Module-level in-memory cache keyed by `${cveId}-${pkgId}` so calling
//     /api/analyze twice in a live demo doesn't double-bill the API.
//   - Cache and `_resetBusinessAdvisorForTests` mirror threatAnalyst's
//     testability surface.

import { callGemini } from "../clients/geminiClient.js";

// Below this risk score we don't generate a narrative. Per Prompt 5 spec.
const NARRATIVE_THRESHOLD = 50;

// Sensible defaults when Gemini returns garbage. Never crash the pipeline.
const FALLBACK_SUMMARY = "Manual review recommended.";
const FALLBACK_ACTION = "Review CVE details manually.";

// Module-level cache so the same finding isn't re-narrated twice in a demo.
// Key shape: `${cveId}-${pkgId}`. Cached values are the full narrative
// object OR null (so a previously-skipped finding stays skipped).
const narrativeCache = new Map();

function cacheKey(finding) {
  if (!finding || !finding.cveId || !finding.pkgId) return null;
  return `${finding.cveId}-${finding.pkgId}`;
}

// ---------------------------------------------------------------------------
// Prompt construction.
//
// Per Prompt 5: be specific, no generic security advice. The narrative is
// the highest-visibility output in the demo — judges read it out loud —
// so the prompt is deliberately prescriptive.
// ---------------------------------------------------------------------------

function buildPrompt(finding, blastRadius, riskScore) {
  const depthLabel = finding.isDirect
    ? "a DIRECT dependency the team explicitly chose to install"
    : `a TRANSITIVE dependency at depth ${finding.depth} (pulled in by another package, not chosen directly)`;

  const criticalPathNote = blastRadius?.criticalPathFlag
    ? "YES — at least one direct dependency of the project transitively depends on it, so a compromise propagates up to code the team chose to install."
    : "NO — no direct dependency of the project transitively depends on it.";

  return `You are writing a short, stakeholder-facing risk note for a non-technical reader (e.g. a product manager or engineering lead).

PACKAGE
- Name: ${finding.packageName} (version ${finding.version ?? "unknown"})
- Role: ${depthLabel}

CVE
- ID: ${finding.cveId}
- CVSS score: ${finding.cvssScore ?? "unknown"} (severity: ${finding.cvssSeverity ?? "unknown"})
- Description: ${finding.description || "(no description available)"}

EXPLOITABILITY (already assessed by a separate analyst step)
- In-context exploitability score (0-1): ${finding.exploitabilityInContext}
- Analyst rationale: ${finding.geminiRationale || "(none provided)"}

BLAST RADIUS
- Number of other packages in the project that transitively depend on this one: ${blastRadius?.dependentCount ?? 0}
- Is this on a critical path to a directly-installed dependency? ${criticalPathNote}

COMPOSITE RISK SCORE (0-100): ${riskScore?.score ?? "unknown"}

TASK
Write a SHORT (2-3 sentences) business-impact explanation aimed at a NON-TECHNICAL stakeholder. Answer concretely: if this CVE is exploited, what could happen to the system, and who / what is affected?

Then return ONE concrete recommended action. Examples of the kind of specificity we want:
- "Upgrade ${finding.packageName} to version X.Y.Z or later, which patches this CVE."
- "Investigate immediately — direct dependency with high in-context exploitability."
- "Defer: low-priority because no direct dependency transitively relies on it and the vulnerable code path is unlikely to be reachable in our usage."
- "Pin to ${finding.packageName}@<safe-version> via package.json overrides until upstream ships a fix."

OUTPUT FORMAT — STRICT JSON ONLY, no markdown fences, no commentary before or after:
{
  "businessImpactSummary": "<2-3 sentence plain-English impact>",
  "recommendedAction": "<one concrete, specific action>"
}

IMPORTANT RULES
- Be concrete and specific. Do not pad with generic security advice like "always keep dependencies updated" or "follow security best practices". Give an action specific to THIS finding.
- Do not invent details you were not given (no fictional version numbers, no invented user counts, no made-up system names).
- If the input genuinely does not give enough to assess business impact, set businessImpactSummary to "Insufficient context to assess business impact automatically." and recommendedAction to "Manually review CVE ${finding.cveId} against deployment usage of ${finding.packageName}."`;
}

// ---------------------------------------------------------------------------
// Defensive JSON parsing. Mirrors threatAnalyst._parseExploitabilityJson so
// the two agents share a recovery philosophy.
// ---------------------------------------------------------------------------

function parseNarrativeJson(raw) {
  if (typeof raw !== "string" || raw.length === 0) {
    return { businessImpactSummary: FALLBACK_SUMMARY, recommendedAction: FALLBACK_ACTION };
  }

  let cleaned = raw.trim();

  // Strip ```json ... ``` or ``` ... ``` fences if Gemini ignores our instructions.
  const fenceMatch = cleaned.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  if (fenceMatch) {
    cleaned = fenceMatch[1].trim();
  }

  let parsed;
  try {
    parsed = JSON.parse(cleaned);
  } catch {
    // Try to salvage a {...} block embedded in surrounding prose.
    const braceMatch = cleaned.match(/\{[\s\S]*\}/);
    if (braceMatch) {
      try {
        parsed = JSON.parse(braceMatch[0]);
      } catch {
        return { businessImpactSummary: FALLBACK_SUMMARY, recommendedAction: FALLBACK_ACTION };
      }
    } else {
      return { businessImpactSummary: FALLBACK_SUMMARY, recommendedAction: FALLBACK_ACTION };
    }
  }

  const businessImpactSummary =
    typeof parsed?.businessImpactSummary === "string" && parsed.businessImpactSummary.trim().length > 0
      ? parsed.businessImpactSummary.trim()
      : FALLBACK_SUMMARY;

  const recommendedAction =
    typeof parsed?.recommendedAction === "string" && parsed.recommendedAction.trim().length > 0
      ? parsed.recommendedAction.trim()
      : FALLBACK_ACTION;

  return { businessImpactSummary, recommendedAction };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Generate a stakeholder-facing narrative for a finding, or null if the
 * finding's risk score is below the threshold (so we don't waste Gemini
 * quota on low-risk findings).
 *
 * Pure from the caller's perspective except for:
 *   - the side effect of a Gemini API call when threshold is met,
 *   - the side effect of populating the in-memory cache.
 */
export async function generateNarrative(finding, blastRadius, riskScore) {
  // Defensive input handling — never throw on bad input.
  if (!finding || !finding.cveId || !finding.pkgId) {
    return null;
  }

  // Threshold gate. riskScore is optional in the function signature, but if
  // it's missing we treat the finding as below threshold (safe default:
  // don't burn quota on un-scored findings).
  const score = typeof riskScore?.score === "number" ? riskScore.score : -1;
  if (score < NARRATIVE_THRESHOLD) {
    return null;
  }

  // Cache lookup. Cached null = previously skipped; cached object = return it.
  const key = cacheKey(finding);
  if (key && narrativeCache.has(key)) {
    return narrativeCache.get(key);
  }

  const prompt = buildPrompt(finding, blastRadius, riskScore);

  let narrative;
  try {
    const raw = await callGemini(prompt, {
      model: process.env.GEMINI_MODEL || "gemini-2.0-flash",
      temperature: 0.3,
      responseMimeType: "application/json",
    });
    narrative = parseNarrativeJson(raw);
  } catch (err) {
    console.warn(`[businessAdvisor] Gemini call failed for ${finding.pkgId} ${finding.cveId}: ${err?.message ?? err}`);
    narrative = { businessImpactSummary: FALLBACK_SUMMARY, recommendedAction: FALLBACK_ACTION };
  }

  if (key) {
    narrativeCache.set(key, narrative);
  }
  return narrative;
}

// ---------------------------------------------------------------------------
// Test hooks (mirrors threatAnalyst's pattern).
// ---------------------------------------------------------------------------

/** Defensive narrative-JSON parser, exposed for unit tests. */
export const _parseNarrativeJson = parseNarrativeJson;

/** Build the prompt string, exposed so tests can assert prompt structure. */
export const _buildPrompt = buildPrompt;

/** Cache key builder, exposed for tests. */
export const _cacheKey = cacheKey;

/** Reset the module-level narrative cache. For tests only. */
export function _resetBusinessAdvisorForTests() {
  narrativeCache.clear();
}

/** Threshold constant, exposed so tests can reference it. */
export const NARRATIVE_SCORE_THRESHOLD = NARRATIVE_THRESHOLD;