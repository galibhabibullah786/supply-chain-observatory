// Single responsibility: calculate an explainable deterministic numeric risk score for a finding.
//
// Contract:
//   Input:
//     finding = { cvssScore: number|null|undefined, exploitabilityInContext: number (0-1) }
//     blastRadius = { dependentCount: number, criticalPathFlag: boolean }
//   Output:
//     RiskScore {
//       score: number,                      // integer 0..100
//       breakdown: {
//         cvssContribution: number,         // pre-rounding numeric contribution (0..~0.4)
//         exploitabilityContribution: number,// pre-rounding numeric contribution (0..~0.35)
//         blastRadiusContribution: number,  // pre-rounding numeric contribution (0..~0.25)
//         criticalPathBoost: number         // 0 or 0.15
//       }
//     }
//
// Notes:
//   - Pure, deterministic, auditable math. NO ML, NO AI. The point of this module is that a
//     security engineer can defend every coefficient live in front of a judge.
//   - Coefficients: CVSS 0.40, exploitability 0.35, blast radius 0.25, critical-path boost +0.15.
//     Sum of maxima = 0.40 + 0.35 + 0.25 + 0.15 = 1.15, which is intentionally > 1; the final
//     Math.min(..., 100) clamp prevents overflow into >100.
//   - We return the pre-rounding contributions so the UI can show "why" a score is what it is.
//     Transparency is itself a feature — explainable risk scoring.
//
// Examples:
//   1) High CVSS, high exploitability, many dependents, on critical path:
//      finding = { cvssScore: 9.8, exploitabilityInContext: 0.9 }
//      blastRadius = { dependentCount: 25, criticalPathFlag: true }
//        normalizedCvss = 9.8/10 = 0.98 -> cvss contribution      = 0.98 * 0.40 = 0.392
//        exploitability contribution                                = 0.90 * 0.35 = 0.315
//        blastRadius factor = min(25/10, 1) = 1.0 -> contribution   = 1.00 * 0.25 = 0.250
//        criticalPathBoost                                        = 0.15
//        raw = 0.392 + 0.315 + 0.250 + 0.15 = 1.107 -> 110.7 -> clamped to 100
//      => { score: 100, breakdown: { cvssContribution: 0.392, exploitabilityContribution: 0.315,
//           blastRadiusContribution: 0.25, criticalPathBoost: 0.15 } }
//
//   2) Missing CVSS, low exploitability, isolated:
//      finding = { cvssScore: null, exploitabilityInContext: 0.2 }
//      blastRadius = { dependentCount: 1, criticalPathFlag: false }
//        normalizedCvss defaults to 5/10 = 0.5 -> contribution       = 0.5  * 0.40 = 0.200
//        exploitability contribution                                 = 0.2  * 0.35 = 0.070
//        blastRadius factor = min(1/10, 1) = 0.1 -> contribution     = 0.1  * 0.25 = 0.025
//        criticalPathBoost                                          = 0
//        raw = 0.200 + 0.070 + 0.025 + 0 = 0.295 -> 29.5 -> rounded 30
//      => { score: 30, breakdown: { cvssContribution: 0.2, exploitabilityContribution: 0.07,
//           blastRadiusContribution: 0.025, criticalPathBoost: 0 } }
//
//   3) Low CVSS, mid exploitability, mid dependents, not on critical path:
//      finding = { cvssScore: 4.0, exploitabilityInContext: 0.5 }
//      blastRadius = { dependentCount: 5, criticalPathFlag: false }
//        normalizedCvss = 4/10 = 0.4 -> contribution                = 0.4 * 0.40 = 0.160
//        exploitability contribution                                 = 0.5 * 0.35 = 0.175
//        blastRadius factor = min(5/10, 1) = 0.5 -> contribution     = 0.5 * 0.25 = 0.125
//        raw = 0.160 + 0.175 + 0.125 + 0 = 0.46 -> 46
//      => { score: 46, breakdown: { cvssContribution: 0.16, exploitabilityContribution: 0.175,
//           blastRadiusContribution: 0.125, criticalPathBoost: 0 } }

const W_CVSS = 0.40;
const W_EXPLOIT = 0.35;
const W_BLAST = 0.25;
const CRITICAL_BOOST = 0.15;
const CVSS_DEFAULT = 5;            // medium severity when CVSS missing
const BLAST_CAP_DEPENDENTS = 10;   // saturation point for blast radius factor

function clampUnit(x) {
  if (typeof x !== "number" || Number.isNaN(x)) return 0;
  if (x < 0) return 0;
  if (x > 1) return 1;
  return x;
}

function safeNumber(x, fallback) {
  return typeof x === "number" && !Number.isNaN(x) ? x : fallback;
}

/**
 * Public entry point. Returns RiskScore.
 */
export function computeRiskScore(finding, blastRadius) {
  const f = finding || {};
  const br = blastRadius || {};

  // Normalize CVSS to 0..1, defaulting to medium (5/10) when missing/invalid.
  const rawCvss = safeNumber(f.cvssScore, CVSS_DEFAULT);
  const normalizedCvss = clampUnit(rawCvss / 10);

  // Clamp exploitability defensively; bad AI output should never propagate garbage.
  const exploitability = clampUnit(safeNumber(f.exploitabilityInContext, 0));

  // Blast radius factor saturates at 10+ dependents.
  const dependents = safeNumber(br.dependentCount, 0);
  const blastRadiusFactor = clampUnit(dependents / BLAST_CAP_DEPENDENTS);

  const criticalPathFlag = br.criticalPathFlag === true;
  const criticalPathBoost = criticalPathFlag ? CRITICAL_BOOST : 0;

  const cvssContribution = normalizedCvss * W_CVSS;
  const exploitabilityContribution = exploitability * W_EXPLOIT;
  const blastRadiusContribution = blastRadiusFactor * W_BLAST;

  const rawScore =
    cvssContribution +
    exploitabilityContribution +
    blastRadiusContribution +
    criticalPathBoost;

  const score = Math.min(Math.round(rawScore * 100), 100);

  return {
    score,
    breakdown: {
      cvssContribution,
      exploitabilityContribution,
      blastRadiusContribution,
      criticalPathBoost,
    },
  };
}

// Internal constants exposed for tests / inspection.
export const __weights = {
  W_CVSS,
  W_EXPLOIT,
  W_BLAST,
  CRITICAL_BOOST,
  CVSS_DEFAULT,
  BLAST_CAP_DEPENDENTS,
};