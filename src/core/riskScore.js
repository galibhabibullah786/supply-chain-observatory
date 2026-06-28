// Single responsibility: calculate an explainable deterministic numeric risk score for a finding.

/**
 * Input: ThreatFinding plus BlastRadius.
 * Output: RiskScore { score, breakdown }.
 */
export function computeRiskScore(finding, blastRadius) {
  // TODO: Combine CVSS, exploitability, and blast radius into a transparent 0-100 score.
  return {
    score: 0,
    breakdown: {
      cvssContribution: 0,
      exploitabilityContribution: 0,
      blastRadiusContribution: 0,
      criticalPathBoost: 0
    }
  };
}
