// Single responsibility: convert high-risk technical findings into concise stakeholder-facing risk narratives.

/**
 * Input: ThreatFinding plus blast radius context.
 * Output: RiskNarrative { businessImpactSummary, recommendedAction }.
 */
export async function generateNarrative(finding, blastRadius) {
  // TODO: Use Gemini to generate a short business-impact explanation and one concrete action.
  return {
    businessImpactSummary: "",
    recommendedAction: ""
  };
}
