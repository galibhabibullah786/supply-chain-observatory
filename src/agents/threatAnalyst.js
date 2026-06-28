// Single responsibility: inspect dependency graph nodes for CVEs and assess exploitability in context.

/**
 * Input: DependencyGraph { nodes, edges }.
 * Output: ThreatFinding[] with vulnerability and exploitability context for affected packages.
 */
export async function analyzeThreats(graph) {
  // TODO: Query NVD for each package and use Gemini to assess context-specific exploitability.
  return [];
}
