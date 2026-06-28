// Single responsibility: compute deterministic dependency impact traversal metrics from a graph.

/**
 * Input: DependencyGraph { nodes, edges } and a package id.
 * Output: BlastRadius { dependents, dependentCount, criticalPathFlag }.
 */
export function computeBlastRadius(graph, pkgId) {
  // TODO: Walk reverse dependency edges to find all dependents of pkgId.
  return {
    dependents: [],
    dependentCount: 0,
    criticalPathFlag: false
  };
}
