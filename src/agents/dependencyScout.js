// Single responsibility: transform a package manifest into a dependency graph for downstream analysis.

/**
 * Input: parsed package.json manifest object.
 * Output: DependencyGraph { nodes: [{ id, name, version, depth, isDirect }], edges: [{ from, to }] }.
 */
export async function buildDependencyGraph(manifestJson) {
  // TODO: Resolve direct and transitive package dependencies from the npm registry.
  return {
    nodes: [],
    edges: [],
    truncated: false
  };
}
