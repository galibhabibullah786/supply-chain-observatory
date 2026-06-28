// Single responsibility: compute deterministic dependency impact traversal metrics from a graph.
//
// Contract:
//   Input  : DependencyGraph { nodes, edges } and a pkgId (string, e.g. "lodash@4.17.21")
//   Output : BlastRadius {
//              dependents: string[],           // pkgIds of every node that transitively depends on pkgId
//              dependentCount: number,         // length of dependents
//              criticalPathFlag: boolean       // true iff any node in dependents is a direct dependency
//            }
//
// Notes:
//   - Edges are stored as { from, to } meaning "from depends on to" (forward direction).
//   - "Blast radius" = everything that depends ON pkgId, so we walk edges BACKWARD.
//     Concretely: if A -> B (A depends on B) and pkgId === B, then A is affected.
//     We need: for each node N in dependents, there exists a path N ->* pkgId using forward edges.
//     Equivalently, on the reverse graph "to -> [from...]", pkgId has descendants.
//   - This module is pure logic. No external calls, no AI, deterministic, test-friendly.
//   - Cycles are defended against (npm trees shouldn't have them, but defensive code is cheap).
//
// Example:
//   graph = {
//     nodes: [
//       { id: "app@1.0.0",        name: "app",        depth: -1, isDirect: false }, // root sentinel, isDirect treated via direct list below
//       { id: "express@4.0.0",    name: "express",    depth: 0,  isDirect: true  },
//       { id: "body-parser@1.0",  name: "body-parser",depth: 1,  isDirect: false },
//       { id: "qs@6.0.0",         name: "qs",         depth: 2,  isDirect: false },
//       { id: "lodash@4.17.21",   name: "lodash",     depth: 1,  isDirect: false },
//     ],
//     edges: [
//       { from: "app@1.0.0",       to: "express@4.0.0"   },
//       { from: "express@4.0.0",   to: "body-parser@1.0" },
//       { from: "body-parser@1.0", to: "qs@6.0.0"        },
//       { from: "express@4.0.0",   to: "lodash@4.17.21"  },
//     ],
//   }
//   computeBlastRadius(graph, "qs@6.0.0")
//   => {
//        dependents: ["body-parser@1.0", "express@4.0.0"],
//        dependentCount: 2,
//        criticalPathFlag: true   // express is a direct dependency and is in the blast set
//      }

const DEFAULT_REVERSE_KEY = "__missing__";

/**
 * Build reverse adjacency: to -> [from, from, ...]
 * Unknown "to" ids (i.e. node referenced by an edge but not in nodes[]) are skipped silently —
 * the traversal should still walk whatever's reachable from a valid pkgId.
 */
function buildReverseAdjacency(graph) {
  const reverse = new Map();
  const knownIds = new Set();
  for (const n of graph.nodes || []) {
    if (!n || typeof n.id !== "string" || n.id.length === 0) continue;
    knownIds.add(n.id);
  }

  for (const e of graph.edges || []) {
    if (!e || typeof e.from !== "string" || typeof e.to !== "string") continue;
    if (e.from === e.to) continue; // self-loops add nothing meaningful to blast radius
    if (!knownIds.has(e.from) || !knownIds.has(e.to)) continue;
    if (!reverse.has(e.to)) reverse.set(e.to, []);
    reverse.get(e.to).push(e.from);
  }
  return reverse;
}

/**
 * Public entry point. Returns BlastRadius.
 */
export function computeBlastRadius(graph, pkgId) {
  const empty = { dependents: [], dependentCount: 0, criticalPathFlag: false };

  if (!graph || typeof graph !== "object") return empty;
  if (typeof pkgId !== "string" || pkgId.length === 0) return empty;

  // Fast path: pkgId not present in the graph at all.
  const nodeExists = graph.nodes && graph.nodes.some((n) => n && n.id === pkgId);
  if (!nodeExists) return empty;

  const reverse = buildReverseAdjacency(graph);
  const directIds = new Set(
    (graph.nodes || [])
      .filter((n) => n && n.isDirect)
      .map((n) => n.id)
  );

  // BFS backward through the reverse adjacency map.
  // reverse.get(x) returns the list of nodes that depend on x.
  // We mark pkgId itself as seen so that cycles (e.g. a -> b -> a) cannot pull
  // pkgId into its own dependents — a package does not "depend on itself" in
  // any meaningful sense, and including it would double-count in the blast set.
  const dependents = [];
  const seen = new Set([pkgId]);
  const queue = [];

  const startList = reverse.get(pkgId) || [];
  for (const upstreamId of startList) {
    if (seen.has(upstreamId)) continue;
    seen.add(upstreamId);
    queue.push(upstreamId);
    dependents.push(upstreamId);
  }

  while (queue.length > 0) {
    const current = queue.shift();
    const parents = reverse.get(current) || [];
    for (const upstreamId of parents) {
      if (seen.has(upstreamId)) continue; // cycle-safe + idempotent
      seen.add(upstreamId);
      queue.push(upstreamId);
      dependents.push(upstreamId);
    }
  }

  let criticalPathFlag = false;
  for (const id of dependents) {
    if (directIds.has(id)) {
      criticalPathFlag = true;
      break;
    }
  }

  return {
    dependents,
    dependentCount: dependents.length,
    criticalPathFlag,
  };
}

// Kept for unit-test introspection. Not exported via default — only via named export.
export const __internal = { buildReverseAdjacency, DEFAULT_REVERSE_KEY };