// Single responsibility: transform a package manifest into a dependency graph for downstream analysis.
//
// Contract:
//   Input  : parsed package.json manifest object
//            { name, version, dependencies?: { [pkgName]: versionRange }, devDependencies?: {...} }
//   Output : {
//              nodes: [{ id, name, version, depth, isDirect }],
//              edges: [{ from, to }],   // from -> to means "from" depends on "to"
//              truncated: boolean        // true if MAX_NODES was hit before traversal finished
//            }
//
// Notes:
//   - Resolves via the public npm registry REST API (no auth).
//   - Uses native fetch with a per-request AbortController timeout.
//   - Ignores devDependencies for MVP scope (per spec).
//   - Deduplicates by package name, keeping the shallowest depth; records every edge.
//   - Bounded: MAX_DEPTH=3, MAX_NODES=200. On overflow, sets truncated=true and stops expanding.

const REGISTRY_BASE = "https://registry.npmjs.org";
const MAX_DEPTH = 3;
const MAX_NODES = 200;
const REQUEST_TIMEOUT_MS = 5000;

/**
 * Strip a semver-ish range down to a concrete version string the registry can resolve.
 * Returns "latest" for ranges we don't want to parse ourselves.
 */
function pickVersion(range) {
  if (!range || typeof range !== "string") return "latest";
  const r = range.trim();
  // Exact pin: "1.2.3"
  if (/^\d+\.\d+\.\d+$/.test(r)) return r;
  // Anything else (^, ~, >=, x-range, tag) -> "latest" is safe for MVP dependency discovery.
  return "latest";
}

/**
 * Fetch a package's metadata document from the public npm registry.
 * Returns the `dependencies` block (name -> range) or {} on any failure.
 * Never throws — failures are logged and skipped so the pipeline can keep going.
 */
async function fetchDeps(name, version, seen) {
  const key = `${name}@${version}`;
  if (seen.has(key)) return seen.get(key);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
  try {
    const url = `${REGISTRY_BASE}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
    const res = await fetch(url, { signal: ctrl.signal });
    if (!res.ok) {
      // Specific version not found -> fall back to "latest" dist-tag, once.
      if (version !== "latest" && (res.status === 404 || res.status === 400)) {
        clearTimeout(timer);
        return fetchDeps(name, "latest", seen);
      }
      console.warn(`[dependencyScout] registry ${res.status} for ${name}@${version}, skipping`);
      seen.set(key, {});
      return {};
    }
    const doc = await res.json();
    const deps = (doc && doc.dependencies) || {};
    // Shallow clone so cache entries are not shared mutable refs.
    const out = {};
    for (const [k, v] of Object.entries(deps)) out[k] = String(v);
    seen.set(key, out);
    return out;
  } catch (err) {
    const msg = err && err.name === "AbortError" ? "timeout" : err && err.message;
    console.warn(`[dependencyScout] registry fetch failed for ${name}@${version}: ${msg}`);
    seen.set(key, {});
    return {};
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Public entry point. Returns DependencyGraph.
 */
export async function buildDependencyGraph(manifestJson) {
  const nodes = [];                 // [{ id, name, version, depth, isDirect }]
  const nodeIndex = new Map();      // name -> index into nodes[]
  const edges = [];                 // [{ from, to }]
  const edgeKey = new Set();        // "from||to" for dedupe
  const cache = new Map();          // registry fetch cache: "name@version" -> deps
  let truncated = false;

  const addEdge = (fromId, toId) => {
    const k = `${fromId}||${toId}`;
    if (edgeKey.has(k) || fromId === toId) return;
    edgeKey.add(k);
    edges.push({ from: fromId, to: toId });
  };

  const upsertNode = ({ name, version, depth, isDirect }) => {
    const id = `${name}@${version}`;
    const existing = nodeIndex.get(name);
    if (existing !== undefined) {
      // Keep shallowest depth; upgrade isDirect if this occurrence is direct.
      const cur = nodes[existing];
      if (depth < cur.depth) cur.depth = depth;
      if (isDirect) cur.isDirect = true;
      return cur.id;
    }
    if (nodes.length >= MAX_NODES) {
      truncated = true;
      return null;
    }
    const node = { id, name, version, depth, isDirect };
    nodes.push(node);
    nodeIndex.set(name, nodes.length - 1);
    return id;
  };

  const manifest = manifestJson || {};
  const directDeps = manifest.dependencies || {};
  // Note: spec says ignore devDependencies for MVP.

  // BFS frontier: [{ name, version, depth }]
  const queue = [];
  for (const [name, range] of Object.entries(directDeps)) {
    const version = pickVersion(range);
    queue.push({ name, version, depth: 0 });
  }

  while (queue.length > 0) {
    if (nodes.length >= MAX_NODES) { truncated = true; break; }

    const { name, version, depth } = queue.shift();
    const isDirect = depth === 0;

    const nodeId = upsertNode({ name, version, depth, isDirect });
    if (nodeId === null) { truncated = true; break; }

    if (depth >= MAX_DEPTH) continue;

    const deps = await fetchDeps(name, version, cache);
    for (const [childName, childRange] of Object.entries(deps)) {
      const childVersion = pickVersion(childRange);
      // Edge: current node depends on child
      addEdge(nodeId, `${childName}@${childVersion}`);
      queue.push({ name: childName, version: childVersion, depth: depth + 1 });
    }
  }

  return { nodes, edges, truncated };
}
