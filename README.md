# Supply Chain Observatory

An MVP for mapping JavaScript dependency graphs, assessing vulnerability exploitability with Gemini, and producing explainable software supply-chain risk reports.

The project is intentionally shaped as an engineering-focused DevSecOps tool: deterministic graph and scoring logic live in pure JavaScript modules, while Gemini is reserved for bounded reasoning tasks such as exploitability context and stakeholder narrative generation.

---

## Why This Exists

Modern dependency risk is usually presented as a flat CVE list. That is not enough for engineering leadership: the same vulnerability can be low priority in an unused transitive package and urgent when it sits on a critical direct dependency path.

Supply Chain Observatory answers three practical questions:

- Which packages are in the dependency graph?
- Which known vulnerabilities matter in this specific dependency context?
- What is the blast radius and business-level action for each high-risk finding?

---

## Current Status

The repository is built incrementally via an **atomic, prompt-driven workflow** defined in [`SKILL.md`](./SKILL.md). Each step implements one module, ships with its own micro-tests, and produces a Conventional Commit.

### Implemented

- **Project scaffold** — Node.js 20 ES module layout, Express + CORS, static file serving, Dockerfile for Cloud Run-style container deployment.
- **DependencyScout** (`src/agents/dependencyScout.js`) — BFS npm dependency graph resolver against the public npm registry, bounded by `MAX_DEPTH=3` and `MAX_NODES=200`, with a 5 s `AbortController` timeout, `latest`-dist-tag fallback, in-memory request cache, and per-package failure isolation. Backed by 9 micro-tests.
- **Engineering guardrails** — `AGENTS.md`, `SKILL.md`, `CONTRIBUTING.md` lock in deterministic-core / AI-bounded-reasoning separation, the atomic-build workflow, and the Conventional Commits v1.0.0 policy for human and AI-assisted commits alike.

### Planned next implementation milestones

In execution order, each scoped to one module per `SKILL.md`:

- **Prompt 3** — `src/clients/nvdClient.js` (rate-limited NVD v2.0 client) + `src/agents/threatAnalyst.js` (CVE lookup + Gemini exploitability-in-context evaluator, concurrency cap 5).
- **Prompt 4** — `src/core/graph.js` (deterministic blast-radius traversal) + `src/core/riskScore.js` (explainable weighted-sum scoring).
- **Prompt 5** — `src/agents/businessAdvisor.js` (Gemini narrative for high-risk findings only, score ≥ 50).
- **Prompt 6** — `src/routes/analyze.js` orchestration replacing the 501 stub, plus `public/graph-view.html` (vis-network force-directed graph, risk-aware node coloring, click-to-inspect panel).

---

## Architecture

```text
ManifestInput (package.json)
  └── DependencyScout       → DependencyGraph
        └── ThreatAnalyst   → ThreatFinding[]
              └── graph.js  → BlastRadius (per finding)
                    └── riskScore.js → RiskScore (per finding)
                          └── BusinessAdvisor (score ≥ 50) → RiskNarrative
                                └── AnalysisReport
                                      └── Static graph visualization
```

### Source tree

```text
supply-chain-observatory/
├── AGENTS.md                      # AI/engineering guardrails
├── CONTRIBUTING.md                # Conventional Commits v1.0.0 policy
├── SKILL.md                       # atomic prompt-driven build workflow
├── README.md
├── Dockerfile                     # node:20-slim, Cloud Run-ready
├── package.json                   # type: "module"; scripts: start, test
├── .env.example                   # GEMINI_API_KEY, NVD_API_KEY, PORT
├── .gitignore                     # node_modules, .env, *.log, temp/
├── public/
│   └── graph-view.html            # vis-network CDN, vanilla JS, no build step
├── src/
│   ├── server.js                  # Express app + static mount
│   ├── agents/
│   │   ├── dependencyScout.js     # ✅ implemented — npm graph builder
│   │   ├── threatAnalyst.js       # NVD lookup + Gemini exploitability
│   │   └── businessAdvisor.js     # Gemini narrative (high-risk only)
│   ├── clients/
│   │   ├── geminiClient.js        # @google/genai wrapper
│   │   └── nvdClient.js           # NVD v2.0 wrapper, rate-limit aware
│   ├── core/
│   │   ├── graph.js               # deterministic blast-radius traversal
│   │   └── riskScore.js           # deterministic explainable scoring
│   └── routes/
│       └── analyze.js             # POST /api/analyze (currently 501 stub)
├── tests/
│   └── unit/
│       └── dependencyScout.test.js  # node:test — shape + smoke + resilience
└── test-fixtures/
    └── sample-package.json        # stable demo input
```

`temp/` is gitignored — local scratch space for ad-hoc notes and intermediate plans.

---

## Data Contracts

```js
ManifestInput = {
  name: string,
  version: string,
  dependencies: Record<string, string>   // devDependencies ignored for MVP
}

DependencyGraph = {
  nodes:    [{ id, name, version, depth, isDirect }],
  edges:    [{ from, to }],               // from -> to means "from depends on to"
  truncated: boolean                      // true if MAX_NODES was hit
}

ThreatFinding = {
  pkgId,
  packageName,
  cveId,
  cvssScore,
  cvssSeverity,
  exploitabilityInContext,                // float 0–1 (Gemini-evaluated)
  geminiRationale
}

BlastRadius = {
  dependents: string[],                   // pkgIds that transitively depend on target
  dependentCount: number,
  criticalPathFlag: boolean               // true if any direct dep is in dependents
}

RiskScore = {
  score: number,                          // 0–100
  breakdown: {                            // pre-rounding contributions for UI explainability
    cvssContribution: number,
    exploitabilityContribution: number,
    blastRadiusContribution: number,
    criticalPathBoost: number
  }
}

RiskNarrative = {                         // only emitted when RiskScore.score >= 50
  businessImpactSummary: string,
  recommendedAction: string
}

AnalysisReport = {
  graph: DependencyGraph,
  findings: Array<ThreatFinding & { blastRadius, riskScore, narrative? }>,
  generatedAt: string                     // ISO 8601
}
```

These shapes are stable; any change to them is a `BREAKING CHANGE:` commit that updates the orchestrator and the visualization consumer in the same PR.

---

## Tech Stack

- **Runtime** — Node.js 20+ ES modules (`"type": "module"`).
- **HTTP** — Express 4 with `cors` and 1 MB JSON body limit.
- **External I/O** — native `fetch` with `AbortController` timeouts (no `node-fetch`).
- **AI SDK** — `@google/genai` for Gemini reasoning calls (read from `GEMINI_API_KEY`).
- **Testing** — Node's built-in `node:test` runner. Zero test-framework dependency.
- **Deployment** — single-stage `node:20-slim` Docker image, ready for Google Cloud Run.

No bundler, no transpiler, no frontend framework. The static UI is one vanilla HTML file using vis-network via CDN.

---

## Getting Started

### 1. Install

```bash
npm ci
```

### 2. Configure environment

```bash
cp .env.example .env
# edit .env and set GEMINI_API_KEY (required once Gemini-backed modules ship)
# NVD_API_KEY is optional — it raises the NVD rate limit
```

### 3. Run

```bash
npm start
```

You should see:

```
Supply Chain Observatory listening on port 8080
```

### 4. Open the UI

```text
http://localhost:8080/graph-view.html
```

### 5. Smoke-test the current API stub

```bash
curl -X POST http://localhost:8080/api/analyze \
  -H "Content-Type: application/json" \
  -d "{}"
```

Expected response **at this milestone** (Prompt 6 will replace it):

```json
{
  "error": "not implemented",
  "message": "The analysis pipeline will be implemented in the next build step."
}
```

---

## Testing

```bash
npm test          # run all tests under tests/
npm run test:unit # alias for the above, currently the same scope
```

Tests use Node's built-in `node:test` runner — no `npm install` of a test framework. Each implemented module ships with a matching `*.test.js` at the same scope (e.g. `tests/unit/dependencyScout.test.js` covers `src/agents/dependencyScout.js`).

Per-module tests are grouped into three tiers:

| Tier | What it verifies | Network? |
|---|---|---|
| Shape | Pure output-shape contracts; empty/null/boundary inputs. | No |
| Live smoke | End-to-end against the real upstream (e.g. npm registry). Succeeds-vacuous if offline, but must not throw. | Yes |
| Resilience | `globalThis.fetch` monkey-patched to simulate timeouts and 5xx responses; asserts the pipeline never throws. | No |

Current coverage: **9 tests, 3 suites, all passing** for `dependencyScout.js`.

---

## Environment Variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `GEMINI_API_KEY` | Yes, once Prompt 3 lands | Gemini exploitability + narrative calls |
| `NVD_API_KEY` | Optional | Raises NVD API rate limit from 5 req/30 s to 50 req/30 s |
| `PORT` | Optional | Server port, defaults to `8080` |

---

## Docker

Build:

```bash
docker build -t supply-chain-observatory .
```

Run locally:

```bash
docker run --rm -p 8080:8080 --env-file .env supply-chain-observatory
```

The image is a single-stage `node:20-slim` container that runs `node src/server.js` and binds to `$PORT` — drop-in compatible with Google Cloud Run.

---

## Engineering Principles

- Keep graph traversal, scoring, parsing, and aggregation **deterministic** and pure.
- Wrap all external I/O behind small client modules (`src/clients/`) so agents never reach for `fetch` directly.
- Treat Gemini as a **reasoning layer**, not as the source of numeric truth. AI never computes CVSS, blast radius, or final risk scores.
- Use **explicit data contracts** between modules; document any change in this README.
- Prefer **bounded concurrency** and **graceful degradation** over all-or-nothing live-demo behavior.
- Every production-code change ships with its own micro-tests.

---

## Repository Workflow

The repository ships four short, operational documents. Together they describe how the project is built and how changes flow back in:

| File | Purpose |
| --- | --- |
| [`AGENTS.md`](./AGENTS.md) | Engineering guardrails — module boundaries, runtime constraints, AI usage rules, performance and reliability rules, documentation rules, testing rules, commit policy. |
| [`SKILL.md`](./SKILL.md) | Atomic prompt-driven build workflow — contract check, scoped implementation, defensive integration, atomic verification, status update. |
| [`CONTRIBUTING.md`](./CONTRIBUTING.md) | Conventional Commits v1.0.0 policy for human and AI-assisted commits — subject-line rules, scopes, AI co-authorship trailer, "agent surfaces message, human executes it" rule, PR conventions. |
| `README.md` | This file. |

These documents are intentionally short and operational. They exist because the project benefits from strict boundaries between deterministic code and AI-assisted reasoning, and from a commit history that is auditable by humans and tooling alike.

---

## License

Internal MVP — license to be decided before public release.