# Supply Chain Observatory

An MVP for mapping JavaScript dependency graphs, assessing vulnerability exploitability with Gemini, and producing explainable software supply-chain risk reports.

The project is intentionally shaped as an engineering-focused DevSecOps tool: deterministic graph and scoring logic live in pure JavaScript modules, while Gemini is reserved for bounded reasoning tasks such as exploitability context and stakeholder narrative generation.

## Why This Exists

Modern dependency risk is usually presented as a flat CVE list. That is not enough for engineering leadership: the same vulnerability can be low priority in an unused transitive package and urgent when it sits on a critical direct dependency path.

Supply Chain Observatory is designed to answer three practical questions:

- Which packages are in the dependency graph?
- Which known vulnerabilities matter in this specific dependency context?
- What is the blast radius and business-level action for each high-risk finding?

## Current Status

This repository currently contains the project scaffold and contract-first module boundaries. The analysis pipeline is intentionally stubbed so each component can be implemented and verified independently.

Implemented in this milestone:

- Node.js 20 ES module project setup
- Express server with CORS and static file serving
- `/api/analyze` route stub
- Dockerfile for Cloud Run-style container deployment
- Environment template
- Fixture package manifest
- Agent, client, core, route, and visualization file structure

Planned next implementation milestones:

- Dependency graph resolver using the npm registry
- NVD CVE client with process-level rate limiting and backoff
- Gemini exploitability-in-context evaluator
- Deterministic blast-radius traversal
- Explainable risk scoring
- Gemini-generated stakeholder narrative for high-risk findings
- Static graph visualization with risk-aware node coloring

## Architecture

```text
ManifestInput package.json
  -> DependencyScout
  -> DependencyGraph
  -> ThreatAnalyst
  -> ThreatFinding[]
  -> BlastRadius calculation
  -> RiskScore calculation
  -> BusinessAdvisor
  -> AnalysisReport
  -> Static graph visualization
```

Target module map:

```text
src/
  server.js                 Express entrypoint
  agents/
    dependencyScout.js      npm dependency graph builder
    threatAnalyst.js        NVD + Gemini exploitability analysis
    businessAdvisor.js      Gemini business-impact narrative
  clients/
    geminiClient.js         Gemini API wrapper
    nvdClient.js            NVD API wrapper
  core/
    graph.js                deterministic blast-radius traversal
    riskScore.js            deterministic explainable risk scoring
  routes/
    analyze.js              analysis orchestration route
public/
  graph-view.html           static visualization entrypoint
test-fixtures/
  sample-package.json       stable demo input
```

## Data Contracts

```js
ManifestInput = {
  name: string,
  version: string,
  dependencies: Record<string, string>
}

DependencyGraph = {
  nodes: [{ id, name, version, depth, isDirect }],
  edges: [{ from, to }],
  truncated: boolean
}

ThreatFinding = {
  pkgId,
  packageName,
  cveId,
  cvssScore,
  cvssSeverity,
  exploitabilityInContext,
  geminiRationale
}

BlastRadius = {
  dependents,
  dependentCount,
  criticalPathFlag
}

RiskScore = {
  score,
  breakdown
}
```

## Tech Stack

- Node.js 20+
- Express
- ES modules
- Native `fetch` for external HTTP calls
- `@google/genai` for Gemini API integration
- Docker container target suitable for Google Cloud Run

## Getting Started

Install dependencies:

```bash
npm ci
```

Create local environment config:

```bash
cp .env.example .env
```

Start the server:

```bash
npm start
```

Open the static UI:

```text
http://localhost:8080/graph-view.html
```

Smoke-test the current API stub:

```bash
curl -X POST http://localhost:8080/api/analyze \
  -H "Content-Type: application/json" \
  -d "{}"
```

Expected current response:

```json
{
  "error": "not implemented",
  "message": "The analysis pipeline will be implemented in the next build step."
}
```

## Environment Variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `GEMINI_API_KEY` | Yes, once Gemini-backed modules are implemented | Gemini reasoning calls |
| `NVD_API_KEY` | Optional | Higher NVD API rate limits |
| `PORT` | Optional | Server port, defaults to `8080` |

## Docker

Build the image:

```bash
docker build -t supply-chain-observatory .
```

Run locally:

```bash
docker run --rm -p 8080:8080 --env-file .env supply-chain-observatory
```

## Engineering Principles

- Keep graph traversal, scoring, parsing, and aggregation deterministic.
- Wrap all external I/O behind small client modules.
- Treat Gemini as a reasoning layer, not as the source of numeric truth.
- Use explicit data contracts between modules.
- Prefer bounded concurrency and graceful degradation over all-or-nothing live-demo behavior.

## Repository Workflow

This project includes:

- `AGENTS.md` for project-specific coding guardrails.
- `SKILL.md` for the atomic build workflow used to guide Codex implementation steps.

These files are intentionally short and operational. They exist because this project benefits from strict boundaries between deterministic code and AI-assisted reasoning.
