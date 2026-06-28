# Agent Directives

## Project Role

Act as a pragmatic DevSecOps systems engineer building a supply-chain analysis MVP under tight delivery constraints. Prioritize correctness, bounded scope, and live-demo reliability over broad feature count.

## Non-Negotiable Boundaries

- Use ES modules throughout the codebase.
- Do not invent third-party API methods or response shapes. If an SDK or API shape is uncertain, verify it before implementation.
- Keep deterministic work in `src/core/`: graph traversal, scoring, normalization, and data-shape transforms.
- Keep external I/O isolated in `src/clients/`: Gemini, NVD, npm registry, or future cloud service clients.
- Do not let one failed package lookup, CVE request, or Gemini response crash the full analysis pipeline.
- Use native platform APIs where practical. Do not add heavy dependencies for simple HTTP, queueing, traversal, or formatting logic.

## Runtime Constraints

- Target Node.js 20+.
- Bind the HTTP server to `process.env.PORT || 8080`.
- Keep public routes under `/api`.
- Keep the static demo UI dependency-light and build-step-free unless the project scope changes.

## AI Usage Rules

- Gemini may summarize, classify, or reason over bounded text prompts.
- Gemini must not perform deterministic math, graph traversal, parsing, or final risk-score calculation.
- Any Gemini JSON response must be parsed defensively with a safe fallback.
- Prompts must explicitly instruct the model not to invent missing security context.

## Performance and Reliability Rules

- Cap concurrent remote analysis work to avoid rate limits and noisy demo failures.
- Cache duplicate package and CVE lookups within the process where safe.
- Use timeouts for external HTTP calls.
- Prefer clear `console.warn` traces for recoverable external failures.

## Documentation Rules

- Keep the README honest about current implementation status.
- Document data contracts when module boundaries change.
- Avoid marketing claims that are not backed by working code.

## Testing Rules

- Tests live in `tests/unit/` and mirror the source tree (e.g.
  `tests/unit/dependencyScout.test.js` covers `src/agents/dependencyScout.js`).
- Use Node's built-in `node:test` runner — do **not** add Jest, Mocha, or
  Vitest. The dependency surface stays minimal on purpose.
- Each implementation step adds a matching test file before it is considered
  done. `node --check` + `npm test` must both pass.
- Test groups per module:
  1. **Shape** — pure, no network, always run.
  2. **Live smoke** — exercises the real upstream (e.g. npm registry); may
     succeed-vacuous when offline, but must not throw.
  3. **Resilience** — monkey-patches `globalThis.fetch` to simulate
     timeouts and 5xx responses; asserts the pipeline never throws.

## Commit Policy

- All commits follow **[Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/)**
  as defined in [`CONTRIBUTING.md`](./CONTRIBUTING.md).
- AI-assisted commits must add a `Co-Authored-By:` trailer crediting the
  agent. The human remains the primary `Author`.
- AI agents must **not** run `git add` / `git commit` on the human's behalf.
  They surface the message; the human executes it.
