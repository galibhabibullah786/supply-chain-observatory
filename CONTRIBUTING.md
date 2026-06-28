# Contributing

This document defines how to commit changes to **Supply Chain Observatory**.
It applies to **all contributors — human and AI-assisted alike** — and is the
single source of truth for the project's commit policy.

The policy is enforced by review, not by tooling. Keep it short, operational,
and consistent with industry standard practice for AI-assisted projects.

---

## Commit Messages

This project follows the **[Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/)**
specification, which is the de facto standard for AI-assisted software
development and is used by Angular, Vue, Babel, NestJS, Electron, and most
CNCF-adjacent tooling.

### Format

```
<type>(<optional-scope>): <subject>

<body — explain WHY, not WHAT>

<footer — references, breaking changes, co-authorship>
```

### Rules

- **Subject line**: imperative mood, no trailing period, no capitalised first
  word, max **72 characters**. Write it as a command: *"implement", "fix",
  "refactor", "remove"* — never *"implemented", "fixes", "refactoring"*.
- **Body**: wrap at 100 columns. Explain the *why* (the motivation, the
  trade-off, the constraint that drove the decision). The *what* is already
  in the diff — do not paraphrase it.
- **Scope** *(optional, recommended)*: the module or area affected, e.g.
  `agents`, `clients`, `core`, `routes`, `docs`, `tests`, `deps`, `ci`.
- **One logical change per commit**. If a diff mixes a feature and its
  accompanying test, that is fine — the feature and its verification are one
  logical change. If it mixes a feature *and* an unrelated refactor, split.
- **Reference issues** in the footer: `Refs: #123` or `Closes: #123`.
- **Breaking changes**: append `!` after the type/scope and add a
  `BREAKING CHANGE:` paragraph in the footer.

### Allowed Types

| Type       | When to use                                                     |
| ---------- | --------------------------------------------------------------- |
| `feat`     | A new user-facing capability                                    |
| `fix`      | A bug fix                                                       |
| `refactor` | A code change that neither fixes a bug nor adds a feature       |
| `perf`     | A performance improvement                                       |
| `test`     | Adding or correcting tests (no production code change)          |
| `docs`     | Documentation only                                              |
| `build`    | Build system, dependencies, or CI                              |
| `chore`    | Tooling, configs, housekeeping that is not user-facing        |
| `style`    | Whitespace, formatting, semicolons — no logic change            |
| `revert`   | Reverting a previous commit                                     |

### AI Co-Authorship

Commits produced with the assistance of an AI agent must declare co-authorship
in the footer:

```
Co-Authored-By: <Agent Name> <noreply@provider.example>
```

The human contributor remains the primary `Author` of the commit. AI tools do
not own commits — they assist them.

### Example — Good

```
feat(agents): implement DependencyScout buildDependencyGraph

Resolve direct and transitive npm dependencies into a bounded
DependencyGraph ({ nodes, edges, truncated }) per the README data
contract. BFS to MAX_DEPTH=3, dedupe by package name (keep shallowest
depth, upgrade isDirect when seen as direct), cap at MAX_NODES=200.

Uses native fetch against the public npm registry REST API with a
5s AbortController timeout, falls back to the "latest" dist-tag on
404/400, and caches lookups in-memory per request. Registry failures
log a console.warn and skip the subtree; one bad package never
crashes the pipeline (AGENTS.md defensive-integration requirement).

devDependencies are intentionally ignored for MVP scope.

Verified with `node --check` and five micro-tests covering
empty/null manifests, devDependencies ignored, a live `lodash`
fetch, and a resilience test simulating registry timeouts.
```

### Example — Bad

```
updated some files

- changed dependencyScout
- added tests
- updated readme
```

*(No type, no scope, no subject rule, body is a list of what — not why.)*

---

## AI-Assisted Workflow

This project ships a **prompt-driven, atomic build workflow** defined in
[`SKILL.md`](./SKILL.md) and constrained by [`AGENTS.md`](./AGENTS.md).

When an AI agent generates a commit, it must:

1. Produce a **Conventional Commits** message as defined above.
2. **Surface the message to the human reviewer for execution** — agents
   must not run `git add` / `git commit` on the human's behalf. The human
   owns the commit authorship and the push.
3. **Stage only files that belong to the change**. Scratch files in
   `temp/` and unrelated modifications are excluded by default (see
   `.gitignore`).
4. **Verify before proposing the commit**:
   - `node --check` on every edited `.js` file
   - `npm test` for the touched module
   - an HTTP smoke test for route changes

---

## Pull Requests

- One logical change per PR. Atomic-build steps (see `SKILL.md`) often map
  1:1 to a single PR.
- PR title mirrors the commit subject line.
- PR body answers: *what changed, why, how it was verified, known gaps*.
- All tests must pass on the touched module before review.

---

## Questions

Open a discussion issue. The maintainer will clarify the rule rather than
waiving it case-by-case.
