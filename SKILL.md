# Skill Definition: Atomic Supply Chain Observatory Build

## Objective

Guide Codex through small, verifiable implementation steps for the Supply Chain Observatory project. The goal is to preserve module contracts, prevent regressions, and keep AI-assisted code generation bounded to one component at a time.

## When To Use

Use this workflow before implementing or modifying any module under `src/`, especially when the change touches:

- dependency graph construction
- external API clients
- Gemini prompts or response parsing
- risk scoring
- analysis orchestration
- graph visualization

## Step 1: Contract Check

Before editing a target module, confirm:

- the input shape entering the module
- the output shape leaving the module
- adjacent modules that consume or produce that shape

Keep this summary short and concrete.

## Step 2: Scoped Implementation

Implement only the target module or the smallest adjacent set required for integration. Preserve these boundaries:

- `src/agents/` coordinates domain behavior
- `src/clients/` owns external I/O
- `src/core/` owns pure deterministic logic
- `src/routes/` owns HTTP orchestration
- `public/` owns the static demo interface

## Step 3: Defensive Integration

For code that touches external services:

- add timeouts
- catch recoverable failures
- return safe fallback values
- log concise warnings
- avoid unbounded parallel requests

For Gemini-backed logic:

- request strict JSON when structured output is needed
- strip markdown fences before parsing
- fall back to conservative defaults on parse failure

## Step 4: Atomic Verification

After each implementation step, run the narrowest useful checks:

- `node --check` for edited JavaScript files
- a fixture-based module invocation when practical
- an HTTP smoke test for route changes
- a browser or `curl` check for static UI changes

Do not proceed to the next major module until the current one parses and its contract still matches adjacent files.

## Step 5: Status Update

At the end of each step, report:

- files changed
- behavior implemented
- verification performed
- known gaps or next module to implement
