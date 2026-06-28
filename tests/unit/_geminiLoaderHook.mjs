// Test-only module loader hook.
//
// Registered by tests/unit/threatAnalyst.test.js. When threatAnalyst.js
// imports geminiClient.js, this hook returns a controllable mock instead of
// the real module. The mock consults a process-global `geminiMockState`
// object — set by tests between calls to control what callGemini returns.
//
// Per Node's loader contract, `resolve` returns the URL the loader chain
// will use, and `load` returns the module source. We mark the resolved URL
// with a custom `customData` flag so we know which module to mock.

import { pathToFileURL, fileURLToPath } from "node:url";
import path from "node:path";

const REAL_GEMINI_PATH = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "..", "..", "src", "clients", "geminiClient.js"
);
const REAL_GEMINI_URL = pathToFileURL(REAL_GEMINI_PATH).href;

export async function resolve(specifier, context, nextResolve) {
  if (specifier.endsWith("clients/geminiClient.js") ||
      specifier.endsWith("clients\\geminiClient.js") ||
      specifier === REAL_GEMINI_URL) {
    // Tag the URL with customData so `load` knows to mock it.
    return {
      url: "mock://gemini-client",
      shortCircuit: true,
      format: "module",
      customData: { mock: true },
    };
  }
  return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
  if (url === "mock://gemini-client") {
    // Return a tiny ESM source whose callGemini consults globalThis.__geminiMock.
    // The test file sets/reads this via geminiMockState.
    return {
      format: "module",
      shortCircuit: true,
      source:
        "globalThis.__geminiMock = globalThis.__geminiMock || { next: null };\n" +
        "export async function callGemini(prompt, options) {\n" +
        "  const state = globalThis.__geminiMock;\n" +
        "  const next = state.next;\n" +
        "  if (!next) return '';\n" +
        "  if (next.mode === 'throw') throw next.error;\n" +
        "  return next.value;\n" +
        "}\n",
    };
  }
  return nextLoad(url, context);
}
