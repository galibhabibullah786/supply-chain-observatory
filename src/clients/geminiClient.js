// Single responsibility: provide a thin Gemini API wrapper for AI-assisted reasoning calls.
//
// Implementation notes:
//   - Uses @google/genai's GoogleGenAI client, calling `ai.models.generateContent`.
//   - Defensive: catches SDK/network errors and throws a plain Error with a clean
//     message so the calling agent can decide whether to fall back.
//   - Supports `responseMimeType: "application/json"` so callers asking for JSON
//     get a parsed-ish text payload back (still a string; the agent's parser
//     handles any leftover fences/prose).
import { GoogleGenAI } from "@google/genai";

const DEFAULT_MODEL = "gemini-2.0-flash";

let _client = null;
function getClient() {
  if (_client) return _client;
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || typeof apiKey !== "string" || apiKey.trim().length === 0) {
    throw new Error("GEMINI_API_KEY is not set");
  }
  _client = new GoogleGenAI({ apiKey: apiKey.trim() });
  return _client;
}

/**
 * Send a single prompt to Gemini and return the model's text response.
 *
 * @param {string} prompt - the prompt to send
 * @param {object} [options]
 * @param {string} [options.model] - model name, defaults to env GEMINI_MODEL or gemini-2.0-flash
 * @param {number} [options.temperature] - sampling temperature, default 0.2
 * @param {"application/json"|"text/plain"} [options.responseMimeType] - defaults to "text/plain"
 * @returns {Promise<string>} the model's text output (may be empty string)
 * @throws {Error} if the SDK call fails for any reason
 */
export async function callGemini(prompt, options = {}) {
  if (typeof prompt !== "string" || prompt.length === 0) {
    throw new Error("callGemini: prompt must be a non-empty string");
  }

  const model = options.model || process.env.GEMINI_MODEL || DEFAULT_MODEL;
  const temperature =
    typeof options.temperature === "number" && Number.isFinite(options.temperature)
      ? options.temperature
      : 0.2;
  const responseMimeType = options.responseMimeType || "text/plain";

  const client = getClient();

  try {
    const response = await client.models.generateContent({
      model,
      contents: prompt,
      config: {
        temperature,
        responseMimeType,
      },
    });

    // The SDK exposes `.text` as a getter that concatenates parts of the first candidate.
    // Fall back to walking candidates manually if `.text` returns undefined (older SDK shapes).
    const text = typeof response?.text === "string"
      ? response.text
      : extractTextFromCandidates(response?.candidates);

    return text || "";
  } catch (err) {
    const msg = err && err.message ? err.message : String(err);
    throw new Error(`Gemini call failed: ${msg}`);
  }
}

function extractTextFromCandidates(candidates) {
  if (!Array.isArray(candidates) || candidates.length === 0) return "";
  const parts = candidates[0]?.content?.parts;
  if (!Array.isArray(parts)) return "";
  const out = [];
  for (const p of parts) {
    if (typeof p?.text === "string") out.push(p.text);
  }
  return out.join("");
}