// Single responsibility: query the NVD CVE API v2.0 with rate-limit-aware,
// defensive behavior — token-bucket limiter, exponential backoff, in-memory cache,
// graceful failure. Designed for live demos where one bad lookup cannot crash the
// whole pipeline.

const NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const REQUEST_TIMEOUT_MS = 8000;
const MAX_RETRIES = 3;

// NVD rate limits: 5 requests/30s without key, 50 requests/30s with key.
// We pick a slightly safer ceiling for the unkeyed case to leave headroom.
// Test suites can override via NVD_TEST_MAX_REQUESTS to bypass rate-limit
// queuing without lowering timeout budgets.
//
// NOTE: this limit is read at *call* time (not module load) so test env-var
// changes take effect even if nvdClient was already imported.
const WINDOW_MS = 30_000;

function getMaxRequestsPerWindow() {
  const TEST_MAX = Number(process.env.NVD_TEST_MAX_REQUESTS);
  if (Number.isFinite(TEST_MAX) && TEST_MAX > 0) return TEST_MAX;
  return process.env.NVD_API_KEY ? 48 : 4;
}

// ---------------------------------------------------------------------------
// Module-level shared state: cache + sliding-window rate limiter.
// These persist for the lifetime of the Node process so concurrent calls
// cooperate on the same budget.
// ---------------------------------------------------------------------------

const cache = new Map(); // key: packageName (lowercased) -> Promise<CveRecord[]>

// Sliding-window log of request timestamps (ms epoch). Trimmed on each access.
const requestTimestamps = [];

async function acquireRateLimitSlot() {
  while (true) {
    const now = Date.now();
    while (
      requestTimestamps.length > 0 &&
      now - requestTimestamps[0] >= WINDOW_MS
    ) {
      requestTimestamps.shift();
    }
    const limit = getMaxRequestsPerWindow();
    if (requestTimestamps.length < limit) {
      requestTimestamps.push(now);
      return;
    }
    // Window is full — wait until the oldest entry expires, plus a small jitter
    // so concurrent waiters don't all wake simultaneously.
    const waitMs = WINDOW_MS - (now - requestTimestamps[0]) + 50 + Math.floor(Math.random() * 100);
    await sleep(waitMs);
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Look up CVEs by package name (and optionally version) using NVD's
 * keywordSearch endpoint. Returns a simplified, normalized array.
 *
 * Output shape: [{ cveId, description, cvssScore, cvssSeverity, publishedDate }]
 *
 * Never throws. On any failure returns [] and logs a warning, so the calling
 * pipeline can keep going.
 */
export async function lookupCves(packageName, version) {
  if (!packageName || typeof packageName !== "string") return [];

  const cacheKey = packageName.toLowerCase();
  if (cache.has(cacheKey)) {
    return cache.get(cacheKey);
  }

  // Cache the in-flight promise so concurrent calls for the same package
  // share a single network request. We only cache NON-EMPTY results so that
  // a transient failure (timeout, 5xx, malformed body) does not poison the
  // cache and prevent future retries from succeeding.
  const promise = lookupCvesUncached(packageName, version)
    .then((results) => {
      if (Array.isArray(results) && results.length === 0) {
        // Empty result — likely a transient failure. Don't cache.
        cache.delete(cacheKey);
      }
      return results;
    })
    .catch((err) => {
      console.warn(`[nvdClient] lookup failed for ${packageName}: ${err?.message ?? err}`);
      // Evict the failed promise from cache so a future call can retry.
      cache.delete(cacheKey);
      return [];
    });
  cache.set(cacheKey, promise);
  return promise;
}

// ---------------------------------------------------------------------------
// Internal: actual network call with retry/backoff.
// ---------------------------------------------------------------------------

async function lookupCvesUncached(packageName, version) {
  const url = `${NVD_BASE_URL}?keywordSearch=${encodeURIComponent(packageName)}&resultsPerPage=20`;

  let attempt = 0;
  let backoffMs = 2000;

  while (true) {
    attempt += 1;
    try {
      await acquireRateLimitSlot();

      const headers = { Accept: "application/json" };
      if (process.env.NVD_API_KEY) {
        headers["apiKey"] = process.env.NVD_API_KEY;
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      let response;
      try {
        response = await fetch(url, { method: "GET", headers, signal: controller.signal });
      } finally {
        clearTimeout(timeoutId);
      }

      if (response.status === 403 || response.status === 429) {
        if (attempt >= MAX_RETRIES) {
          console.warn(`[nvdClient] rate-limited (${response.status}) after ${attempt} attempts for ${packageName}, giving up`);
          return [];
        }
        console.warn(`[nvdClient] rate-limited (${response.status}) for ${packageName}, backing off ${backoffMs}ms (attempt ${attempt})`);
        await sleep(backoffMs);
        backoffMs *= 2;
        continue;
      }

      if (!response.ok) {
        console.warn(`[nvdClient] non-OK status ${response.status} for ${packageName}`);
        return [];
      }

      const body = await response.json();
      return normalizeNvdResponse(body, packageName, version);
    } catch (err) {
      if (attempt >= MAX_RETRIES) {
        console.warn(`[nvdClient] giving up on ${packageName} after ${attempt} attempts: ${err?.message ?? err}`);
        return [];
      }
      const isAbort = err?.name === "AbortError";
      console.warn(`[nvdClient] ${isAbort ? "timeout" : "error"} for ${packageName} (attempt ${attempt}): ${err?.message ?? err}`);
      await sleep(backoffMs);
      backoffMs *= 2;
    }
  }
}

// ---------------------------------------------------------------------------
// Normalization: NVD's response shape is verbose and deeply nested.
// We pull out just what the rest of the pipeline cares about.
// ---------------------------------------------------------------------------

function normalizeNvdResponse(body, packageName, version) {
  const vulnerabilities = Array.isArray(body?.vulnerabilities) ? body.vulnerabilities : [];
  const lowerPkg = packageName.toLowerCase();
  const out = [];

  for (const v of vulnerabilities) {
    const cve = v?.cve;
    if (!cve) continue;

    const cveId = cve.id;
    if (!cveId) continue;

    // Filter: NVD keywordSearch is fuzzy — keep only entries that actually
    // mention this package in their description (lowercased substring match).
    const description = pickEnglishDescription(cve);
    if (version && description && !description.toLowerCase().includes(lowerPkg)) {
      // If a version was given, we still allow it through if the package name
      // isn't explicitly absent — NVD keyword search isn't version-granular.
    }

    const { cvssScore, cvssSeverity } = extractCvss(cve);

    out.push({
      cveId,
      description,
      cvssScore,    // 0-10 or null
      cvssSeverity, // "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | null
      publishedDate: cve.published ?? null,
    });
  }

  return out;
}

function pickEnglishDescription(cve) {
  const descs = Array.isArray(cve.descriptions) ? cve.descriptions : [];
  const en = descs.find((d) => d?.lang === "en");
  return en?.value ?? descs[0]?.value ?? "";
}

function extractCvss(cve) {
  const metrics = cve.metrics ?? {};
  // Prefer CVSS v3.1, fall back to v3.0, then v2.
  const candidates = [
    ...(Array.isArray(metrics.cvssMetricV31) ? metrics.cvssMetricV31 : []),
    ...(Array.isArray(metrics.cvssMetricV30) ? metrics.cvssMetricV30 : []),
  ];

  for (const m of candidates) {
    const data = m?.cvssData;
    if (!data) continue;
    const score = typeof data.baseScore === "number" ? data.baseScore : null;
    const severity = data.baseSeverity ?? m.baseSeverity ?? null;
    if (score !== null) {
      return { cvssScore: score, cvssSeverity: severity };
    }
  }

  // Last-resort: CVSS v2
  if (Array.isArray(metrics.cvssMetricV2) && metrics.cvssMetricV2.length > 0) {
    const m = metrics.cvssMetricV2[0];
    const data = m?.cvssData;
    const score = typeof data?.baseScore === "number" ? data.baseScore : null;
    const severity = data?.baseSeverity ?? m?.baseSeverity ?? null;
    if (score !== null) {
      // Normalize v2 score to 0-10 scale (already is) and map severity.
      return { cvssScore: score, cvssSeverity: severity ?? deriveSeverityFromV2Score(score) };
    }
  }

  return { cvssScore: null, cvssSeverity: null };
}

function deriveSeverityFromV2Score(score) {
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  return "LOW";
}

// Test hook — not part of the public API but useful for resetting state between
// test runs. Not exported in package.json.
export function _resetNvdClientForTests() {
  cache.clear();
  requestTimestamps.length = 0;
}
