// Micro-level unit tests for src/clients/nvdClient.js
//
// Run with:  npm test
//
// Uses Node's built-in test runner (node:test). Three groups:
//   A. Pure-shape / normalization tests — use a mocked fetch so no network is touched
//   B. Defensive-resilience tests       — simulate timeouts, 4xx/5xx, malformed bodies
//   C. Cache + rate-limiter behavior    — assert cache hits and limiter slot acquisition

import { test, describe, beforeEach } from "node:test";
import assert from "node:assert/strict";
import {
  lookupCves,
  _resetNvdClientForTests,
} from "../../src/clients/nvdClient.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeNvdBody(vulns) {
  return { vulnerabilities: vulns };
}

function makeV31Cve({ id, description, score, severity, published }) {
  return {
    cve: {
      id,
      descriptions: [{ lang: "en", value: description }],
      metrics: {
        cvssMetricV31: [
          {
            cvssData: { baseScore: score, baseSeverity: severity },
          },
        ],
      },
      published,
    },
  };
}

function makeV30Cve({ id, description, score, severity }) {
  return {
    cve: {
      id,
      descriptions: [{ lang: "en", value: description }],
      metrics: {
        cvssMetricV30: [
          {
            cvssData: { baseScore: score, baseSeverity: severity },
          },
        ],
      },
    },
  };
}

function makeV2Cve({ id, description, score }) {
  return {
    cve: {
      id,
      descriptions: [{ lang: "en", value: description }],
      metrics: {
        cvssMetricV2: [
          {
            cvssData: { baseScore: score }, // v2 metrics often omit severity
          },
        ],
      },
    },
  };
}

function makeBareCve({ id, description }) {
  return {
    cve: {
      id,
      descriptions: [{ lang: "en", value: description }],
      metrics: {},
    },
  };
}

/**
 * Install a stub fetch on globalThis. Returns a restore() function the caller
 * MUST call in finally{}. The handler is (url, init) => Promise<Response>.
 */
function stubFetch(handler) {
  const orig = globalThis.fetch;
  globalThis.fetch = handler;
  return () => {
    globalThis.fetch = orig;
  };
}

beforeEach(() => {
  _resetNvdClientForTests();
  // Clear any API-key env so we exercise the unkeyed branch by default.
  delete process.env.NVD_API_KEY;
  // Default test budget: generous, so individual tests don't queue. The
  // rate-limiter test sets this lower to exercise the limit.
  process.env.NVD_TEST_MAX_REQUESTS = "10000";
});

// ---------------------------------------------------------------------------
// Group A — Shape & normalization
// ---------------------------------------------------------------------------
describe("nvdClient.lookupCves — shape & normalization", () => {
  test("returns [] for empty / nullish package names", async () => {
    assert.deepEqual(await lookupCves(""), []);
    assert.deepEqual(await lookupCves(null), []);
    assert.deepEqual(await lookupCves(undefined), []);
  });

  test("parses a CVSS v3.1 entry into the simplified shape", async () => {
    const restore = stubFetch(async () => ({
      ok: true,
      status: 200,
      json: async () =>
        makeNvdBody([
          makeV31Cve({
            id: "CVE-2024-0001",
            description: "lodash prototype pollution",
            score: 7.5,
            severity: "HIGH",
            published: "2024-01-15T10:00:00.000Z",
          }),
        ]),
    }));

    try {
      const out = await lookupCves("lodash", "4.17.20");
      assert.equal(out.length, 1);
      assert.deepEqual(out[0], {
        cveId: "CVE-2024-0001",
        description: "lodash prototype pollution",
        cvssScore: 7.5,
        cvssSeverity: "HIGH",
        publishedDate: "2024-01-15T10:00:00.000Z",
      });
    } finally {
      restore();
    }
  });

  test("falls back to v3.0 when v3.1 is absent", async () => {
    const restore = stubFetch(async () => ({
      ok: true,
      status: 200,
      json: async () =>
        makeNvdBody([
          makeV30Cve({
            id: "CVE-2024-0002",
            description: "xss in some pkg",
            score: 6.1,
            severity: "MEDIUM",
          }),
        ]),
    }));

    try {
      const out = await lookupCves("some-pkg", "1.0.0");
      assert.equal(out.length, 1);
      assert.equal(out[0].cvssScore, 6.1);
      assert.equal(out[0].cvssSeverity, "MEDIUM");
    } finally {
      restore();
    }
  });

  test("falls back to v2 and derives severity when label is missing", async () => {
    const restore = stubFetch(async () => ({
      ok: true,
      status: 200,
      json: async () =>
        makeNvdBody([
          makeV2Cve({ id: "CVE-2024-0003", description: "old thing", score: 8.5 }),
        ]),
    }));

    try {
      const out = await lookupCves("old-pkg", "0.1.0");
      assert.equal(out.length, 1);
      assert.equal(out[0].cvssScore, 8.5);
      // No severity label was provided — derive from score.
      assert.equal(out[0].cvssSeverity, "HIGH");
    } finally {
      restore();
    }
  });

  test("derives LOW severity from a low v2 score", async () => {
    const restore = stubFetch(async () => ({
      ok: true,
      status: 200,
      json: async () =>
        makeNvdBody([
          makeV2Cve({ id: "CVE-2024-0004", description: "minor", score: 3.5 }),
        ]),
    }));

    try {
      const out = await lookupCves("p", "1");
      assert.equal(out[0].cvssSeverity, "LOW");
    } finally {
      restore();
    }
  });

  test("returns cvssScore=null when no metrics are present", async () => {
    const restore = stubFetch(async () => ({
      ok: true,
      status: 200,
      json: async () =>
        makeNvdBody([
          makeBareCve({ id: "CVE-2024-0005", description: "no metrics" }),
        ]),
    }));

    try {
      const out = await lookupCves("p", "1");
      assert.equal(out.length, 1);
      assert.equal(out[0].cvssScore, null);
      assert.equal(out[0].cvssSeverity, null);
    } finally {
      restore();
    }
  });

  test("skips entries with no cve.id", async () => {
    const restore = stubFetch(async () => ({
      ok: true,
      status: 200,
      json: async () =>
        makeNvdBody([
          { cve: { /* no id */ descriptions: [{ lang: "en", value: "x" }] } },
          makeBareCve({ id: "CVE-2024-0006", description: "ok" }),
        ]),
    }));

    try {
      const out = await lookupCves("p", "1");
      assert.equal(out.length, 1);
      assert.equal(out[0].cveId, "CVE-2024-0006");
    } finally {
      restore();
    }
  });

  test("falls back to first description when no English one is present", async () => {
    const restore = stubFetch(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        vulnerabilities: [
          {
            cve: {
              id: "CVE-2024-0007",
              descriptions: [
                { lang: "es", value: "descripcion en espanol" },
                { lang: "fr", value: "description francaise" },
              ],
              metrics: {},
            },
          },
        ],
      }),
    }));

    try {
      const out = await lookupCves("p", "1");
      // Falls back to descriptions[0].value
      assert.equal(out[0].description, "descripcion en espanol");
    } finally {
      restore();
    }
  });

  test("always emits the simplified shape with the documented keys", async () => {
    const restore = stubFetch(async () => ({
      ok: true,
      status: 200,
      json: async () =>
        makeNvdBody([
          makeV31Cve({
            id: "CVE-2024-9999",
            description: "shape check",
            score: 5.0,
            severity: "MEDIUM",
          }),
        ]),
    }));

    try {
      const out = await lookupCves("p", "1");
      const keys = Object.keys(out[0]).sort();
      assert.deepEqual(keys, [
        "cveId",
        "cvssScore",
        "cvssSeverity",
        "description",
        "publishedDate",
      ]);
    } finally {
      restore();
    }
  });
});

// ---------------------------------------------------------------------------
// Group B — Resilience (timeouts, 4xx, 5xx, malformed bodies)
// ---------------------------------------------------------------------------
describe("nvdClient.lookupCves — resilience", () => {
  test("aborted (timeout) request returns [] and does not throw", async () => {
    const restore = stubFetch(
      (_url, opts) =>
        new Promise((_resolve, reject) => {
          opts.signal.addEventListener("abort", () => {
            const e = new Error("aborted");
            e.name = "AbortError";
            reject(e);
          });
        })
    );

    try {
      const out = await lookupCves("slowpkg", "1.0.0");
      assert.deepEqual(out, []);
    } finally {
      restore();
    }
  });

  test("429 is retried with backoff, then surfaces [] on exhaustion", async () => {
    let calls = 0;
    const restore = stubFetch(async () => {
      calls += 1;
      return { ok: false, status: 429, json: async () => ({}) };
    });

    try {
      const out = await lookupCves("limited", "1");
      assert.deepEqual(out, []);
      // 1 initial + up to 3 retries = 4 calls maximum
      assert.ok(calls >= 1 && calls <= 4, `expected 1..4 calls, got ${calls}`);
    } finally {
      restore();
    }
  });

  test("403 is retried then gives up", async () => {
    let calls = 0;
    const restore = stubFetch(async () => {
      calls += 1;
      return { ok: false, status: 403, json: async () => ({}) };
    });

    try {
      const out = await lookupCves("forbidden", "1");
      assert.deepEqual(out, []);
      assert.ok(calls <= 4);
    } finally {
      restore();
    }
  });

  test("500 is treated as terminal non-OK (returns [])", async () => {
    let calls = 0;
    const restore = stubFetch(async () => {
      calls += 1;
      return { ok: false, status: 500, json: async () => ({}) };
    });

    try {
      const out = await lookupCves("server-error", "1");
      assert.deepEqual(out, []);
      assert.equal(calls, 1, "500 is not retried");
    } finally {
      restore();
    }
  });

  test("malformed JSON body returns [] (does not throw)", async () => {
    const restore = stubFetch(async () => ({
      ok: true,
      status: 200,
      json: async () => {
        throw new SyntaxError("Unexpected token }");
      },
    }));

    try {
      const out = await lookupCves("bad-json", "1");
      assert.deepEqual(out, []);
    } finally {
      restore();
    }
  });

  test("missing vulnerabilities array returns []", async () => {
    const restore = stubFetch(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ resultsPerPage: 0 }),
    }));

    try {
      const out = await lookupCves("empty", "1");
      assert.deepEqual(out, []);
    } finally {
      restore();
    }
  });
});

// ---------------------------------------------------------------------------
// Group C — Cache & rate-limiter behavior
// ---------------------------------------------------------------------------
describe("nvdClient.lookupCves — cache & rate limiter", () => {
  test("identical lookups within a process hit the cache (fetch called once)", async () => {
    let calls = 0;
    const restore = stubFetch(async () => {
      calls += 1;
      return {
        ok: true,
        status: 200,
        json: async () =>
          makeNvdBody([
            makeBareCve({ id: "CVE-2024-CACHE", description: "x" }),
          ]),
      };
    });

    try {
      await lookupCves("cachedpkg", "1.0.0");
      await lookupCves("cachedpkg", "1.0.0");
      await lookupCves("cachedpkg", "1.0.0");
      await lookupCves("CACHEDPKG", "9.9.9"); // case-insensitive key
      assert.equal(calls, 1, "fetch should only be called once for the same package");
    } finally {
      restore();
    }
  });

  test("a failed lookup is NOT permanently cached (next call can retry)", async () => {
    let calls = 0;
    const restore = stubFetch(async () => {
      calls += 1;
      return { ok: false, status: 500, json: async () => ({}) };
    });

    try {
      await lookupCves("flaky", "1");
      await lookupCves("flaky", "1");
      // 500 is not retried (terminal), so 1 + 1 = 2 calls
      assert.equal(calls, 2, "after a terminal failure, the next call should retry fetch");
    } finally {
      restore();
    }
  });

  test("concurrent identical lookups share a single in-flight request", async () => {
    let calls = 0;
    const restore = stubFetch(async () => {
      calls += 1;
      // Yield so concurrent callers have time to all attach to the in-flight promise.
      await new Promise((r) => setTimeout(r, 30));
      return {
        ok: true,
        status: 200,
        json: async () =>
          makeNvdBody([
            makeBareCve({ id: "CVE-2024-SHARED", description: "x" }),
          ]),
      };
    });

    try {
      const [a, b, c, d] = await Promise.all([
        lookupCves("shared", "1"),
        lookupCves("shared", "2"),
        lookupCves("SHARED", "3"),
        lookupCves("shared", "4"),
      ]);
      assert.equal(calls, 1, "all concurrent callers should share one fetch");
      assert.equal(a.length, 1);
      assert.equal(b.length, 1);
      assert.equal(c.length, 1);
      assert.equal(d.length, 1);
    } finally {
      restore();
    }
  });

  test("NVD_API_KEY header is included when env var is set", async () => {
    process.env.NVD_API_KEY = "test-key-123";
    let lastHeaders = null;
    const restore = stubFetch(async (_url, init) => {
      lastHeaders = init.headers;
      return {
        ok: true,
        status: 200,
        json: async () => makeNvdBody([]),
      };
    });

    try {
      await lookupCves("hdrcheck", "1");
      assert.equal(lastHeaders.apiKey, "test-key-123");
      assert.equal(lastHeaders.Accept, "application/json");
    } finally {
      restore();
    }
  });

  test("NVD_API_KEY header is omitted when env var is absent", async () => {
    let lastHeaders = null;
    const restore = stubFetch(async (_url, init) => {
      lastHeaders = init.headers;
      return {
        ok: true,
        status: 200,
        json: async () => makeNvdBody([]),
      };
    });

    try {
      await lookupCves("nokey", "1");
      assert.equal(lastHeaders.apiKey, undefined);
      assert.equal(lastHeaders.Accept, "application/json");
    } finally {
      restore();
    }
  });

  test("URL is the documented NVD v2.0 keywordSearch endpoint with encoded name", async () => {
    let lastUrl = null;
    const restore = stubFetch(async (url) => {
      lastUrl = url;
      return { ok: true, status: 200, json: async () => makeNvdBody([]) };
    });

    try {
      await lookupCves("@scope/pkg", "1.0.0");
      assert.match(lastUrl, /^https:\/\/services\.nvd\.nist\.gov\/rest\/json\/cves\/2\.0\?/);
      assert.ok(lastUrl.includes("keywordSearch="));
      assert.ok(lastUrl.includes(encodeURIComponent("@scope/pkg")));
      assert.ok(lastUrl.includes("resultsPerPage=20"));
    } finally {
      restore();
    }
  });

  test("rate limiter caps consecutive unkeyed calls at 4 within 30s", async () => {
    // Without an API key the limit is 4 per 30s. Make 6 lookups for distinct
    // packages — we expect 4 immediate calls + the rest queued. We assert
    // that the first 4 were issued promptly (no queuing delay).
    // Opt into the low default limit (no API key, no test override).
    delete process.env.NVD_TEST_MAX_REQUESTS;
    _resetNvdClientForTests();

    let callCount = 0;
    const restore = stubFetch(async () => {
      callCount += 1;
      return { ok: true, status: 200, json: async () => makeNvdBody([]) };
    });

    try {
      const start = Date.now();
      const lookups = Array.from({ length: 6 }, (_, i) =>
        lookupCves(`rl-pkg-${i}`, "1")
      );
      // Wait long enough for queued items to drain (backoff is small here).
      await Promise.all(lookups);
      const elapsed = Date.now() - start;
      assert.equal(callCount, 6, "all 6 lookups should eventually complete");
      assert.ok(
        elapsed >= 1000,
        `expected queuing delay of >=1s for 6 unkeyed calls within a 30s window, got ${elapsed}ms`
      );
    } finally {
      restore();
    }
  });
});
