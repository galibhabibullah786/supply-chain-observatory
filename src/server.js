// Single responsibility: configure and start the Express HTTP server for the Supply Chain Observatory API and static UI.
import "dotenv/config";
import express from "express";
import cors from "cors";
import path from "node:path";
import { fileURLToPath } from "node:url";
import analyzeRouter from "./routes/analyze.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const port = process.env.PORT || 8080;

app.use(cors());
app.use(express.json({ limit: "1mb" }));

// Tiny health check. Useful for smoke tests and for the frontend to know the
// server is alive before kicking off a long /analyze request.
app.get("/api/health", (_req, res) => {
  res.status(200).json({
    status: "ok",
    service: "supply-chain-observatory",
    time: new Date().toISOString(),
    geminiConfigured: Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.length > 0),
    nvdConfigured: Boolean(process.env.NVD_API_KEY && process.env.NVD_API_KEY.length > 0),
  });
});

app.use("/api", analyzeRouter);
app.use(express.static(path.join(__dirname, "../public")));

// Last-resort JSON 404 for any /api/* route that didn't match above.
// The static middleware will serve /index.html for non-/api paths, so
// this only fires for unknown API endpoints.
app.use("/api", (_req, res) => {
  res.status(404).json({ error: "not_found", message: "Unknown API endpoint." });
});

// Express error handler: converts uncaught errors into clean JSON so a frontend
// fetch never gets an HTML stack trace.
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error("[server] unhandled error:", err);
  if (res.headersSent) return;
  res.status(500).json({
    error: "server_error",
    message: err?.message || "Unhandled server error.",
  });
});

app.listen(port, () => {
  const hasGemini = Boolean(process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY.length > 0);
  const hasNvd = Boolean(process.env.NVD_API_KEY && process.env.NVD_API_KEY.length > 0);
  console.log(`Supply Chain Observatory listening on http://localhost:${port}`);
  console.log(`  Gemini: ${hasGemini ? "configured" : "MISSING — narrative/exploitability will fall back"}`);
  console.log(`  NVD:    ${hasNvd ? "configured (48 req/30s)" : "not configured (4 req/30s)"}`);
  console.log(`  UI:     http://localhost:${port}/`);
});
