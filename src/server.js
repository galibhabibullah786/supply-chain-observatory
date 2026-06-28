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
app.use("/api", analyzeRouter);
app.use(express.static(path.join(__dirname, "../public")));

app.listen(port, () => {
  console.log(`Supply Chain Observatory listening on port ${port}`);
});
