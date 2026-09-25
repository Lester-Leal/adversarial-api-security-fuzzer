/**
 * Fuzzer UI Server — Fastify 5, port 4000
 *
 * Exposes three API routes consumed by the /dashboard Next.js frontend:
 *
 *   POST /api/scan   — Run the full Red Team attack suite against a target URL.
 *                      Body: { targetUrl?: string }
 *                      Returns the FuzzState summary JSON.
 *
 *   GET  /api/logs   — Return the most recent summary.json + patches.diff content.
 *
 *   POST /api/patch  — Apply the Blue Team mutations to routes/index.ts and
 *                      return the patched source so the UI can show a diff.
 *                      Body: { diffPath?: string }
 */

import Fastify from "fastify";
import cors from "@fastify/cors";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { runFuzzer } from "./orchestrator/index.js";
import { applyMutations, MUTATIONS } from "./orchestrator/verify.js";

const PORT    = Number(process.env["UI_PORT"] ?? 4000);
const LOGS_DIR = path.resolve("logs");

// ── Helpers ───────────────────────────────────────────────────────────────────

async function latestFile(ext: string): Promise<string | null> {
  try {
    const entries = await readdir(LOGS_DIR);
    const matches = entries
      .filter((f) => f.endsWith(ext))
      .sort((a, b) => b.localeCompare(a));
    return matches[0] ? path.join(LOGS_DIR, matches[0]) : null;
  } catch {
    return null;
  }
}

// ── Build ─────────────────────────────────────────────────────────────────────

const app = Fastify({ logger: { level: "info" } });

await app.register(cors, {
  origin: true,          // reflect request origin — fine for a local dev tool
  methods: ["GET", "POST", "OPTIONS"],
});

// ── POST /api/scan ────────────────────────────────────────────────────────────
app.post("/api/scan", async (req, reply) => {
  const body = req.body as { targetUrl?: string } | null;
  const targetUrl = body?.targetUrl?.trim() || "http://127.0.0.1:3001";

  // Override TARGET_URL for this run so the runner hits the right host
  process.env["TARGET_URL"] = targetUrl;

  try {
    const state = await runFuzzer();
    // Strip large attack-result bodies before sending to the UI
    return reply.send({
      runId:       state.runId,
      startedAt:   state.startedAt,
      completedAt: state.completedAt,
      summary:     state.summary,
      vulnReports: state.vulnReports,
      patches:     state.patches.map((p) => ({
        payloadId:  p.payloadId,
        vulnClass:  p.vulnClass,
        targetFile: p.targetFile,
      })),
    });
  } catch (err) {
    app.log.error(err);
    return reply.status(500).send({ error: String(err) });
  }
});

// ── GET /api/logs ─────────────────────────────────────────────────────────────
app.get("/api/logs", async (_req, reply) => {
  const [summaryPath, diffPath] = await Promise.all([
    latestFile("-summary.json"),
    latestFile("-patches.diff"),
  ]);

  const [summary, diff] = await Promise.all([
    summaryPath ? readFile(summaryPath, "utf-8").then(JSON.parse).catch(() => null) : null,
    diffPath    ? readFile(diffPath,    "utf-8").catch(() => null)                  : null,
  ]);

  if (!summary && !diff) {
    return reply.status(404).send({ error: "No log files found. Run a scan first." });
  }

  return reply.send({
    summaryFile: summaryPath ? path.basename(summaryPath) : null,
    diffFile:    diffPath    ? path.basename(diffPath)    : null,
    summary,
    diff,
  });
});

// ── POST /api/patch ───────────────────────────────────────────────────────────
app.post("/api/patch", async (req, reply) => {
  const body = (req.body ?? {}) as { diffPath?: string };

  // Resolve the diff to apply: explicit path > latest in /logs
  let diffContent: string;
  try {
    const resolved = body.diffPath
      ? path.resolve(body.diffPath)
      : await latestFile("-patches.diff");

    if (!resolved) {
      return reply.status(404).send({ error: "No patch diff found. Run a scan first." });
    }
    diffContent = await readFile(resolved, "utf-8");
  } catch (err) {
    return reply.status(400).send({ error: `Could not read diff: ${String(err)}` });
  }

  // Parse vuln classes from the diff comment headers (# PAYLOAD-ID lines)
  const PAYLOAD_TO_CLASS: Record<string, string> = {
    "IDOR":        "IDOR",
    "MASS-ASSIGN": "MASS_ASSIGNMENT",
    "AUTH-BYPASS": "AUTH_BYPASS",
    "PRICE-MANIP": "PRICE_MANIPULATION",
    "INFO-DISC":   "INFO_DISCLOSURE",
  };
  const vulnClasses = new Set<string>();
  for (const line of diffContent.split("\n")) {
    const m = line.match(/^#\s+(\S+)/);
    if (!m) continue;
    const key = m[1] ?? "";
    const cls =
      PAYLOAD_TO_CLASS[key] ??
      Object.entries(PAYLOAD_TO_CLASS).find(([k]) => key.startsWith(k))?.[1];
    if (cls) vulnClasses.add(cls);
  }

  if (vulnClasses.size === 0) {
    // Allow explicit class list as fallback: apply all registered mutations
    for (const cls of Object.keys(MUTATIONS)) {
      if (!cls.endsWith("_VALUES")) vulnClasses.add(cls);
    }
  }

  // Read current routes source
  const ROUTES_FILE = path.resolve("target-api/src/routes/index.ts");
  let original: string;
  try {
    original = await readFile(ROUTES_FILE, "utf-8");
  } catch {
    return reply.status(500).send({ error: "Could not read routes file." });
  }

  const { patched, applied, skipped } = await applyMutations(vulnClasses, original);

  if (applied.length > 0) {
    const { writeFile } = await import("node:fs/promises");
    await writeFile(ROUTES_FILE, patched, "utf-8");
  }

  return reply.send({
    applied,
    skipped,
    linesChanged: patched.split("\n").length - original.split("\n").length,
    // Return a simple line diff for display in the UI
    diff: produceDiff(original, patched),
  });
});

/** Minimal +/- line diff (no external deps). */
function produceDiff(before: string, after: string): string {
  const a = before.split("\n");
  const b = after.split("\n");
  const lines: string[] = [`--- target-api/src/routes/index.ts (before)`, `+++ target-api/src/routes/index.ts (after)`];
  const maxLen = Math.max(a.length, b.length);
  for (let i = 0; i < maxLen; i++) {
    if (a[i] === b[i]) continue;
    if (a[i] !== undefined) lines.push(`- ${a[i]}`);
    if (b[i] !== undefined) lines.push(`+ ${b[i]}`);
  }
  return lines.join("\n");
}

// ── Start ─────────────────────────────────────────────────────────────────────
try {
  await app.listen({ port: PORT, host: "127.0.0.1" });
  console.log(`\n🖥️  Fuzzer UI Server → http://127.0.0.1:${PORT}`);
  console.log(`   POST /api/scan   — launch Red Team attack`);
  console.log(`   GET  /api/logs   — fetch latest results`);
  console.log(`   POST /api/patch  — apply Blue Team fixes\n`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
