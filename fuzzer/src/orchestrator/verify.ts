/**
 * Orchestrator — Auto-Patch Verifier
 *
 * Three-phase pipeline (strict Red Team → patch → re-verify lifecycle):
 *
 *   Phase 1 — DISCOVER
 *     Locate the most recently written .diff file in /logs.
 *     Parse which vulnerability classes it covers.
 *
 *   Phase 2 — PATCH
 *     Kill any running target server, apply source mutations to
 *     target-api/src/routes/index.ts, then spawn a fresh target process
 *     and wait until its health-check is reachable before continuing.
 *
 *   Phase 3 — VERIFY
 *     Re-run the full fuzzer pipeline against the patched server.
 *     Exit 0 when 0 confirmed findings remain; exit 1 otherwise.
 *
 * Usage:
 *   npm run verify
 *   npm run verify -- --diff logs/run-...-patches.diff
 */

import { readdir, readFile, writeFile, copyFile } from "node:fs/promises";
import { spawn, type ChildProcess } from "node:child_process";
import path from "node:path";
import { runFuzzer } from "./index.js";
import type { FuzzState } from "./index.js";

// ── ANSI colour helpers ───────────────────────────────────────────────────────
const C = {
  reset:  "\x1b[0m",
  bold:   "\x1b[1m",
  green:  "\x1b[32m",
  red:    "\x1b[31m",
  yellow: "\x1b[33m",
  cyan:   "\x1b[36m",
  dim:    "\x1b[2m",
};
const green  = (s: string) => `${C.bold}${C.green}${s}${C.reset}`;
const red    = (s: string) => `${C.bold}${C.red}${s}${C.reset}`;
const yellow = (s: string) => `${C.bold}${C.yellow}${s}${C.reset}`;
const cyan   = (s: string) => `${C.bold}${C.cyan}${s}${C.reset}`;
const dim    = (s: string) => `${C.dim}${s}${C.reset}`;
const hr     = (ch = "─", n = 60) => ch.repeat(n);

// ── Constants ─────────────────────────────────────────────────────────────────
const ROUTES_FILE  = path.resolve("target-api/src/routes/index.ts");
const SERVER_FILE  = path.resolve("target-api/src/server.ts");
const TSCONFIG     = path.resolve("tsconfig.json");
const LOGS_DIR     = path.resolve("logs");
const BACKUP_EXT   = ".verify-backup";
const TARGET_URL   = process.env["TARGET_URL"] ?? "http://127.0.0.1:3001";
const HEALTH_ROUTE = `${TARGET_URL}/users`;          // any route that returns fast
const POLL_MS      = 300;
const POLL_TIMEOUT = 15_000;

// ── Phase 1: Discover most-recent diff ───────────────────────────────────────

async function findLatestDiff(overridePath?: string): Promise<string> {
  if (overridePath) {
    return path.resolve(overridePath);
  }
  const entries = await readdir(LOGS_DIR);
  const diffs = entries
    .filter((f) => f.endsWith(".diff"))
    .map((f) => ({ name: f, abs: path.join(LOGS_DIR, f) }))
    .sort((a, b) => b.name.localeCompare(a.name));

  if (diffs.length === 0) {
    throw new Error(
      `No .diff files in ${LOGS_DIR}. Run \`npm run fuzzer\` first.`
    );
  }
  console.log(dim(`  Latest diff: ${diffs[0]!.name}`));
  return diffs[0]!.abs;
}

function parseDiffVulnClasses(diffContent: string): Set<string> {
  const PAYLOAD_TO_CLASS: Record<string, string> = {
    "IDOR":        "IDOR",
    "MASS-ASSIGN": "MASS_ASSIGNMENT",
    "AUTH-BYPASS": "AUTH_BYPASS",
    "PRICE-MANIP": "PRICE_MANIPULATION",
    "INFO-DISC":   "INFO_DISCLOSURE",
  };
  const found = new Set<string>();
  for (const line of diffContent.split("\n")) {
    const m = line.match(/^#\s+(\S+)/);
    if (!m) continue;
    const key = m[1] ?? "";
    const cls =
      PAYLOAD_TO_CLASS[key] ??
      Object.entries(PAYLOAD_TO_CLASS).find(([k]) => key.startsWith(k))?.[1];
    if (cls) found.add(cls);
  }
  return found;
}

// ── Phase 2a: Source mutations ────────────────────────────────────────────────
//
// Each RegexMutation matches code STRUCTURE rather than exact text.
// Patterns use \s+ in place of every whitespace span so they survive
// re-formatting, comment edits, and line-ending changes.
//
// `replace` is a string passed to String.prototype.replace(regex, replace).
// Use $& to reference the matched text where needed.
//
// All patterns are idempotent: they only match the VULNERABLE form, so running
// verify twice on an already-patched file is a safe no-op.

interface RegexMutation {
  description: string;
  /** Regex that matches the vulnerable code region. Use the `s` (dotAll) flag for multi-line spans. */
  pattern: RegExp;
  /** Replacement string (may reference capture groups $1, $2 …). */
  replace: string;
}

const MUTATIONS: Record<string, RegexMutation> = {
  // ── IDOR ───────────────────────────────────────────────────────────────────
  // Matches the GET /notes/:id handler body that returns the note without an
  // ownership check.  Anchored to the 404 guard + bare reply.send(note) line.
  IDOR: {
    description: "IDOR → ownership check on GET /notes/:id",
    pattern: new RegExp(
      // Capture leading whitespace so we can re-indent the replacement.
      `([ \\t]*)if\\s*\\(!note\\)\\s*return\\s+reply\\.code\\(404\\)[^;]+;\\s*` +
      `return\\s+reply\\.send\\(note\\);[^\\n]*`,
      "g"
    ),
    replace: [
      "$1if (!note) return reply.code(404).send({ error: \"Not found\" });",
      "$1// [PATCHED] Ownership check to prevent IDOR",
      "$1const currentUser = req.user as { id: number };",
      "$1if (note.ownerId !== currentUser.id) {",
      "$1  return reply.code(403).send({ error: \"Forbidden\" });",
      "$1}",
      "$1return reply.send(note);",
    ].join("\n"),
  },

  // ── MASS_ASSIGNMENT ────────────────────────────────────────────────────────
  // Matches the destructuring that pulls `isAdmin` from req.body inside the
  // /register handler, plus the .values() call that spreads isAdmin.
  MASS_ASSIGNMENT: {
    description: "MASS_ASSIGNMENT → strip isAdmin from POST /register body",
    pattern: new RegExp(
      // Destructure line that includes isAdmin
      `([ \\t]*)const\\s*\\{\\s*username\\s*,\\s*password\\s*,\\s*isAdmin\\s*\\}` +
      `\\s*=\\s*req\\.body\\s+as\\s+\\{[^}]+isAdmin\\?\\s*:\\s*boolean[^}]*\\};`,
      "gs"
    ),
    replace: [
      "$1// [PATCHED] Allowlist — isAdmin stripped from request body",
      "$1const { username, password } = req.body as {",
      "$1  username: string;",
      "$1  password: string;",
      "$1};",
    ].join("\n"),
  },

  // The isAdmin field in .values() must also be fixed — separate pattern so
  // it applies even when the destructure line was already cleaned up.
  MASS_ASSIGNMENT_VALUES: {
    description: "MASS_ASSIGNMENT → force isAdmin:false in .values()",
    pattern: new RegExp(
      `isAdmin\\s*:\\s*isAdmin\\s*\\?\\?\\s*false`,
      "g"
    ),
    replace: "isAdmin: false",
  },

  // ── AUTH_BYPASS ────────────────────────────────────────────────────────────
  // Matches app.get("/users", async ... without an onRequest hook.
  AUTH_BYPASS: {
    description: "AUTH_BYPASS → add onRequest auth guard to GET /users",
    pattern: new RegExp(
      `([ \\t]*)app\\.get\\(\\s*"/users"\\s*,\\s*async\\s*\\(`,
      "g"
    ),
    replace: '$1app.get("/users", { onRequest: [app.authenticate] }, async (',
  },

  // ── PRICE_MANIPULATION ─────────────────────────────────────────────────────
  // Matches the destructure that pulls `price` from req.body in POST /orders.
  PRICE_MANIPULATION: {
    description: "PRICE_MANIPULATION → server-side price lookup in POST /orders",
    pattern: new RegExp(
      `([ \\t]*)const\\s*\\{\\s*product\\s*,\\s*price\\s*\\}` +
      `\\s*=\\s*req\\.body\\s+as\\s*\\{[^}]+price\\s*:\\s*number[^}]*\\};`,
      "gs"
    ),
    replace: [
      "$1// [PATCHED] Server-side price lookup — client price is ignored",
      "$1const { product } = req.body as { product: string };",
      "$1const CATALOGUE: Record<string, number> = { Widget: 9.99, Gadget: 49.99 };",
      "$1const price = CATALOGUE[product] ?? 0;",
      "$1if (price === 0) return reply.code(400).send({ error: \"Unknown product\" });",
    ].join("\n"),
  },

  // ── INFO_DISCLOSURE ────────────────────────────────────────────────────────
  // Matches db.select().from(users) with no column projection inside a GET /users handler.
  // We look for the bare select() call — if a projection already exists (patched),
  // the pattern won't match because select() won't be followed by .from() directly.
  INFO_DISCLOSURE: {
    description: "INFO_DISCLOSURE → safe column projection on GET /users",
    pattern: new RegExp(
      `([ \\t]*)const\\s+(\\w+)\\s*=\\s*await\\s+db\\.select\\(\\)\\.from\\(users\\);`,
      "g"
    ),
    replace: [
      "$1// [PATCHED] Project safe columns only — never expose password or apiKey",
      "$1const $2 = await db.select({",
      "$1  id:       users.id,",
      "$1  username: users.username,",
      "$1  isAdmin:  users.isAdmin,",
      "$1}).from(users);",
    ].join("\n"),
  },
};

async function applyMutations(
  vulnClasses: Set<string>,
  source: string,
): Promise<{ patched: string; applied: string[]; skipped: string[] }> {
  let patched = source;
  const applied: string[] = [];
  const skipped: string[] = [];

  // Expand MASS_ASSIGNMENT to also run the companion VALUES patch
  const toApply = new Set(vulnClasses);
  if (toApply.has("MASS_ASSIGNMENT")) toApply.add("MASS_ASSIGNMENT_VALUES");

  for (const cls of toApply) {
    const mut = MUTATIONS[cls];
    if (!mut) {
      if (!cls.endsWith("_VALUES")) skipped.push(`${cls} (no mutation registered)`);
      continue;
    }
    // Test whether the pattern matches before replacing
    mut.pattern.lastIndex = 0;
    if (!mut.pattern.test(patched)) {
      mut.pattern.lastIndex = 0;
      if (!cls.endsWith("_VALUES")) {
        skipped.push(`${cls} (pattern did not match — may already be patched)`);
      }
      continue;
    }
    mut.pattern.lastIndex = 0;
    patched = patched.replace(mut.pattern, mut.replace);
    if (!cls.endsWith("_VALUES")) applied.push(cls);
  }
  return { patched, applied, skipped };
}

// Exported for testing
export { applyMutations, MUTATIONS };

// ── Phase 2b: Target server lifecycle ────────────────────────────────────────

/** Kill a child process and wait for it to fully exit. */
function killProcess(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null) { resolve(); return; }
    child.once("exit", () => resolve());
    child.kill("SIGTERM");
    // Force-kill after 3 s if still alive
    setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* already gone */ } }, 3000);
  });
}

/**
 * Kill whatever process is currently holding the target port so the fresh
 * patched server can bind it.  Works on Windows (taskkill) and POSIX (kill).
 */
async function evictPortHolder(port: number): Promise<void> {
  return new Promise((resolve) => {
    // netstat is available on both Windows and Linux/macOS
    const ns = spawn("netstat", ["-ano"], { shell: true, stdio: ["ignore", "pipe", "ignore"] });
    let out = "";
    ns.stdout?.on("data", (d: Buffer) => { out += d.toString(); });
    ns.on("close", () => {
      const pattern = new RegExp(`:${port}\\s.*LISTENING\\s+(\\d+)`);
      const m = out.match(pattern);
      if (!m) { resolve(); return; }                    // nothing to evict
      const pid = m[1]!;
      const killer = process.platform === "win32"
        ? spawn("taskkill", ["/F", "/PID", pid], { shell: true, stdio: "ignore" })
        : spawn("kill",     ["-9", pid],          { shell: true, stdio: "ignore" });
      killer.on("close", () => {
        // Give the OS 500 ms to fully release the port
        setTimeout(resolve, 500);
      });
    });
  });
}

/** Spawn the target server as a detached child; pipe stdout/stderr to parent. */
function spawnTarget(): ChildProcess {
  const child = spawn(
    process.execPath,                        // same node binary
    ["--import", "tsx/esm", SERVER_FILE, "--tsconfig", TSCONFIG],
    { stdio: ["ignore", "pipe", "pipe"], env: process.env }
  );
  child.stdout?.on("data", (d: Buffer) =>
    process.stdout.write(dim(`  [target] ${d.toString().trim()}\n`))
  );
  child.stderr?.on("data", (d: Buffer) =>
    process.stderr.write(dim(`  [target] ${d.toString().trim()}\n`))
  );
  return child;
}

/** Poll the health route until it responds or we time out. */
async function waitForTarget(): Promise<void> {
  const deadline = Date.now() + POLL_TIMEOUT;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(HEALTH_ROUTE, { signal: AbortSignal.timeout(500) });
      if (res.status < 500) return;          // any non-5xx means the server is up
    } catch { /* not ready yet */ }
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
  throw new Error(`Target did not become healthy within ${POLL_TIMEOUT / 1000}s.`);
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log(`\n${hr("═")}`);
  console.log(cyan("  🛡   Adversarial API Security Fuzzer — Auto-Patch Verifier"));
  console.log(`${hr("═")}\n`);

  const diffFlagIdx = process.argv.indexOf("--diff");
  const diffOverride = diffFlagIdx !== -1 ? process.argv[diffFlagIdx + 1] : undefined;

  // ── Phase 1 ───────────────────────────────────────────────────────────────
  console.log(yellow("Phase 1 — Discover"));
  const diffPath    = await findLatestDiff(diffOverride);
  const diffContent = await readFile(diffPath, "utf-8");
  const vulnClasses = parseDiffVulnClasses(diffContent);

  if (vulnClasses.size === 0) {
    console.log(dim("  No vuln-class tokens found in diff. Nothing to patch."));
    process.exit(0);
  }
  console.log(`  Vuln classes to patch: ${[...vulnClasses].join(", ")}\n`);

  // ── Phase 2 ───────────────────────────────────────────────────────────────
  console.log(yellow("Phase 2 — Patch"));

  const originalSource = await readFile(ROUTES_FILE, "utf-8");
  const backupPath     = ROUTES_FILE + BACKUP_EXT;
  await copyFile(ROUTES_FILE, backupPath);
  console.log(dim(`  Backup written → ${backupPath}`));

  const { patched, applied, skipped } = await applyMutations(vulnClasses, originalSource);
  for (const cls of applied) console.log(`  ✓ Applied  — ${cls}`);
  for (const cls of skipped) console.log(dim(`  ⊘ Skipped  — ${cls}`));

  if (applied.length > 0) {
    await writeFile(ROUTES_FILE, patched, "utf-8");
    console.log(`\n  ${applied.length} mutation(s) written to routes/index.ts`);
  } else {
    console.log(yellow("\n  All patches already applied or no matching text found."));
  }

  // Evict any process holding the target port, then start a fresh patched server.
  const targetPort = Number(new URL(TARGET_URL).port || 3001);
  console.log(dim(`\n  Evicting any process on port ${targetPort}…`));
  await evictPortHolder(targetPort);
  console.log(dim("  Restarting target server with patched source…"));

  let targetProc: ChildProcess | undefined;
  try {
    targetProc = spawnTarget();
    await waitForTarget();
    console.log(green("  ✓ Patched target server is healthy.\n"));
  } catch (startErr) {
    // Restore backup and abort
    await copyFile(backupPath, ROUTES_FILE);
    console.error(red("  ✗ Patched target failed to start — original source restored."));
    console.error(startErr);
    if (targetProc) await killProcess(targetProc);
    process.exit(1);
  }

  // ── Phase 3 ───────────────────────────────────────────────────────────────
  console.log(yellow("Phase 3 — Re-Verify"));
  console.log(cyan("⟳  Re-running fuzzer against patched API…\n"));

  let state: FuzzState;
  try {
    state = await runFuzzer();
  } catch (err) {
    await copyFile(backupPath, ROUTES_FILE);
    console.error(red("\n  Fuzzer threw — original source restored."), err);
    if (targetProc) await killProcess(targetProc);
    process.exit(1);
  } finally {
    if (targetProc) await killProcess(targetProc);
  }

  // ── Result ────────────────────────────────────────────────────────────────
  const remaining = state.summary.confirmed;

  console.log(`\n${hr("═")}`);
  if (remaining === 0) {
    console.log(green("  ✅  [VERIFIED] All payloads blocked. API is secure."));
    console.log(green(`       0 / ${state.summary.totalAttacks} attacks confirmed after patch.`));
  } else {
    console.log(red(`  ❌  [FAILED] ${remaining} vulnerability/vulnerabilities still confirmed after patch.`));
    const survivors = state.vulnReports.filter((r) => r.confirmed);
    for (const r of survivors) {
      console.log(red(`       • [${r.severity}] ${r.vulnClass} — ${r.payloadId}`));
      console.log(dim(`         ${r.evidence}`));
    }
    console.log(yellow("\n  Inspect the routes file and diff for coverage gaps."));
  }
  console.log(`${hr("═")}\n`);

  process.exit(remaining === 0 ? 0 : 1);
}

// ── Entrypoint guard ─────────────────────────────────────────────────────────
// Only run when executed directly (npm run verify), not when imported by
// ui-server.ts.  Mirrors the same guard used in orchestrator/index.ts.
function _bn(p: string): string {
  return p.replace(/\\/g, "/").split("/").pop()?.replace(/\.(js|ts)$/, "") ?? "";
}
if (_bn(import.meta.url) === _bn(process.argv[1] ?? "")) {
  await main();
}
