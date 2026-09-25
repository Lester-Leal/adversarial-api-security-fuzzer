/**
 * Orchestrator — Workflow Manager
 *
 * Coordinates the Red Team and Blue Team agents in a sequential pipeline:
 *
 *   1. Red Team generates and fires all attack payloads.
 *   2. Blue Team analyses the raw results and confirms vulnerabilities.
 *   3. Blue Team generates code-level patches for each confirmed finding.
 *   4. All output is persisted to /logs.
 *
 * The state object (FuzzState) is passed through each stage and written to
 * disk as a single audit artefact at the end of every run.
 */

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { allPayloads }     from "../red-team/payloads.js";
import { runAllAttacks }   from "../red-team/runner.js";
import { analyseResults }  from "../blue-team/analyser.js";
import { generatePatches } from "../blue-team/patcher.js";
import type { AttackResult } from "../red-team/runner.js";
import type { VulnReport }   from "../blue-team/analyser.js";
import type { Patch }        from "../blue-team/patcher.js";

// ── Shared state shape ────────────────────────────────────────────────────────
export interface FuzzState {
  runId:       string;
  startedAt:   string;
  completedAt?: string;
  attackResults: AttackResult[];
  vulnReports:   VulnReport[];
  patches:       Patch[];
  summary: {
    totalAttacks:   number;
    confirmed:      number;
    bySeverity:     Record<string, number>;
  };
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function buildRunId(): string {
  return `run-${new Date().toISOString().replace(/[:.]/g, "-")}`;
}

function buildSummary(state: Pick<FuzzState, "attackResults" | "vulnReports">): FuzzState["summary"] {
  const confirmed = state.vulnReports.filter((r) => r.confirmed);
  const bySeverity: Record<string, number> = {};
  for (const r of confirmed) {
    bySeverity[r.severity] = (bySeverity[r.severity] ?? 0) + 1;
  }
  return {
    totalAttacks: state.attackResults.length,
    confirmed:    confirmed.length,
    bySeverity,
  };
}

// ── Main orchestration loop ───────────────────────────────────────────────────
export async function runFuzzer(): Promise<FuzzState> {
  const runId = buildRunId();
  console.log(`\n${"─".repeat(60)}`);
  console.log(`🚀  Adversarial API Security Fuzzer — ${runId}`);
  console.log(`${"─".repeat(60)}\n`);

  const state: FuzzState = {
    runId,
    startedAt: new Date().toISOString(),
    attackResults: [],
    vulnReports:   [],
    patches:       [],
    summary:       { totalAttacks: 0, confirmed: 0, bySeverity: {} },
  };

  // ── Stage 1: Red Team ───────────────────────────────────────────────────────
  console.log("🔴  [Red Team] Generating payloads…");
  const payloads = allPayloads();
  console.log(`    ${payloads.length} payloads queued.\n`);

  console.log("🔴  [Red Team] Executing attacks…");
  state.attackResults = await runAllAttacks(payloads);
  console.log(`    ✓ ${state.attackResults.length} attacks completed.\n`);

  // ── Stage 2: Blue Team — Analyse ────────────────────────────────────────────
  console.log("🔵  [Blue Team] Analysing results…");
  state.vulnReports = analyseResults(state.attackResults);
  const confirmed = state.vulnReports.filter((r) => r.confirmed);
  console.log(`    ✓ ${confirmed.length} / ${state.vulnReports.length} vulnerabilities confirmed.\n`);

  for (const r of confirmed) {
    console.log(`    ⚠  [${r.severity}] ${r.vulnClass} — ${r.payloadId}`);
    console.log(`       ${r.suggestedFix}`);
  }
  console.log();

  // ── Stage 3: Blue Team — Patch ──────────────────────────────────────────────
  console.log("🔵  [Blue Team] Generating patches…");
  state.patches = generatePatches(state.vulnReports);
  console.log(`    ✓ ${state.patches.length} patch(es) generated.\n`);

  // ── Finalise ────────────────────────────────────────────────────────────────
  state.completedAt = new Date().toISOString();
  state.summary     = buildSummary(state);

  // ── Persist logs ────────────────────────────────────────────────────────────
  const logsDir = path.resolve("logs");
  await mkdir(logsDir, { recursive: true });

  const summaryPath = path.join(logsDir, `${runId}-summary.json`);
  await writeFile(summaryPath, JSON.stringify(state, null, 2), "utf-8");
  console.log(`📄  Report written → ${summaryPath}`);

  if (state.patches.length > 0) {
    const diffPath = path.join(logsDir, `${runId}-patches.diff`);
    const diffContent = state.patches.map((p) => `# ${p.payloadId}\n${p.diff}`).join("\n\n");
    await writeFile(diffPath, diffContent, "utf-8");
    console.log(`🩹  Patches written → ${diffPath}`);
  }

  console.log(`\n${"─".repeat(60)}`);
  console.log(`✅  Run complete. ${state.summary.confirmed} confirmed finding(s).`);
  console.log(`${"─".repeat(60)}\n`);

  return state;
}

// ── Entrypoint (only runs when executed directly, not when imported) ──────────
// Normalise both URLs to bare filenames before comparing so the check works
// under tsx (file:// URLs) and after tsc compilation (plain paths) on both
// Windows and POSIX.
function _basename(p: string): string {
  return p.replace(/\\/g, "/").split("/").pop()?.replace(/\.(js|ts)$/, "") ?? "";
}
const _self = _basename(import.meta.url);
const _argv = _basename(process.argv[1] ?? "");

if (_self === _argv) {
  await runFuzzer();
}
