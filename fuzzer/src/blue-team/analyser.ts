/**
 * Blue Team — Vulnerability Analyser
 *
 * Inspects raw AttackResult objects and applies heuristic rules to determine
 * whether a vulnerability was confirmed.  Produces a structured VulnReport
 * that the patch generator consumes.
 */

import type { AttackResult } from "../red-team/runner.js";
import type { VulnClass } from "../red-team/payloads.js";

export interface VulnReport {
  payloadId: string;
  vulnClass: VulnClass;
  confirmed: boolean;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  description: string;
  evidence: string;
  suggestedFix: string;
}

// ── Severity map ──────────────────────────────────────────────────────────────
const SEVERITY_MAP: Record<VulnClass, VulnReport["severity"]> = {
  IDOR:               "HIGH",
  MASS_ASSIGNMENT:    "CRITICAL",
  AUTH_BYPASS:        "CRITICAL",
  PRICE_MANIPULATION: "HIGH",
  INFO_DISCLOSURE:    "MEDIUM",
};

// ── Detection heuristics ──────────────────────────────────────────────────────

function detectIdor(result: AttackResult): boolean {
  // IDOR confirmed only when a note is returned that alice does NOT own.
  // alice (test user, id=1) legitimately owns note 1 — a 200 there is correct.
  if (result.statusCode !== 200) return false;
  if (typeof result.body !== "object" || result.body === null) return false;
  if (!("ownerId" in result.body)) return false;
  const ownerId = (result.body as Record<string, unknown>)["ownerId"];
  return typeof ownerId === "number" && ownerId !== 1;
}

function detectMassAssignment(result: AttackResult): boolean {
  // Confirmed when:
  //   (a) the response body explicitly echoes isAdmin:true (pre-patch behaviour), OR
  //   (b) the post-registration admin probe returned 200 (the registered user
  //       gained admin access, proving isAdmin was stored in the DB).
  if (result.statusCode !== 201) return false;
  const body = result.body as Record<string, unknown>;
  if (body["isAdmin"] === true) return true;
  return result.adminProbeStatus === 200;
}

function detectAuthBypass(result: AttackResult): boolean {
  // Confirmed when an unauthenticated probe (no token) receives 200.
  // The runner fires AUTH_BYPASS payloads without a bearer token.
  return result.statusCode === 200;
}

function detectPriceManipulation(result: AttackResult): boolean {
  if (result.statusCode !== 201) return false;
  const body = result.body as Record<string, unknown>;
  const price = body["price"];
  return typeof price === "number" && price <= 0;
}

function detectInfoDisclosure(result: AttackResult): boolean {
  // Confirmed only when raw credential fields appear in the response body.
  if (result.statusCode !== 200) return false;
  const raw = JSON.stringify(result.body);
  return raw.includes("apiKey") || raw.includes('"password"');
}

// ── Suggested fixes ───────────────────────────────────────────────────────────
const FIX_HINTS: Record<VulnClass, string> = {
  IDOR: "Add ownership check: verify `note.ownerId === req.user.id` before returning the resource.",
  MASS_ASSIGNMENT: "Strip `isAdmin` from the request body before inserting into the database. Use an allowlist for accepted fields.",
  AUTH_BYPASS: "Add `{ onRequest: [app.authenticate] }` to all sensitive routes.",
  PRICE_MANIPULATION: "Override the `price` field server-side from a trusted product catalogue; never trust client-supplied prices.",
  INFO_DISCLOSURE: "Use a projection/DTO that explicitly selects only safe columns (exclude `password`, `apiKey`).",
};

// ── Main analyser ─────────────────────────────────────────────────────────────
export function analyseResults(results: AttackResult[]): VulnReport[] {
  return results.map((result) => {
    const { vulnClass } = result.payload;
    let confirmed = false;

    switch (vulnClass) {
      case "IDOR":               confirmed = detectIdor(result);              break;
      case "MASS_ASSIGNMENT":    confirmed = detectMassAssignment(result);    break;
      case "AUTH_BYPASS":        confirmed = detectAuthBypass(result);        break;
      case "PRICE_MANIPULATION": confirmed = detectPriceManipulation(result); break;
      case "INFO_DISCLOSURE":    confirmed = detectInfoDisclosure(result);    break;
    }

    return {
      payloadId:    result.payload.id,
      vulnClass,
      confirmed,
      severity:     SEVERITY_MAP[vulnClass],
      description:  result.payload.description,
      evidence:     `HTTP ${result.statusCode} — ${JSON.stringify(result.body).slice(0, 200)}`,
      suggestedFix: confirmed ? FIX_HINTS[vulnClass] : "No fix required — test did not confirm vulnerability.",
    };
  });
}
