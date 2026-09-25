/**
 * Red Team — Attack Runner
 *
 * Fires each AttackPayload against the live target API and captures the
 * raw HTTP response.  Returns an array of AttackResult objects consumed
 * by the Blue Team analyser.
 */

import type { AttackPayload } from "./payloads.js";

export interface AttackResult {
  payload: AttackPayload;
  statusCode: number;
  body: unknown;
  durationMs: number;
  /**
   * For MASS_ASSIGNMENT payloads with `verifyLoginAs`: the HTTP status code
   * returned when the registered user attempts to access /admin/users.
   * 200 = privilege escalation confirmed; 401/403 = blocked.
   */
  adminProbeStatus?: number;
  /** Populated by the orchestrator / Blue Team after analysis */
  vulnerabilityConfirmed?: boolean;
  notes?: string;
}

const BASE_URL = process.env["TARGET_URL"] ?? "http://127.0.0.1:3001";

/**
 * Executes a single attack payload and returns the result.
 * The runner accepts an optional bearer token for authenticated attacks.
 */
export async function runAttack(
  payload: AttackPayload,
  bearerToken?: string
): Promise<AttackResult> {
  const url = `${BASE_URL}${payload.path}`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...payload.headers,
  };

  if (bearerToken) {
    headers["Authorization"] = `Bearer ${bearerToken}`;
  }

  const init: RequestInit = {
    method: payload.method,
    headers,
    ...(payload.body !== undefined && { body: JSON.stringify(payload.body) }),
  };

  const start = Date.now();
  const response = await fetch(url, init);
  const durationMs = Date.now() - start;

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = await response.text();
  }

  const result: AttackResult = {
    payload,
    statusCode: response.status,
    body,
    durationMs,
  };

  // ── Post-registration privilege probe ──────────────────────────────────────
  // If the payload registered a user and we want to verify privilege escalation,
  // log in as that user and hit /admin/users.  A 200 confirms isAdmin was stored.
  if (payload.verifyLoginAs && response.status === 201) {
    try {
      const loginRes = await fetch(`${BASE_URL}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload.verifyLoginAs),
      });
      const loginBody = (await loginRes.json()) as { token?: string };
      if (loginBody.token) {
        const probeRes = await fetch(`${BASE_URL}/admin/users`, {
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${loginBody.token}`,
          },
        });
        result.adminProbeStatus = probeRes.status;
      }
    } catch {
      // probe failed — treat as blocked
    }
  }

  return result;
}

/**
 * Runs the full payload suite in sequence, acquiring an authenticated token
 * first so protected-route payloads can be exercised.
 */
export async function runAllAttacks(payloads: AttackPayload[]): Promise<AttackResult[]> {
  // Obtain a token for the non-admin "alice" account
  let aliceToken: string | undefined;
  try {
    const loginRes = await fetch(`${BASE_URL}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "alice", password: "password123" }),
    });
    const loginBody = (await loginRes.json()) as { token?: string };
    aliceToken = loginBody.token;
  } catch (err) {
    console.error("[Red Team] Could not obtain alice token:", err);
  }

  const results: AttackResult[] = [];
  for (const payload of payloads) {
    console.log(`[Red Team] Firing ${payload.id} → ${payload.method} ${payload.path}`);
    // AUTH_BYPASS payloads must be sent WITHOUT a token — that is the entire
    // point of the test.  All other payloads run authenticated as alice.
    const token = payload.vulnClass === "AUTH_BYPASS" ? undefined : aliceToken;
    const result = await runAttack(payload, token);
    results.push(result);
  }
  return results;
}
