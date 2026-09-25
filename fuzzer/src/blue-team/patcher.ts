/**
 * Blue Team — Patch Generator
 *
 * Accepts confirmed VulnReports and emits concrete code-level patches as
 * unified diffs (strings) that can be applied directly to the target-api
 * source files.  Each patch targets the specific line(s) responsible for
 * the vulnerability.
 */

import type { VulnReport } from "./analyser.js";

export interface Patch {
  payloadId: string;
  vulnClass: string;
  targetFile: string;
  diff: string;
}

// ── Per-class patch templates ─────────────────────────────────────────────────

const PATCHES: Record<string, Patch> = {
  IDOR: {
    payloadId: "IDOR",
    vulnClass: "IDOR",
    targetFile: "target-api/src/routes/index.ts",
    diff: `
--- a/target-api/src/routes/index.ts
+++ b/target-api/src/routes/index.ts
@@ GET /notes/:id handler @@
-    if (!note) return reply.code(404).send({ error: "Not found" });
-    return reply.send(note); // any authenticated user gets any note
+    if (!note) return reply.code(404).send({ error: "Not found" });
+    // PATCH: Ownership check to prevent IDOR
+    const currentUser = req.user as { id: number };
+    if (note.ownerId !== currentUser.id) {
+      return reply.code(403).send({ error: "Forbidden" });
+    }
+    return reply.send(note);
`.trim(),
  },

  MASS_ASSIGNMENT: {
    payloadId: "MASS-ASSIGN",
    vulnClass: "MASS_ASSIGNMENT",
    targetFile: "target-api/src/routes/index.ts",
    diff: `
--- a/target-api/src/routes/index.ts
+++ b/target-api/src/routes/index.ts
@@ POST /register handler @@
-    const { username, password, isAdmin } = req.body as {
-      username: string;
-      password: string;
-      isAdmin?: boolean;
-    };
-    const [user] = await db
-      .insert(users)
-      .values({ username, password, isAdmin: isAdmin ?? false, apiKey: ... })
+    // PATCH: Allowlist — isAdmin is NEVER accepted from the request body
+    const { username, password } = req.body as {
+      username: string;
+      password: string;
+    };
+    const [user] = await db
+      .insert(users)
+      .values({ username, password, isAdmin: false, apiKey: ... })
`.trim(),
  },

  AUTH_BYPASS: {
    payloadId: "AUTH-BYPASS",
    vulnClass: "AUTH_BYPASS",
    targetFile: "target-api/src/routes/index.ts",
    diff: `
--- a/target-api/src/routes/index.ts
+++ b/target-api/src/routes/index.ts
@@ GET /users handler @@
-  // VULN-02 + VULN-03: no auth, returns all columns including apiKey
-  app.get("/users", async (_req, reply) => {
+  // PATCH: Require authentication and project safe columns only
+  app.get("/users", { onRequest: [app.authenticate] }, async (_req, reply) => {
`.trim(),
  },

  PRICE_MANIPULATION: {
    payloadId: "PRICE-MANIP",
    vulnClass: "PRICE_MANIPULATION",
    targetFile: "target-api/src/routes/index.ts",
    diff: `
--- a/target-api/src/routes/index.ts
+++ b/target-api/src/routes/index.ts
@@ POST /orders handler @@
-    const { product, price } = req.body as { product: string; price: number };
+    // PATCH: Ignore client-supplied price; look it up from a server-side catalogue
+    const { product } = req.body as { product: string };
+    const CATALOGUE: Record<string, number> = { Widget: 9.99, Gadget: 49.99 };
+    const price = CATALOGUE[product] ?? 0;
+    if (price === 0) return reply.code(400).send({ error: "Unknown product" });
`.trim(),
  },

  INFO_DISCLOSURE: {
    payloadId: "INFO-DISC",
    vulnClass: "INFO_DISCLOSURE",
    targetFile: "target-api/src/routes/index.ts",
    diff: `
--- a/target-api/src/routes/index.ts
+++ b/target-api/src/routes/index.ts
@@ GET /users handler @@
-    const allUsers = await db.select().from(users);
+    // PATCH: Project safe columns only — never expose password or apiKey
+    const allUsers = await db.select({
+      id:       users.id,
+      username: users.username,
+      isAdmin:  users.isAdmin,
+    }).from(users);
`.trim(),
  },
};

// ── Generator ─────────────────────────────────────────────────────────────────
export function generatePatches(reports: VulnReport[]): Patch[] {
  const patches: Patch[] = [];
  const seen = new Set<string>();

  for (const report of reports) {
    if (!report.confirmed) continue;
    const patch = PATCHES[report.vulnClass];
    if (patch && !seen.has(report.vulnClass)) {
      seen.add(report.vulnClass);
      patches.push({ ...patch, payloadId: report.payloadId });
    }
  }

  return patches;
}
