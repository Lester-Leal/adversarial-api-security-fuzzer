/**
 * Intentionally vulnerable routes for the target API.
 *
 * Vulnerability map:
 *   POST /login          — VULN-01 plain-text password compare, no rate-limit
 *   GET  /users          — VULN-02 unauthenticated admin list, leaks apiKey (VULN-03)
 *   GET  /notes/:id      — VULN-04 IDOR: no ownership check, any authenticated user
 *                          can read any note
 *   POST /orders         — VULN-05 price accepted from client body, no server-side
 *                          override
 *   GET  /admin/users    — VULN-06 "admin" check reads isAdmin from JWT body that
 *                          was set from the DB row populated at login — but the
 *                          /register route (below) lets anyone pass isAdmin:true
 *   POST /register       — VULN-07 mass-assignment: isAdmin accepted from request body
 */

import type { FastifyInstance } from "fastify";
import { db } from "../db/client.js";
import { users, notes, orders } from "../db/schema.js";
import { eq } from "drizzle-orm";

export async function routes(app: FastifyInstance): Promise<void> {
  // ── Auth ──────────────────────────────────────────────────────────────────

  // [PATCHED] Allowlist — isAdmin is NEVER accepted from the request body
  app.post("/register", async (req, reply) => {
    const { username, password } = req.body as {
      username: string;
      password: string;
    };
    const [user] = await db
      .insert(users)
      .values({ username, password, isAdmin: false, apiKey: `key-${Math.random()}` })
      .returning();
    return reply.code(201).send({ id: user?.id, username: user?.username });
  });

  // VULN-01: plain-text compare
  app.post("/login", async (req, reply) => {
    const { username, password } = req.body as { username: string; password: string };
    const [user] = await db.select().from(users).where(eq(users.username, username));
    if (!user || user.password !== password) {
      return reply.code(401).send({ error: "Invalid credentials" });
    }
    // JWT payload contains isAdmin — VULN-02 surface
    const token = await reply.jwtSign({ id: user.id, username: user.username, isAdmin: user.isAdmin });
    return { token };
  });

  // ── Users ─────────────────────────────────────────────────────────────────

  // [PATCHED] Require authentication on GET /users
  app.get("/users", { onRequest: [app.authenticate] }, async (_req, reply) => {
    // [PATCHED] Project safe columns only — never expose password or apiKey
    const allUsers = await db.select({
      id:       users.id,
      username: users.username,
      isAdmin:  users.isAdmin,
    }).from(users);
    return reply.send(allUsers);
  });

  // ── Notes ─────────────────────────────────────────────────────────────────

  // VULN-04: IDOR — fetches by id only, never checks req.user.id === note.ownerId
  app.get("/notes/:id", { onRequest: [app.authenticate] }, async (req, reply) => {
    const { id } = req.params as { id: string };
    const [note] = await db.select().from(notes).where(eq(notes.id, parseInt(id, 10)));
    if (!note) return reply.code(404).send({ error: "Not found" });
    // [PATCHED] Ownership check to prevent IDOR
    const currentUser = req.user as { id: number };
    if (note.ownerId !== currentUser.id) {
      return reply.code(403).send({ error: "Forbidden" });
    }
    return reply.send(note);
  });

  // ── Orders ────────────────────────────────────────────────────────────────

  // [PATCHED] Server-side price lookup — client price is ignored
  app.post("/orders", { onRequest: [app.authenticate] }, async (req, reply) => {
    const { product } = req.body as { product: string };
    const CATALOGUE: Record<string, number> = { Widget: 9.99, Gadget: 49.99 };
    const price = CATALOGUE[product] ?? 0;
    if (price === 0) return reply.code(400).send({ error: "Unknown product" });
    const user = req.user as { id: number };
    const [order] = await db
      .insert(orders)
      .values({ userId: user.id, product, price })
      .returning();
    return reply.code(201).send(order);
  });

  // ── Admin ─────────────────────────────────────────────────────────────────

  // VULN-06: relies on JWT claim isAdmin which can be forged via VULN-07
  app.get("/admin/users", { onRequest: [app.authenticate] }, async (req, reply) => {
    const user = req.user as { isAdmin: boolean };
    if (!user.isAdmin) return reply.code(403).send({ error: "Forbidden" });
    const allUsers = await db.select().from(users);
    return reply.send(allUsers);
  });
}
