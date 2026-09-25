import type { FastifyInstance } from "fastify";
import { db } from "../db/client.js";
import { users, notes, orders } from "../db/schema.js";
import { eq } from "drizzle-orm";

export async function routes(app: FastifyInstance): Promise<void> {
  // ── Auth ──────────────────────────────────────────────────────────────────

  // VULN: Mass Assignment — accepts isAdmin directly from request body
  app.post("/register", async (req, reply) => {
    // [PATCHED] Allowlist — isAdmin stripped from request body
    const { username, password } = req.body as {
      username: string;
      password: string;
    };
    const [user] = await db
      .insert(users)
      .values({
        username,
        password,
        isAdmin: false,
        apiKey: `key-${Math.random()}`,
      })
      .returning();
    return reply.code(201).send({ id: user?.id, username: user?.username });
  });

  // VULN: Plain-text comparison
  app.post("/login", async (req, reply) => {
    const { username, password } = req.body as { username: string; password: string };
    const [user] = await db.select().from(users).where(eq(users.username, username));
    if (!user || user.password !== password) {
      return reply.code(401).send({ error: "Invalid credentials" });
    }
    const token = await reply.jwtSign({ id: user.id, username: user.username, isAdmin: user.isAdmin });
    return { token };
  });

  // ── Users ─────────────────────────────────────────────────────────────────

  // VULN: Authentication bypass & sensitive data exposure (selects all columns including password and apiKey)
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

  // VULN: IDOR — fetches by note ID without verifying ownerId matches req.user.id
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

  // VULN: Price Manipulation — client controls price directly
  app.post("/orders", { onRequest: [app.authenticate] }, async (req, reply) => {
    // [PATCHED] Server-side price lookup — client price is ignored
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

  app.get("/admin/users", { onRequest: [app.authenticate] }, async (req, reply) => {
    const user = req.user as { isAdmin: boolean };
    if (!user.isAdmin) return reply.code(403).send({ error: "Forbidden" });
    // [PATCHED] Project safe columns only — never expose password or apiKey
    const allUsers = await db.select({
      id:       users.id,
      username: users.username,
      isAdmin:  users.isAdmin,
    }).from(users);
    return reply.send(allUsers);
  });
}