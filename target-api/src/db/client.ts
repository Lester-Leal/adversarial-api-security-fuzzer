/**
 * Drizzle client — initialises a libsql in-memory database and applies the
 * schema so the target API is self-contained for fuzzer runs.
 *
 * Uses @libsql/client (pure-JS, no native build required) with the
 * drizzle-orm/libsql adapter.
 */

import { createClient } from "@libsql/client";
import { drizzle } from "drizzle-orm/libsql";
import * as schema from "./schema.js";

const libsql = createClient({ url: ":memory:" });
export const db = drizzle(libsql, { schema });

// ── DDL ───────────────────────────────────────────────────────────────────────
const DDL = `
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    username  TEXT    NOT NULL UNIQUE,
    password  TEXT    NOT NULL,
    is_admin  INTEGER NOT NULL DEFAULT 0,
    api_key   TEXT    NOT NULL
  );
  CREATE TABLE IF NOT EXISTS notes (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    title    TEXT    NOT NULL,
    body     TEXT    NOT NULL
  );
  CREATE TABLE IF NOT EXISTS orders (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    product TEXT    NOT NULL,
    price   REAL    NOT NULL,
    status  TEXT    NOT NULL DEFAULT 'pending'
  );
`;

// ── Seed data ─────────────────────────────────────────────────────────────────
// Two regular users and one admin.  Plain-text passwords are intentional
// (VULN-01) so the fuzzer can detect them.
export async function seedDatabase(): Promise<void> {
  // libsql executes one statement per call; split on semicolons
  for (const stmt of DDL.split(";").map((s) => s.trim()).filter(Boolean)) {
    await libsql.execute(stmt);
  }

  await db.insert(schema.users).values([
    { username: "alice", password: "password123", isAdmin: false, apiKey: "key-alice-secret-001" },
    { username: "bob",   password: "hunter2",     isAdmin: false, apiKey: "key-bob-secret-002"   },
    { username: "admin", password: "admin",        isAdmin: true,  apiKey: "key-admin-secret-000" },
  ]);

  await db.insert(schema.notes).values([
    { ownerId: 1, title: "Alice private note", body: "SSN: 123-45-6789" },
    { ownerId: 2, title: "Bob private note",   body: "Credit card: 4111111111111111" },
  ]);

  await db.insert(schema.orders).values([
    { userId: 1, product: "Widget", price: 9.99,  status: "pending" },
    { userId: 2, product: "Gadget", price: 49.99, status: "shipped" },
  ]);
}
