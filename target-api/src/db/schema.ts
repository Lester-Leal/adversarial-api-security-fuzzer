/**
 * Drizzle schema for the intentionally vulnerable target API.
 *
 * INTENTIONAL VULNERABILITIES (for fuzzer to discover):
 *   [VULN-01] Passwords stored as plain-text strings (no hashing).
 *   [VULN-02] `isAdmin` flag lives on the user row and is trust-able by callers.
 *   [VULN-03] `apiKey` is a first-class column — leakable via SELECT *.
 *   [VULN-04] No `ownerId` ownership check at query layer → IDOR surface.
 *   [VULN-05] `price` accepted from client body without server-side override.
 */

import { sqliteTable, text, integer, real } from "drizzle-orm/sqlite-core";

// ── Users ────────────────────────────────────────────────────────────────────
export const users = sqliteTable("users", {
  id:       integer("id").primaryKey({ autoIncrement: true }),
  username: text("username").notNull().unique(),
  // VULN-01: plain-text password
  password: text("password").notNull(),
  // VULN-02: client-controllable privilege flag
  isAdmin:  integer("is_admin", { mode: "boolean" }).notNull().default(false),
  // VULN-03: secret leaks in SELECT *
  apiKey:   text("api_key").notNull(),
});

// ── Notes (private per-user resource) ────────────────────────────────────────
export const notes = sqliteTable("notes", {
  id:      integer("id").primaryKey({ autoIncrement: true }),
  // VULN-04: ownerId not validated at route layer → IDOR
  ownerId: integer("owner_id").notNull(),
  title:   text("title").notNull(),
  body:    text("body").notNull(),
});

// ── Orders ───────────────────────────────────────────────────────────────────
export const orders = sqliteTable("orders", {
  id:       integer("id").primaryKey({ autoIncrement: true }),
  userId:   integer("user_id").notNull(),
  product:  text("product").notNull(),
  // VULN-05: price is accepted from user input without server-side validation
  price:    real("price").notNull(),
  status:   text("status", { enum: ["pending", "shipped", "cancelled"] })
              .notNull()
              .default("pending"),
});

export type User  = typeof users.$inferSelect;
export type Note  = typeof notes.$inferSelect;
export type Order = typeof orders.$inferSelect;
