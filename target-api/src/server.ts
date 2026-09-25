/**
 * Target API server entry-point.
 * Starts a Fastify server on PORT (default 3001) with JWT support and
 * seeds the in-memory SQLite database on startup.
 */

import Fastify from "fastify";
import fastifyJwt from "@fastify/jwt";
import sensible from "@fastify/sensible";
import { seedDatabase } from "./db/client.js";
import { routes } from "./routes/index.js";

const PORT = Number(process.env["PORT"] ?? 3001);
const JWT_SECRET = process.env["JWT_SECRET"] ?? "super-insecure-dev-secret";

// ── Type augmentation so req.authenticate is recognised ──────────────────────
declare module "fastify" {
  interface FastifyInstance {
    authenticate: (req: import("fastify").FastifyRequest, reply: import("fastify").FastifyReply) => Promise<void>;
  }
}

async function build(): Promise<ReturnType<typeof Fastify>> {
  const app = Fastify({ logger: { level: "info" } });

  await app.register(sensible);
  await app.register(fastifyJwt, { secret: JWT_SECRET });

  // Convenience decorator used as onRequest hook on protected routes
  app.decorate("authenticate", async function (req, reply) {
    try {
      await req.jwtVerify();
    } catch (err) {
      reply.send(err);
    }
  });

  await app.register(routes);
  return app;
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────
const app = await build();
await seedDatabase();

try {
  const address = await app.listen({ port: PORT, host: "127.0.0.1" });
  app.log.info(`🎯 Target API listening at ${address}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
