# Adversarial API Security Fuzzer

An AI-powered adversarial fuzzing framework that pits an automated **Red Team** (attack agent) against a **Blue Team** (analysis + patch agent) to discover and remediate REST API vulnerabilities.

## Architecture

```
adversarial-api-security-fuzzer/
├── target-api/              # Intentionally vulnerable Fastify + Drizzle REST API
│   └── src/
│       ├── db/
│       │   ├── schema.ts    # Drizzle schema (VULN-01 … VULN-05 annotated)
│       │   └── client.ts    # SQLite in-memory DB + seed data
│       ├── routes/
│       │   └── index.ts     # Vulnerable route handlers
│       └── server.ts        # Fastify server entry-point
│
├── fuzzer/                  # Core fuzzing engine
│   └── src/
│       ├── red-team/
│       │   ├── payloads.ts  # Adversarial payload generators
│       │   └── runner.ts    # HTTP attack executor
│       ├── blue-team/
│       │   ├── analyser.ts  # Heuristic vulnerability detector
│       │   └── patcher.ts   # Unified-diff patch generator
│       └── orchestrator/
│           └── index.ts     # Pipeline: Red → Blue → Logs
│
├── logs/                    # Run artefacts (JSON summaries + .diff patches)
├── package.json
├── tsconfig.json
└── .env.example
```

## Vulnerability Map (target-api)

| ID | Route | Class | Description |
|----|-------|-------|-------------|
| VULN-01 | `POST /login` | Auth | Plain-text password storage and comparison |
| VULN-02 | `GET /users` | Auth Bypass | Unauthenticated endpoint exposes all users |
| VULN-03 | `GET /users` | Info Disclosure | `apiKey` + `password` fields leak in response |
| VULN-04 | `GET /notes/:id` | IDOR | No ownership check — any user reads any note |
| VULN-05 | `POST /orders` | Business Logic | Price accepted from client body, never validated |
| VULN-06 | `GET /admin/users` | Privilege Escalation | isAdmin JWT claim forged via VULN-07 |
| VULN-07 | `POST /register` | Mass Assignment | `isAdmin` accepted from request body |

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Copy env file
cp .env.example .env

# 3. Start the vulnerable target API  (terminal 1)
npm run target

# 4. Run the fuzzer  (terminal 2)
npm run fuzzer
```

Results are written to `logs/<run-id>-summary.json` and `logs/<run-id>-patches.diff`.

## Scripts

| Command | Description |
|---------|-------------|
| `npm run target` | Start the vulnerable target API on port 3001 |
| `npm run fuzzer` | Run one full Red→Blue fuzzing cycle |
| `npm run dev` | Start both concurrently |
| `npm run build` | Compile TypeScript to `dist/` |
| `npm test` | Run Vitest test suite |
