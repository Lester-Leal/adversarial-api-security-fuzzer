# Adversarial API Security Fuzzer

An AI-powered adversarial fuzzing framework that pits an automated **Red Team** (attack agent) against a **Blue Team** (analysis + patch agent) to discover and remediate REST API vulnerabilities — with a full **Web UI dashboard** for interactive control.

---

## Architecture

```
adversarial-api-security-fuzzer/
│
├── target-api/                   # Intentionally vulnerable Fastify + Drizzle REST API
│   └── src/
│       ├── db/
│       │   ├── schema.ts         # Drizzle schema (VULN-01 … VULN-07 annotated)
│       │   └── client.ts         # libsql in-memory DB + seed data
│       ├── routes/
│       │   └── index.ts          # Vulnerable route handlers
│       └── server.ts             # Fastify server :3001
│
├── fuzzer/                       # Core fuzzing engine + UI API
│   └── src/
│       ├── red-team/
│       │   ├── payloads.ts       # Adversarial payload generators (IDOR, SQLi, etc.)
│       │   └── runner.ts         # HTTP attack executor + privilege-escalation probe
│       ├── blue-team/
│       │   ├── analyser.ts       # Heuristic vulnerability detector → VulnReport[]
│       │   └── patcher.ts        # Patch diff generator
│       └── orchestrator/
│           ├── index.ts          # Pipeline: Red → Blue → /logs  (npm run fuzzer)
│           ├── verify.ts         # Auto-patch + re-verify lifecycle (npm run verify)
│           └── ui-server.ts      # Fastify UI API server :4000   (npm run ui)
│
├── dashboard/                    # Next.js 14 + Tailwind web dashboard :3000
│   └── app/
│       ├── layout.tsx
│       ├── globals.css
│       └── page.tsx              # Interactive scan / patch / results UI
│
├── logs/                         # Run artefacts — *-summary.json + *-patches.diff
├── package.json
├── tsconfig.json
├── .env.example
└── .gitignore
```

---

## Vulnerability Map (target-api)

| ID | Route | Class | Description |
|----|-------|-------|-------------|
| VULN-01 | `POST /login` | Auth | Plain-text password storage and comparison |
| VULN-02 | `GET /users` | Auth Bypass | Unauthenticated endpoint exposes all users |
| VULN-03 | `GET /users` | Info Disclosure | `apiKey` + `password` fields leak in response |
| VULN-04 | `GET /notes/:id` | IDOR | No ownership check — any user reads any note |
| VULN-05 | `POST /orders` | Business Logic | Price accepted from client body, never validated |
| VULN-06 | `GET /admin/users` | Privilege Escalation | `isAdmin` JWT claim forged via VULN-07 |
| VULN-07 | `POST /register` | Mass Assignment | `isAdmin` accepted directly from request body |

---

## Quick Start — CLI

```bash
# 1. Install root dependencies
npm install

# 2. Copy env file
cp .env.example .env

# 3. Start the vulnerable target API  (terminal 1)
npm run target          # → http://127.0.0.1:3001

# 4. Run one full Red→Blue fuzzing cycle  (terminal 2)
npm run fuzzer          # writes logs/<run-id>-summary.json + patches.diff

# 5. (Optional) Auto-patch & re-verify  (terminal 2)
npm run verify          # applies Blue Team mutations, restarts target, re-scans
```

---

## Quick Start — Web UI

```bash
# Terminal 1 — vulnerable target
npm run target          # → http://127.0.0.1:3001

# Terminal 2 — Fuzzer UI API server
npm run ui              # → http://127.0.0.1:4000

# Terminal 3 — Next.js dashboard
npm run dashboard       # → http://localhost:3000
# (installs dashboard/node_modules on first run: cd dashboard && npm install)
```

Open **http://localhost:3000** in your browser.

---

## Dashboard Features

| Section | What it does |
|---------|-------------|
| 🎯 **Target Configuration** | Set the API URL and click **🔴 Launch Fuzzer** to run a live attack |
| 📂 **Load Logs** | Fetch the latest `summary.json` + `patches.diff` from `/logs` without re-scanning |
| ⚠️ **Vulnerability Reports** | Collapsible rows per finding — severity badge, evidence, suggested fix |
| 📊 **Summary Cards** | Total attacks · Confirmed vulns · Critical · High counts |
| 🩹 **Blue Team AI Patch** | Review the `.diff`, click **🔵 Review & Apply AI Patch** to mutate the source live |

---

## All npm Scripts

| Command | Port | Description |
|---------|------|-------------|
| `npm run target` | :3001 | Start the intentionally vulnerable Fastify target API |
| `npm run fuzzer` | — | Run one full Red Team → Blue Team scan cycle |
| `npm run verify` | — | Apply Blue Team patches, restart target, re-scan to confirm 0 findings |
| `npm run ui` | :4000 | Start the Fastify UI API server (consumed by the dashboard) |
| `npm run dashboard` | :3000 | Start the Next.js web dashboard |
| `npm run build` | — | Compile TypeScript to `dist/` |
| `npm run dev` | — | Start target + fuzzer concurrently |
| `npm test` | — | Run Vitest test suite |

---

## UI API Endpoints (port 4000)

| Method | Route | Description |
|--------|-------|-------------|
| `POST` | `/api/scan` | Run Red Team attacks. Body: `{ targetUrl?: string }` |
| `GET` | `/api/logs` | Return latest `summary.json` + `patches.diff` from `/logs` |
| `POST` | `/api/patch` | Apply Blue Team source mutations. Body: `{ diffPath?: string }` |

---

## Latest Scan Summary

> Run `npm run fuzzer` (or use the dashboard) to generate a fresh report.
> The result below reflects the most recent run in `/logs`.

```
Run ID      : run-2026-09-25T17-24-59-305Z
Started     : 2026-09-25T17:24:59 UTC
Completed   : 2026-09-25T17:24:59 UTC  (< 1 second)
Target      : http://127.0.0.1:3001

Payloads fired : 11
Confirmed      : 0  ✅  (all Blue Team patches already applied)
```

| Payload | Vuln Class | Severity | Status |
|---------|-----------|----------|--------|
| IDOR-NOTE-1 | IDOR | HIGH | ✅ Blocked (alice owns note 1) |
| IDOR-NOTE-2 | IDOR | HIGH | ✅ Blocked — 403 Forbidden |
| IDOR-NOTE-3…5 | IDOR | HIGH | ✅ Blocked — 404 Not Found |
| MASS-ASSIGN-ADMIN-01 | MASS_ASSIGNMENT | CRITICAL | ✅ Blocked — admin probe → 403 |
| AUTH-BYPASS-USER-LIST | AUTH_BYPASS | CRITICAL | ✅ Blocked — 401 Unauthorized |
| AUTH-BYPASS-ADMIN | AUTH_BYPASS | CRITICAL | ✅ Blocked — 401 Unauthorized |
| PRICE-MANIP-ZERO | PRICE_MANIPULATION | HIGH | ✅ Blocked — 400 Unknown product |
| PRICE-MANIP-NEGATIVE | PRICE_MANIPULATION | HIGH | ✅ Blocked — 400 Unknown product |
| INFO-DISC-USER-LIST | INFO_DISCLOSURE | MEDIUM | ✅ Blocked — no credentials in response |

---

## Logs & Artefacts

All fuzzer runs write two files to `/logs/` (gitignored):

```
logs/
├── run-<ISO>-summary.json   # Full FuzzState: attack results, vuln reports, patches
└── run-<ISO>-patches.diff   # Human-readable patch descriptions per confirmed finding
```

The `GET /api/logs` endpoint and the **📂 Load Logs** button in the dashboard surface these files directly.

---

## How the Three-Step Lifecycle Works

```
┌─────────────────────────────────────────────────────────────────┐
│  Step 1 — Red Team                                              │
│  payloads.ts generates 11 adversarial payloads across 5 classes │
│  runner.ts fires each against the live target API               │
│  Saves raw HTTP responses + adminProbeStatus per result         │
└────────────────────────┬────────────────────────────────────────┘
                         │ AttackResult[]
┌────────────────────────▼────────────────────────────────────────┐
│  Step 2 — Blue Team (Analyse)                                   │
│  analyser.ts applies heuristic rules to each result             │
│  Emits confirmed:true / false per VulnReport                    │
│  Writes *-summary.json to /logs                                 │
└────────────────────────┬────────────────────────────────────────┘
                         │ VulnReport[]
┌────────────────────────▼────────────────────────────────────────┐
│  Step 3 — Blue Team (Patch)                                     │
│  patcher.ts maps confirmed findings → patch descriptions        │
│  verify.ts applies whitespace-agnostic regex mutations to       │
│  target-api/src/routes/index.ts, then re-runs the full          │
│  pipeline to confirm 0 findings remain                          │
│  Writes *-patches.diff to /logs                                 │
└─────────────────────────────────────────────────────────────────┘
```
