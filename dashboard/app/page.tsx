"use client";

import { useState, useCallback } from "react";

// ── Types ─────────────────────────────────────────────────────────────────────

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

interface VulnReport {
  payloadId:    string;
  vulnClass:    string;
  confirmed:    boolean;
  severity:     Severity;
  description:  string;
  evidence:     string;
  suggestedFix: string;
}

interface ScanSummary {
  totalAttacks: number;
  confirmed:    number;
  bySeverity:   Record<string, number>;
}

interface ScanResult {
  runId:       string;
  startedAt:   string;
  completedAt: string;
  summary:     ScanSummary;
  vulnReports: VulnReport[];
  patches:     { payloadId: string; vulnClass: string; targetFile: string }[];
}

interface LogsResult {
  summaryFile: string | null;
  diffFile:    string | null;
  summary:     ScanResult | null;
  diff:        string | null;
}

interface PatchResult {
  applied:      string[];
  skipped:      string[];
  linesChanged: number;
  diff:         string;
}

type Status = "idle" | "loading" | "success" | "error";

// ── Severity badge ────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: "bg-red-600   text-white   border-red-500",
  HIGH:     "bg-orange-500 text-white  border-orange-400",
  MEDIUM:   "bg-yellow-500 text-black  border-yellow-400",
  LOW:      "bg-blue-600  text-white   border-blue-500",
  INFO:     "bg-gray-600  text-gray-100 border-gray-500",
};

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold border ${SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.INFO}`}>
      {severity}
    </span>
  );
}

// ── Diff viewer ───────────────────────────────────────────────────────────────

function DiffViewer({ diff }: { diff: string }) {
  return (
    <pre className="diff-viewer overflow-auto text-xs font-mono bg-gray-900 rounded-lg p-4 border border-gray-700 max-h-96 leading-5">
      {diff.split("\n").map((line, i) => {
        const cls = line.startsWith("+")
          ? "text-green-400"
          : line.startsWith("-")
          ? "text-red-400"
          : line.startsWith("@") || line.startsWith("---") || line.startsWith("+++")
          ? "text-blue-400"
          : "text-gray-400";
        return (
          <span key={i} className={`block ${cls}`}>
            {line || " "}
          </span>
        );
      })}
    </pre>
  );
}

// ── Summary cards ─────────────────────────────────────────────────────────────

function SummaryCards({ summary }: { summary: ScanSummary }) {
  const cards = [
    { label: "Total Attacks",     value: summary.totalAttacks,           color: "text-blue-400"   },
    { label: "Confirmed Vulns",   value: summary.confirmed,              color: "text-red-400"    },
    { label: "Critical",          value: summary.bySeverity["CRITICAL"] ?? 0, color: "text-red-500"  },
    { label: "High",              value: summary.bySeverity["HIGH"]     ?? 0, color: "text-orange-400" },
  ];
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
      {cards.map((c) => (
        <div key={c.label} className="bg-gray-800 rounded-lg p-4 border border-gray-700">
          <p className="text-gray-400 text-xs uppercase tracking-wider mb-1">{c.label}</p>
          <p className={`text-3xl font-bold ${c.color}`}>{c.value}</p>
        </div>
      ))}
    </div>
  );
}

// ── Vuln report row ───────────────────────────────────────────────────────────

function VulnRow({ report }: { report: VulnReport }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={`rounded-lg border mb-2 overflow-hidden transition-colors ${report.confirmed ? "border-red-700 bg-red-950/30" : "border-gray-700 bg-gray-800/40"}`}>
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/5 transition-colors"
        onClick={() => setOpen((o) => !o)}
      >
        <SeverityBadge severity={report.severity} />
        <span className="font-mono text-sm font-semibold flex-1 truncate">{report.vulnClass}</span>
        <span className="text-gray-400 text-xs font-mono">{report.payloadId}</span>
        {report.confirmed && (
          <span className="ml-2 px-2 py-0.5 bg-red-700 text-white text-xs rounded-full font-bold shrink-0">CONFIRMED</span>
        )}
        <svg className={`w-4 h-4 text-gray-500 shrink-0 transition-transform ${open ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-2 border-t border-gray-700 pt-3">
          <p className="text-gray-300 text-sm">{report.description}</p>
          <div className="bg-gray-900 rounded p-3 border border-gray-700">
            <p className="text-gray-500 text-xs uppercase tracking-wider mb-1">Evidence</p>
            <p className="font-mono text-xs text-yellow-300 break-all">{report.evidence}</p>
          </div>
          {report.confirmed && (
            <div className="bg-blue-950/40 rounded p-3 border border-blue-700">
              <p className="text-gray-500 text-xs uppercase tracking-wider mb-1">Suggested Fix</p>
              <p className="text-blue-200 text-sm">{report.suggestedFix}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:3001");

  const [scanStatus,  setScanStatus]  = useState<Status>("idle");
  const [logsStatus,  setLogsStatus]  = useState<Status>("idle");
  const [patchStatus, setPatchStatus] = useState<Status>("idle");

  const [scanResult,  setScanResult]  = useState<ScanResult  | null>(null);
  const [logsResult,  setLogsResult]  = useState<LogsResult  | null>(null);
  const [patchResult, setPatchResult] = useState<PatchResult | null>(null);

  const [error, setError] = useState<string | null>(null);

  // The results panel shows either live scan data or fetched log data
  const activeResult: ScanResult | null =
    scanResult ?? logsResult?.summary ?? null;

  // ── Handlers ────────────────────────────────────────────────────────────────

  const handleScan = useCallback(async () => {
    setScanStatus("loading");
    setScanResult(null);
    setError(null);
    try {
      const res = await fetch("/api/scan", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ targetUrl }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      const data = (await res.json()) as ScanResult;
      setScanResult(data);
      setScanStatus("success");
    } catch (e) {
      setError(String(e));
      setScanStatus("error");
    }
  }, [targetUrl]);

  const handleFetchLogs = useCallback(async () => {
    setLogsStatus("loading");
    setLogsResult(null);
    setError(null);
    try {
      const res = await fetch("/api/logs");
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      const data = (await res.json()) as LogsResult;
      setLogsResult(data);
      setLogsStatus("success");
    } catch (e) {
      setError(String(e));
      setLogsStatus("error");
    }
  }, []);

  const handlePatch = useCallback(async () => {
    setPatchStatus("loading");
    setPatchResult(null);
    setError(null);
    try {
      const res = await fetch("/api/patch", {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({}),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
      const data = (await res.json()) as PatchResult;
      setPatchResult(data);
      setPatchStatus("success");
    } catch (e) {
      setError(String(e));
      setPatchStatus("error");
    }
  }, []);

  // ── Render ───────────────────────────────────────────────────────────────────

  const confirmedReports = activeResult?.vulnReports.filter((r) => r.confirmed) ?? [];
  const cleanReports     = activeResult?.vulnReports.filter((r) => !r.confirmed) ?? [];

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* ── Header ── */}
      <header className="border-b border-gray-800 bg-gray-900/80 backdrop-blur sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center gap-4">
          <div className="flex items-center gap-3">
            <span className="text-2xl">🛡️</span>
            <div>
              <h1 className="font-bold text-lg leading-none">Adversarial API Security Fuzzer</h1>
              <p className="text-gray-500 text-xs mt-0.5">Red Team · Blue Team · Auto-Patch</p>
            </div>
          </div>
          <div className="ml-auto flex items-center gap-2 text-xs text-gray-500">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse inline-block" />
            UI Server :4000
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-8">

        {/* ── Target & Controls ── */}
        <section className="bg-gray-900 rounded-2xl border border-gray-800 p-6">
          <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-widest mb-4">
            🎯 Target Configuration
          </h2>
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="flex-1">
              <label htmlFor="targetUrl" className="block text-xs text-gray-500 mb-1">
                Target API URL
              </label>
              <input
                id="targetUrl"
                type="url"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="http://127.0.0.1:3001"
                className="w-full bg-gray-800 border border-gray-600 rounded-lg px-4 py-2.5 text-sm font-mono text-gray-100 placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent transition"
              />
            </div>
            <div className="flex items-end gap-2">
              <button
                onClick={handleScan}
                disabled={scanStatus === "loading"}
                className="px-6 py-2.5 bg-red-600 hover:bg-red-500 disabled:bg-red-800 disabled:cursor-not-allowed text-white font-bold rounded-lg text-sm transition flex items-center gap-2 shadow-lg shadow-red-900/40"
              >
                {scanStatus === "loading" ? (
                  <>
                    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                    </svg>
                    Scanning…
                  </>
                ) : (
                  <>🔴 Launch Fuzzer</>
                )}
              </button>
              <button
                onClick={handleFetchLogs}
                disabled={logsStatus === "loading"}
                className="px-4 py-2.5 bg-gray-700 hover:bg-gray-600 disabled:opacity-50 text-gray-200 font-medium rounded-lg text-sm transition"
              >
                {logsStatus === "loading" ? "Loading…" : "📂 Load Logs"}
              </button>
            </div>
          </div>
        </section>

        {/* ── Error banner ── */}
        {error && (
          <div className="bg-red-950 border border-red-700 rounded-xl p-4 text-red-300 text-sm font-mono">
            <span className="font-bold text-red-400">Error: </span>{error}
          </div>
        )}

        {/* ── Results Panel ── */}
        {activeResult && (
          <section className="space-y-4">
            {/* Meta bar */}
            <div className="flex flex-wrap items-center gap-4 text-xs text-gray-500 font-mono">
              <span>Run: <span className="text-gray-300">{activeResult.runId}</span></span>
              <span>Started: <span className="text-gray-300">{new Date(activeResult.startedAt).toLocaleTimeString()}</span></span>
              {activeResult.completedAt && (
                <span>Completed: <span className="text-gray-300">{new Date(activeResult.completedAt).toLocaleTimeString()}</span></span>
              )}
            </div>

            {/* Summary cards */}
            <SummaryCards summary={activeResult.summary} />

            {/* Vuln reports — confirmed first */}
            <div className="bg-gray-900 rounded-2xl border border-gray-800 p-6">
              <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-widest mb-4">
                ⚠️ Vulnerability Reports
                {activeResult.summary.confirmed === 0 && (
                  <span className="ml-3 text-green-400 normal-case font-normal">— All Clear ✅</span>
                )}
              </h2>

              {confirmedReports.length > 0 && (
                <div className="mb-4">
                  <p className="text-xs text-red-400 font-semibold uppercase tracking-wider mb-2">
                    🚨 Confirmed ({confirmedReports.length})
                  </p>
                  {confirmedReports.map((r) => <VulnRow key={r.payloadId} report={r} />)}
                </div>
              )}

              {cleanReports.length > 0 && (
                <div>
                  <p className="text-xs text-gray-500 font-semibold uppercase tracking-wider mb-2">
                    ✅ Not Exploitable ({cleanReports.length})
                  </p>
                  {cleanReports.map((r) => <VulnRow key={r.payloadId} report={r} />)}
                </div>
              )}
            </div>
          </section>
        )}

        {/* ── Patch Panel ── */}
        {(activeResult?.summary.confirmed ?? 0) > 0 || logsResult?.diff ? (
          <section className="bg-gray-900 rounded-2xl border border-gray-800 p-6 space-y-4">
            <div className="flex items-center justify-between flex-wrap gap-3">
              <div>
                <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-widest">
                  🩹 Blue Team — AI Patch
                </h2>
                <p className="text-gray-500 text-xs mt-1">
                  Apply regex-based source mutations to remediate all confirmed findings.
                </p>
              </div>
              <button
                onClick={handlePatch}
                disabled={patchStatus === "loading"}
                className="px-6 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 disabled:cursor-not-allowed text-white font-bold rounded-lg text-sm transition flex items-center gap-2 shadow-lg shadow-blue-900/40"
              >
                {patchStatus === "loading" ? (
                  <>
                    <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
                    </svg>
                    Patching…
                  </>
                ) : patchStatus === "success" ? (
                  <>✅ Patch Applied</>
                ) : (
                  <>🔵 Review &amp; Apply AI Patch</>
                )}
              </button>
            </div>

            {/* Existing diff from logs */}
            {logsResult?.diff && !patchResult && (
              <div>
                <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">
                  Patch diff — {logsResult.diffFile}
                </p>
                <DiffViewer diff={logsResult.diff} />
              </div>
            )}

            {/* Patch result */}
            {patchResult && (
              <div className="space-y-3">
                <div className="flex flex-wrap gap-2">
                  {patchResult.applied.map((cls) => (
                    <span key={cls} className="px-3 py-1 bg-green-900 border border-green-600 text-green-300 text-xs rounded-full font-mono">
                      ✓ {cls}
                    </span>
                  ))}
                  {patchResult.skipped.map((cls) => (
                    <span key={cls} className="px-3 py-1 bg-gray-800 border border-gray-600 text-gray-400 text-xs rounded-full font-mono">
                      ⊘ {cls}
                    </span>
                  ))}
                </div>
                <p className="text-gray-400 text-xs">
                  {patchResult.applied.length} mutation(s) applied ·{" "}
                  {patchResult.linesChanged > 0 ? `+${patchResult.linesChanged}` : patchResult.linesChanged} lines
                </p>
                <DiffViewer diff={patchResult.diff} />
              </div>
            )}
          </section>
        ) : null}

      </main>

      {/* ── Footer ── */}
      <footer className="border-t border-gray-800 mt-16 py-6 text-center text-xs text-gray-600">
        Adversarial API Security Fuzzer · Red Team attacks · Blue Team patches · UI :3000 · API :4000
      </footer>
    </div>
  );
}
