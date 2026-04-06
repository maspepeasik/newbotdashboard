"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useParams } from "next/navigation";
import {
  getScanStatus,
  getScanLogs,
  downloadReport,
  type ScanStatus,
  type LogEntry,
} from "@/lib/api";

const STAGE_LABELS: Record<string, string> = {
  Queued:       "Queued",
  Recon:        "Subdomain Discovery",
  Resolver:     "DNS Resolution",
  OriginIP:     "Origin IP Detection",
  PortScan:     "Port Scanning",
  ServiceScan:  "Service Detection",
  HTTPProbe:    "HTTP Probing",
  Fingerprint:  "Fingerprinting",
  WebDiscovery: "Web Discovery",
  VulnScan:     "Vulnerability Scan",
  TLSScan:      "TLS Analysis",
  Aggregation:  "Aggregation",
  AIAnalysis:   "AI Analysis",
  Report:       "Report Generation",
  Done:         "Complete",
};

function stageIcon(state: string): string {
  switch (state) {
    case "completed":
      return "✓";
    case "running":
      return "⟳";
    case "failed":
      return "✗";
    default:
      return "○";
  }
}

function riskColor(level: string | undefined): string {
  switch (level?.toLowerCase()) {
    case "critical":
      return "var(--accent-red)";
    case "high":
      return "var(--accent-amber)";
    case "medium":
      return "var(--accent-amber)";
    case "low":
      return "var(--accent-cyan)";
    default:
      return "var(--text-muted)";
  }
}

export default function ScanPage() {
  const params = useParams();
  const scanId = params.id as string;

  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [logCursor, setLogCursor] = useState(0);
  const [error, setError] = useState("");

  const logEndRef = useRef<HTMLDivElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const isTerminal = scan?.state === "completed" || scan?.state === "failed" || scan?.state === "cancelled";

  const fetchStatus = useCallback(async () => {
    try {
      const status = await getScanStatus(scanId);
      setScan(status);
      return status;
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load scan");
      return null;
    }
  }, [scanId]);

  const fetchLogs = useCallback(async () => {
    try {
      const data = await getScanLogs(scanId, logCursor);
      if (data.entries.length > 0) {
        setLogs((prev) => [...prev, ...data.entries]);
        setLogCursor(data.nextCursor);
      }
    } catch {
      // Logs may not be available yet
    }
  }, [scanId, logCursor]);

  // Initial load
  useEffect(() => {
    fetchStatus();
    fetchLogs();
  }, []);

  // Polling
  useEffect(() => {
    if (isTerminal) {
      if (pollRef.current) clearInterval(pollRef.current);
      return;
    }

    pollRef.current = setInterval(async () => {
      const status = await fetchStatus();
      await fetchLogs();

      if (
        status &&
        (status.state === "completed" ||
          status.state === "failed" ||
          status.state === "cancelled")
      ) {
        if (pollRef.current) clearInterval(pollRef.current);
      }
    }, 3000);

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [isTerminal, fetchStatus, fetchLogs]);

  // Auto-scroll logs
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  if (error && !scan) {
    return (
      <div className="scan-page">
        <div className="card">
          <div className="error-msg">{error}</div>
          <div className="actions-row" style={{ marginTop: "1rem" }}>
            <a href="/" className="btn btn-ghost">← Back to Home</a>
          </div>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="scan-page">
        <div className="card" style={{ textAlign: "center", padding: "3rem" }}>
          <div style={{ fontSize: "1.5rem", marginBottom: "0.5rem" }}>⟳</div>
          <div style={{ color: "var(--text-secondary)" }}>Loading scan details…</div>
        </div>
      </div>
    );
  }

  const progressClass = scan.state === "completed"
    ? "completed"
    : scan.state === "failed"
      ? "failed"
      : "";

  return (
    <div className="scan-page">
      {/* Target & Status */}
      <div className="card">
        <div className="target-badge">🎯 {scan.target}</div>
        {scan.scanMode && (
          <span className={`scan-mode-badge ${scan.scanMode}`}>
            {scan.scanMode === "deep" ? "🔬 In-Depth Scan" : "⚡ Fast Scan"}
          </span>
        )}

        {/* Progress Bar */}
        <div className="progress-section">
          <div className="progress-header">
            <span className="progress-label">
              {isTerminal
                ? scan.state === "completed"
                  ? "Scan Complete"
                  : "Scan Failed"
                : STAGE_LABELS[scan.currentStage] || scan.currentStage}
            </span>
            <span className="progress-value">{scan.progress}%</span>
          </div>
          <div className="progress-bar-track">
            <div
              className={`progress-bar-fill ${progressClass}`}
              style={{ width: `${scan.progress}%` }}
            />
          </div>
        </div>

        {/* Pipeline Stages */}
        <div className="stages-list" style={{ marginTop: "1.5rem" }}>
          {scan.stages.map((stage) => (
            <div
              key={stage.name}
              className={`stage-item ${stage.state}`}
            >
              <span className={`stage-icon ${stage.state}`}>
                {stageIcon(stage.state)}
              </span>
              <span className="stage-name">
                {STAGE_LABELS[stage.name] || stage.name}
              </span>
              {stage.completedAt && stage.startedAt && (
                <span className="stage-time">
                  {(
                    (new Date(stage.completedAt).getTime() -
                      new Date(stage.startedAt).getTime()) /
                    1000
                  ).toFixed(1)}s
                </span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Summary (when completed) */}
      {scan.state === "completed" && scan.summary && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">Scan Summary</div>
            <div className="card-subtitle">
              Assessment completed in {scan.summary.duration || "—"}
            </div>
          </div>
          <div className="risk-level-row">
            <div
              className="risk-level-value"
              style={{ color: riskColor(scan.summary.risk_level) }}
            >
              {scan.summary.risk_level || "—"}
            </div>
            <div className="risk-level-label">Risk Level</div>
          </div>
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-value">
                {scan.summary.total_findings ?? 0}
              </div>
              <div className="stat-label">Findings</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">
                {scan.summary.subdomains ?? 0}
              </div>
              <div className="stat-label">Subdomains</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">
                {scan.summary.open_ports ?? 0}
              </div>
              <div className="stat-label">Open Ports</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">
                {scan.summary.live_hosts ?? 0}
              </div>
              <div className="stat-label">Live Hosts</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">
                {scan.summary.discovered_urls ?? 0}
              </div>
              <div className="stat-label">URLs</div>
            </div>
          </div>
        </div>
      )}

      {/* Error Detail */}
      {scan.state === "failed" && scan.error && (
        <div className="card">
          <div className="error-msg">{scan.error}</div>
        </div>
      )}

      {/* Actions */}
      <div className="actions-row">
        <a href="/" className="btn btn-ghost">
          ← New Scan
        </a>
        {scan.pdfReady && (
          <button
            className="btn btn-success"
            onClick={() => downloadReport(scanId).catch((e) => alert(e.message))}
          >
            📄 Download PDF Report
          </button>
        )}
      </div>

      {/* Live Logs */}
      {logs.length > 0 && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">Scan Log</div>
            <div className="card-subtitle">
              {logs.length} entries · {isTerminal ? "Final" : "Live"}
            </div>
          </div>
          <div className="log-viewer">
            {logs.map((entry) => (
              <div key={entry.id} className="log-entry">
                <span className="log-stage">[{entry.stage}]</span>
                <span className="log-message">{entry.message}</span>
              </div>
            ))}
            <div ref={logEndRef} />
          </div>
        </div>
      )}
    </div>
  );
}
