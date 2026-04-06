"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { createScan, listScans, type ScanListItem } from "@/lib/api";

export default function HomePage() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [scanMode, setScanMode] = useState<"fast" | "deep">("fast");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [recentScans, setRecentScans] = useState<ScanListItem[]>([]);

  useEffect(() => {
    listScans()
      .then((data) => setRecentScans(data.scans || []))
      .catch(() => {});
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = target.trim();
    if (!trimmed) return;

    setLoading(true);
    setError("");

    try {
      const result = await createScan(trimmed, scanMode);
      router.push(`/scan/${result.scanId}`);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
    } finally {
      setLoading(false);
    }
  };

  const formatTime = (iso: string | null) => {
    if (!iso) return "";
    const d = new Date(iso);
    return d.toLocaleDateString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <>
      {/* Hero */}
      <section className="hero">
        <div className="hero-badge">
          <span className="dot" />
          No-Exploit Reconnaissance Platform
        </div>
        <h1>Automated Security Assessment</h1>
        <p>
          Deep reconnaissance, passive vulnerability scanning, and AI-powered
          PDF reporting — without active exploitation.
        </p>

        {/* Scan Form */}
        <div className="card" style={{ maxWidth: 620, margin: "0 auto" }}>
          <form className="scan-form" onSubmit={handleSubmit}>
            <input
              id="target-input"
              type="text"
              className="scan-input"
              placeholder="Enter target domain (e.g. example.com)"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              disabled={loading}
              autoFocus
              autoComplete="off"
              spellCheck={false}
            />
            <button
              id="scan-submit"
              type="submit"
              className="btn btn-primary"
              disabled={loading || !target.trim()}
            >
              {loading ? "Starting…" : "Start Scan"}
            </button>
          </form>
          {error && <div className="error-msg">{error}</div>}
          <div className="mode-toggle-row">
            <span className="mode-label">Scan Mode</span>
            <div className="mode-toggle">
              <button
                type="button"
                className={`mode-option ${scanMode === "fast" ? "active fast" : ""}`}
                onClick={() => setScanMode("fast")}
              >
                ⚡ Fast
              </button>
              <button
                type="button"
                className={`mode-option ${scanMode === "deep" ? "active deep" : ""}`}
                onClick={() => setScanMode("deep")}
              >
                🔬 In-Depth
              </button>
            </div>
            <span className="mode-hint">
              {scanMode === "fast"
                ? "Quick reconnaissance scan"
                : "Thorough deep analysis — takes longer"}
            </span>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="features">
        <div className="feature">
          <div className="feature-icon">🔍</div>
          <h3>Deep Recon</h3>
          <p>
            Subdomain discovery, DNS resolution, port scanning, and service
            fingerprinting across the full attack surface.
          </p>
        </div>
        <div className="feature">
          <div className="feature-icon">🛡️</div>
          <h3>Safe Scanning</h3>
          <p>
            Strictly no-exploit. All tools perform passive detection and
            validation only — never active exploitation.
          </p>
        </div>
        <div className="feature">
          <div className="feature-icon">📄</div>
          <h3>AI Reports</h3>
          <p>
            Groq-powered AI generates narrative reports with realistic risk
            assessment and actionable remediation priorities.
          </p>
        </div>
      </section>

      {/* Recent Scans */}
      {recentScans.length > 0 && (
        <section style={{ marginTop: "3rem" }}>
          <div className="card">
            <div className="card-header">
              <div className="card-title">Recent Scans</div>
              <div className="card-subtitle">
                Click a scan to view its progress or download the report
              </div>
            </div>
            <div className="history-list">
              {recentScans.map((scan) => (
                <a
                  key={scan.scanId}
                  href={`/scan/${scan.scanId}`}
                  className="history-item"
                >
                  <span className="history-target">{scan.target}</span>
                  <span className={`scan-mode-badge ${scan.scanMode || "fast"}`}>
                    {(scan.scanMode || "fast") === "deep" ? "\ud83d\udd2c Deep" : "\u26a1 Fast"}
                  </span>
                  <span className={`history-state ${scan.state}`}>
                    {scan.state}
                  </span>
                  <span className="history-time">
                    {formatTime(scan.createdAt)}
                  </span>
                </a>
              ))}
            </div>
          </div>
        </section>
      )}
    </>
  );
}
