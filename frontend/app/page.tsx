"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { createScan, listScans, deleteScan, type ScanListItem } from "@/lib/api";

export default function HomePage() {
  const router = useRouter();
  const [target, setTarget] = useState("");
  const [scanMode, setScanMode] = useState<"fast" | "deep">("fast");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [recentScans, setRecentScans] = useState<ScanListItem[]>([]);
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [password, setPassword] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(10);
  
  const totalPages = Math.max(1, Math.ceil(recentScans.length / itemsPerPage));
  const safePage = Math.min(currentPage, totalPages);
  
  const paginatedScans = recentScans.slice(
    (safePage - 1) * itemsPerPage,
    safePage * itemsPerPage
  );

  const fetchScans = () => {
    listScans()
      .then((data) => setRecentScans(data.scans || []))
      .catch(() => {});
  };

  useEffect(() => {
    fetchScans();
      
    const handleResize = () => setItemsPerPage(window.innerWidth <= 768 ? 5 : 10);
    handleResize();
    window.addEventListener("resize", handleResize);
    return () => window.removeEventListener("resize", handleResize);
  }, []);

  useEffect(() => {
    const unlockedUntil = localStorage.getItem("scanbot_unlock_expiry");
    if (unlockedUntil && parseInt(unlockedUntil, 10) > Date.now()) {
      setIsUnlocked(true);
    } else {
      localStorage.removeItem("scanbot_unlock_expiry");
    }
  }, []);

  useEffect(() => {
    if (!isUnlocked) return;
    
    const updateExpiry = () => {
      localStorage.setItem("scanbot_unlock_expiry", (Date.now() + 5 * 60 * 1000).toString());
    };
    
    updateExpiry();
    const interval = setInterval(updateExpiry, 30000);
    return () => clearInterval(interval);
  }, [isUnlocked]);

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

  const handleDeleteScan = async (e: React.MouseEvent, scanId: string) => {
    e.preventDefault();
    e.stopPropagation();
    
    if (!confirm("Are you sure you want to delete this scan history? This will remove all data and reports.")) {
      return;
    }

    try {
      await deleteScan(scanId);
      setRecentScans(recentScans.filter(s => s.scanId !== scanId));
    } catch (err) {
      alert("Failed to delete scan.");
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
            <div style={{ position: "relative" }}>
              <div 
                className="history-list"
                style={{
                  filter: isUnlocked ? "none" : "blur(8px)",
                  pointerEvents: isUnlocked ? "auto" : "none",
                  userSelect: isUnlocked ? "auto" : "none",
                }}
              >
                {paginatedScans.map((scan) => (
                    <a
                      key={scan.scanId}
                      href={`/scan/${scan.scanId}`}
                      className="history-item"
                    >
                      <span className="history-target">{scan.target}</span>
                      <span className={`scan-mode-badge ${scan.scanMode || "fast"}`}>
                        {(scan.scanMode || "fast") === "deep" ? "🔬 Deep" : "⚡ Fast"}
                      </span>
                      <span className={`history-state ${scan.state}`}>
                        {scan.state}
                      </span>
                      <span className="history-time">
                        {formatTime(scan.createdAt)}
                      </span>
                      <button
                        onClick={(e) => handleDeleteScan(e, scan.scanId)}
                        className="btn-delete-small"
                        title="Delete Scan"
                      >
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="3 6 5 6 21 6"></polyline>
                          <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                          <line x1="10" y1="11" x2="10" y2="17"></line>
                          <line x1="14" y1="11" x2="14" y2="17"></line>
                        </svg>
                      </button>
                    </a>
                ))}
                {totalPages > 1 && (
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "1rem" }}>
                    <button 
                      className="btn btn-ghost" 
                      style={{ padding: "0.5rem 1rem", fontSize: "0.85rem" }}
                      disabled={safePage === 1}
                      onClick={() => setCurrentPage(safePage - 1)}
                    >
                      ← Previous
                    </button>
                    <span style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                      Page {safePage} of {totalPages}
                    </span>
                    <button 
                      className="btn btn-ghost" 
                      style={{ padding: "0.5rem 1rem", fontSize: "0.85rem" }}
                      disabled={safePage === totalPages}
                      onClick={() => setCurrentPage(safePage + 1)}
                    >
                      Next →
                    </button>
                  </div>
                )}
              </div>
              
              {!isUnlocked && (
                <div
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    right: 0,
                    bottom: 0,
                    display: "flex",
                    flexDirection: "column",
                    alignItems: "center",
                    justifyContent: "center",
                    background: "rgba(10, 14, 26, 0.3)",
                    borderRadius: "8px",
                    zIndex: 10,
                  }}
                >
                  <div style={{ marginBottom: "1rem", fontWeight: 600 }}>Enter password to view history</div>
                  <form
                    onSubmit={(e: any) => {
                      e.preventDefault();
                      if (password === "Jogja@2026#!") {
                        setIsUnlocked(true);
                      } else {
                        alert("Incorrect password!");
                      }
                    }}
                    style={{ display: "flex", gap: "0.5rem" }}
                  >
                    <input
                      type="password"
                      placeholder="Password"
                      value={password}
                      onChange={(e: any) => setPassword(e.target.value)}
                      className="scan-input"
                      style={{ padding: "0.5rem 1rem", fontSize: "0.9rem" }}
                    />
                    <button type="submit" className="btn btn-primary" style={{ padding: "0.5rem 1rem", fontSize: "0.9rem" }}>
                      Unlock
                    </button>
                  </form>
                </div>
              )}
            </div>
          </div>
        </section>
      )}
    </>
  );
}
