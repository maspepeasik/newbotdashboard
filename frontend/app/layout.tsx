import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "PentestBot — Automated Security Assessment",
  description:
    "No-exploit reconnaissance and discovery platform. Submit a target domain for deep passive vulnerability scanning and AI-powered PDF reports.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <div className="bg-mesh" />
        <div className="app-container">
          <header className="app-header">
            <a href="/" className="app-logo">
              <div className="logo-icon">C</div>
              <div className="logo-text">
                CyberScan
              </div>
            </a>
          </header>
          <main style={{ flex: 1, display: "flex", flexDirection: "column" }}>
            {children}
          </main>
        </div>
      </body>
    </html>
  );
}
