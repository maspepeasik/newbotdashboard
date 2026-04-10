<h1 align="center">ScanBot Dashboard</h1>

<p align="center">
  <i>Automated Scanning Bots Platform with AI-Powered Reporting</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Next.js-15-000000?style=flat-square&logo=nextdotjs&logoColor=white" alt="Next.js">
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker">
  <img src="https://img.shields.io/badge/License-Private-red?style=flat-square" alt="License">
</p>

---

## 👨‍💻 Author

| Field | Detail |
|---|---|
| **Prepared by** | Narendra Yudhistira Bagaskoro, Rafa Nuragani Kurniawan |
| **Institution** | SMKN 2 Yogyakarta — Sistem Informasi Jaringan dan Aplikasi (SIJA) |
| **Version** | 1.0.0 |

---

## 📖 Project Overview

**ScanBot Dashboard** is a full-stack automated scanning bots platform that combines a multi-tool reconnaissance engine with an AI-powered report generator and a real-time web dashboard. The system is designed for security professionals and developers who need to assess the external attack surface of a domain or IP address without performing active exploitation.

The platform solves the following problems:

- **Tool Fragmentation** — Instead of manually running 15+ security tools (subfinder, nmap, nuclei, testssl.sh, etc.) and correlating their outputs, ScanBot orchestrates a complete 11-stage scanning pipeline automatically.
- **Report Noise** — Raw scanner output contains excessive false positives and low-signal detections. ScanBot normalizes, deduplicates, and filters findings through severity-aware logic before passing them to an AI (Groq LLaMA 3.3) that generates professional prose narratives for each report section.
- **Accessibility** — The Next.js web dashboard provides a user-friendly interface for submitting scans, monitoring real-time progress across all pipeline stages, and downloading professionally formatted PDF reports.
- **Flexibility** — The system can be operated through the web dashboard or directly via REST API, and supports both **Fast** and **Deep** scan modes.

---

## 🚀 Tech Stack & Dependencies

### Backend (Scanning Engine + API)

| Category | Technology |
|---|---|
| **Language** | Python 3.11 |
| **Web Framework** | FastAPI ≥ 0.115, Uvicorn ≥ 0.32 |
| **Database** | SQLite (async via `aiosqlite` ≥ 0.20) |
| **AI Integration** | Groq API (LLaMA 3.3 70B Versatile) via `httpx` |
| **PDF Generation** | ReportLab ≥ 4.2 |
| **TLS Analysis** | sslyze ≥ 6.2, testssl.sh |
| **HTTP Client** | httpx ≥ 0.27, aiohttp ≥ 3.10 |
| **Environment** | python-dotenv ≥ 1.0 |

### External Security Tools (installed in Docker image)

| Tool | Purpose |
|---|---|
| `subfinder`, `assetfinder`, `amass` | Subdomain discovery |
| `dnsx` | DNS resolution |
| `naabu` | Port scanning |
| `nmap` | Service detection & script scanning |
| `httpx` (ProjectDiscovery) | HTTP/HTTPS probing & technology detection |
| `katana`, `gau`, `gobuster`, `dirsearch` | Web discovery & URL enumeration |
| `nuclei` | Template-based vulnerability scanning |
| `nikto` | Web server scanner |
| `whatweb`, `wafw00f`, `webanalyze` | Technology fingerprinting & WAF detection |
| `wpscan`, `joomscan` | CMS-specific vulnerability scanning |
| `testssl.sh`, `sslyze` | TLS/SSL configuration analysis |
| `s3scanner` | S3 bucket misconfiguration detection |

### Frontend (Web Dashboard)

| Category | Technology |
|---|---|
| **Framework** | Next.js 15 (App Router) |
| **Language** | TypeScript 5.8 |
| **UI Library** | React 19 |
| **Runtime** | Node.js 20 |

### Infrastructure

| Category | Technology |
|---|---|
| **Containerization** | Docker, Docker Compose |
| **Tunneling** | Cloudflare Tunnel (cloudflared) |
| **Architecture** | 3-service compose (engine, frontend, cloudflared) |

---

## 📁 Directory Structure

```
projectdashboard/
├── docker-compose.yml          # Multi-service orchestration (engine + frontend + tunnel)
├── .env.example                # Environment variable template for Docker Compose
│
├── backend/                    # Python scanning engine + FastAPI server
│   ├── main.py                 # Application entry point (CLI + server bootstrap)
│   ├── config.py               # Configuration loader (reads .env → dataclasses)
│   ├── scan_profiles.py        # Fast/Deep scan mode definitions & overrides
│   ├── Dockerfile              # Multi-stage build (Go tools → Python runtime)
│   ├── requirements.txt        # Python package dependencies
│   │
│   ├── core/                   # Core infrastructure
│   │   ├── database.py         # Async SQLite layer (scans, stages, results, audit)
│   │   ├── job_manager.py      # Scan lifecycle management & pipeline orchestration
│   │   └── queue_manager.py    # Concurrent scan queue with max-parallelism control
│   │
│   ├── pipeline/               # 11-stage scanning pipeline
│   │   ├── base_stage.py       # Abstract base class for all pipeline stages
│   │   ├── recon.py            # Stage 1: Subdomain discovery (subfinder + assetfinder)
│   │   ├── resolver.py         # Stage 2: DNS resolution (dnsx)
│   │   ├── originip.py         # Stage 3: Origin IP / CDN bypass detection
│   │   ├── portscan.py         # Stage 4: Port scanning (naabu)
│   │   ├── service_scan.py     # Stage 5: Service detection (nmap)
│   │   ├── http_probe.py       # Stage 6: HTTP/HTTPS probing (httpx)
│   │   ├── fingerprint.py      # Stage 7: Technology fingerprinting (whatweb/wafw00f/webanalyze)
│   │   ├── web_discovery.py    # Stage 8: URL discovery (katana + gau + gobuster)
│   │   ├── vuln_scan.py        # Stage 9: Vulnerability scanning (nuclei + nikto)
│   │   └── tls_scan.py         # Stage 10: TLS/SSL analysis (testssl.sh + sslyze)
│   │
│   ├── analysis/               # Post-scan data processing
│   │   ├── result_aggregator.py  # Merges all stage outputs into unified AggregatedResult
│   │   ├── normalizer.py       # Deduplication, severity filtering, noise reduction
│   │   └── groq_ai.py          # AI narrative generation via Groq API (11 report sections)
│   │
│   ├── report/                 # PDF report generation
│   │   ├── report_builder.py   # Assembles ReportData from scan artifacts + AI analysis
│   │   └── pdf_generator.py    # Renders professional PDF using ReportLab
│   │
│   ├── service/                # Network services
│   │   └── http_api.py         # FastAPI application factory (REST endpoints)
│   │
│   ├── utils/                  # Shared utilities
│   │   ├── command_runner.py   # Async subprocess wrapper for external tool execution
│   │   └── logger.py           # Structured logging (per-scan log files)
│   │
│   ├── docker/                 # Container support files
│   │   └── entrypoint.sh       # Container initialization script
│   │
│   ├── scripts/                # Maintenance scripts
│   │   └── install_tools.sh    # Host-level tool installer
│   │
│   ├── data/                   # Runtime data (SQLite DB, working files)
│   ├── logs/                   # Application and per-scan log files
│   └── reports/                # Generated PDF reports
│
└── frontend/                   # Next.js web dashboard
    ├── Dockerfile              # Multi-stage Node.js build
    ├── package.json            # Node.js dependencies
    ├── next.config.ts          # Next.js configuration
    ├── tsconfig.json           # TypeScript configuration
    ├── app/                    # Next.js App Router pages
    │   ├── layout.tsx          # Root layout component
    │   ├── page.tsx            # Dashboard home page (scan submission + history)
    │   ├── globals.css         # Global stylesheet
    │   └── scan/[id]/          # Dynamic scan detail page (real-time progress)
    ├── lib/
    │   └── api.ts              # Typed API client (communicates with FastAPI backend)
    └── public/                 # Static assets
```

---

## ⚙️ System Workflow

The system follows a **pipeline architecture** where data flows through clearly defined stages:

```
┌──────────────────────────────────────────────────────────────────┐
│                         USER INPUT                               │
│  (Web Dashboard / REST API)                                      │
│  Target: domain name or IP address                               │
│  Mode: Fast or Deep                                              │
└──────────────┬───────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────┐
│                    FASTAPI SERVER (Port 8000)                     │
│  POST /api/scans → validates target → creates DB record          │
│                  → enqueues scan job                             │
└──────────────┬───────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────┐
│               11-STAGE SCANNING PIPELINE                         │
│                                                                  │
│  1. Recon         → Subdomain discovery (subfinder, assetfinder) │
│  2. Resolver      → DNS resolution (dnsx)                        │
│  3. OriginIP      → CDN bypass / origin IP detection             │
│  4. PortScan      → Port scanning (naabu, top 1000 or full)      │
│  5. ServiceScan   → Service fingerprinting (nmap -sV -sC)        │
│  6. HTTPProbe     → Live endpoint discovery (httpx)              │
│  7. Fingerprint   → Tech detection (whatweb, wafw00f, webanalyze)│
│  8. WebDiscovery  → URL enumeration (katana, gau, gobuster)      │
│  9. VulnScan      → Vulnerability checks (nuclei, nikto)         │
│ 10. TLSScan       → TLS configuration analysis (testssl, sslyze) │
│ 11. Aggregation   → Result merging + normalization + filtering   │
│                                                                  │
│  Each stage writes findings to a shared context dictionary.      │
│  Raw tool outputs are persisted to SQLite for audit.             │
└──────────────┬───────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────┐
│                    AI ANALYSIS (Groq API)                         │
│                                                                  │
│  All aggregated scan data is sent to LLaMA 3.3 70B which         │
│  generates 11 narrative sections:                                │
│  Executive Summary, Scope, Attack Surface, Vulnerabilities,      │
│  Network Exposure, TLS Analysis, Realistic Risk Summary,         │
│  Attack Paths, Remediation Plan, Conclusion,                     │
│  Initial Security Recommendations                                │
└──────────────┬───────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────┐
│                   PDF REPORT GENERATION                           │
│                                                                  │
│  ReportBuilder assembles scan data + AI narratives → ReportData  │
│  PDFGenerator renders a professional A4 PDF via ReportLab        │
│  Report is saved to /app/reports/ and path stored in SQLite      │
└──────────────┬───────────────────────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────────────┐
│                    DELIVERY TO USER                               │
│                                                                  │
│  • Web Dashboard: real-time progress bar + PDF download button   │
│  • REST API: GET /api/scans/{id}/report → PDF file response      │
└──────────────────────────────────────────────────────────────────┘
```

### Scan Modes

| Mode | Description |
|---|---|
| **Fast** (default) | Top 1000 ports, standard Nuclei templates (critical/high/medium), shallow crawl depth (2), core tools only. Completes in ~10–20 minutes. |
| **Deep** | Full port range, extended Nuclei templates (includes low severity), crawl depth 4, enables additional tools (Amass, Nikto, Dirsearch, S3Scanner). Completes in ~30–60+ minutes. |

---

## 🛠️ Setup & Installation

### Prerequisites

- **Docker** ≥ 20.10 and **Docker Compose** ≥ 2.0
- A **Groq API key** (free at [console.groq.com](https://console.groq.com))
- *(Optional)* A Cloudflare Tunnel token for public access

### 1. Clone the Repository

```bash
git clone https://github.com/maspepeasik/newbotdashboard.git
cd newbotdashboard
```

### 2. Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```env
# Required — Groq AI API key for report generation
GROQ_API_KEY=your_groq_api_key_here

# Required — API authentication token (pre-generated default is included)
PENTESTBOT_API_TOKEN=b47bc562f096436ce843868429268cca86acbbe5f6cf1971d8341d366b00ff22

# Required for public access — set to your engine's public URL
NEXT_PUBLIC_API_URL=http://localhost:8000

# Optional — Cloudflare Tunnel for public exposure
CLOUDFLARE_TUNNEL_TOKEN=your_tunnel_token
```

### 3. Build and Start with Docker Compose

```bash
docker compose up -d --build
```

This launches three services:

| Service | Container | Port | Description |
|---|---|---|---|
| `engine` | `pentestbot-engine` | `8000` | FastAPI backend + scanning pipeline |
| `frontend` | `pentestbot-frontend` | `3000` | Next.js web dashboard |
| `cloudflared` | `pentestbot-tunnel` | — | Cloudflare Tunnel (optional) |

### 4. Verify Deployment

```bash
# Check all services are healthy
docker compose ps

# Test the API health endpoint
curl http://localhost:8000/health

# Open the dashboard
# Navigate to http://localhost:3000 in your browser
```

### 5. View Logs

```bash
# All services
docker compose logs -f

# Engine only
docker compose logs -f engine

# Frontend only
docker compose logs -f frontend
```

### Tool Verification (inside container)

```bash
docker compose exec engine python3 main.py --check-tools
```

---

## ✨ Main Features

### 1. Web Dashboard (Next.js)

- **Scan Submission** — Enter a domain or IP address, select Fast or Deep mode, and launch a scan with a single click.
- **Real-Time Progress Tracking** — Live progress bar updates across all 11 pipeline stages with percentage indicators.
- **Scan History** — View recent scans with status, risk level, finding counts, and duration.
- **PDF Report Download** — Download the AI-generated professional scanning bots report directly from the dashboard.
- **Responsive Design** — Modern, dark-themed interface optimized for desktop and mobile.

### 2. Scanning Engine (Python)

- **11-Stage Pipeline** — Automated orchestration of subdomain discovery, DNS resolution, origin IP detection, port scanning, service detection, HTTP probing, fingerprinting, web discovery, vulnerability scanning, and TLS analysis.
- **Concurrent Scanning** — Configurable maximum concurrent scans (default: 3) with queue management.
- **Graceful Error Handling** — Individual tool failures are contained per-stage; the pipeline continues with degraded coverage and records limitations in the final report.
- **Scan Profiles** — Fast mode for quick assessments; Deep mode enables full port scans, additional tools, deeper crawling, and extended timeouts.

### 3. AI-Powered Report Generation

- **11 AI-Written Sections** — Executive Summary, Scope & Coverage, Attack Surface, Vulnerability Analysis, Network Exposure, TLS Analysis, Realistic Risk Summary, Attack Path Simulation, Remediation Priorities, Conclusion, and Initial Security Recommendations.
- **Evidence-Driven Narratives** — The AI is instructed to never invent findings, distinguish observed conditions from inferred risk, and avoid hype or severity inflation.
- **Fallback Mechanism** — If the Groq API is unavailable, static fallback text is generated for each section so reports are always produced.

### 4. Professional PDF Reports

- **A4 Format** — Clean, engineering-focused layout with headers, footers, page numbers, and section separators.
- **Finding Detail Cards** — Each finding includes evidence status, exploitability assessment, impact classification, priority timeline, description, affected assets, source, remediation guidance, and references.
- **Severity-Aware Filtering** — Low-signal observations are excluded from the main findings section; the report clearly states excluded observation counts.

### 5. REST API Endpoints

All endpoints require Bearer token authentication when `PENTESTBOT_API_TOKEN` is configured.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health check (no auth required) |
| `POST` | `/api/scans` | Submit a new scan (body: `{ target, scanMode }`) |
| `GET` | `/api/scans` | List recent scans (query: `?limit=20`) |
| `GET` | `/api/scans/{scan_id}` | Get scan status, progress, stages, and summary |
| `GET` | `/api/scans/{scan_id}/logs` | Get per-scan log entries (query: `?after=0` for pagination) |
| `GET` | `/api/scans/{scan_id}/report` | Download the generated PDF report |

#### Example: Submit a Scan

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer b47bc562f096436ce843868429268cca86acbbe5f6cf1971d8341d366b00ff22" \
  -d '{"target": "example.com", "scanMode": "fast"}'
```

#### Example: Check Scan Status

```bash
curl http://localhost:8000/api/scans/{scan_id} \
  -H "Authorization: Bearer b47bc562f096436ce843868429268cca86acbbe5f6cf1971d8341d366b00ff22"
```

---

## 📄 Database Schema

The system uses **SQLite** (async via `aiosqlite`) with WAL journal mode. The database file is stored at `/app/data/pentestbot.db` inside the container.

| Table | Purpose |
|---|---|
| `scans` | Scan metadata: target, state, timestamps, PDF path, summary JSON |
| `scan_stages` | Per-stage progress tracking (state, start/end timestamps, errors) |
| `scan_results` | Full aggregated results stored as a JSON blob |
| `raw_outputs` | Per-tool raw stdout/stderr for audit and debugging |
| `audit_log` | Timestamped audit trail of all user actions |

---

## 🔒 Security Considerations

- All scan operations are **non-destructive** — the system performs reconnaissance and detection only, never active exploitation.
- The API supports **Bearer token authentication** to prevent unauthorized access.
- **`.gov` and `.mil` domains** are blocked at the target validation layer.
- **Private/RFC1918 IP addresses** and **loopback addresses** are rejected.
- The `.env` file is excluded from Docker builds via `.dockerignore` — secrets are injected through Docker Compose environment variables.

---

> **Disclaimer:** This tool is intended for authorized security assessments only. Ensure you have explicit written permission before scanning any target. Unauthorized scanning may violate applicable laws and regulations.
