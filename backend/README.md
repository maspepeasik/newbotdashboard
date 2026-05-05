# Backend Service

Backend pada repository ini adalah engine utama untuk scan orchestration, API, persistence, AI analysis, dan PDF report generation.

## Peran Backend

Komponen utama yang dijalankan oleh backend:

- FastAPI HTTP API untuk dashboard
- Queue manager untuk membatasi scan paralel
- Job manager untuk orkestrasi pipeline
- SQLite persistence untuk scan, stage, result, raw output, dan audit log
- Optional Telegram bot bila token tersedia
- AI analysis via Groq
- PDF report generation via ReportLab

## Modul Penting

| Path | Fungsi |
|---|---|
| `main.py` | Entry point CLI dan bootstrap service |
| `config.py` | Loader environment dan runtime config |
| `core/database.py` | SQLite schema dan persistence |
| `core/job_manager.py` | Lifecycle scan dan pipeline orchestration |
| `core/queue_manager.py` | Batas concurrency scan |
| `service/http_api.py` | FastAPI app factory dan endpoint |
| `pipeline/` | 10 tahap scanning |
| `analysis/` | Aggregation, normalization, AI analysis |
| `report/` | Report builder dan PDF generator |
| `utils/command_runner.py` | Wrapper eksekusi tool eksternal |

## Urutan Stage Backend

Pipeline aktual yang dijalankan backend:

1. Recon
2. Resolver
3. OriginIP
4. PortScan
5. ServiceScan
6. HTTPProbe
7. Fingerprint
8. WebDiscovery
9. VulnScan
10. TLSScan
11. Aggregation
12. AIAnalysis
13. Report

Backend kemudian menutup job dengan state `Done` jika report berhasil dibuat.

## Menjalankan Secara Lokal

1. Salin environment file dari root repository.

```bash
cp ../.env.example ../.env
```

2. Install dependency Python.

```bash
pip install -r requirements.txt
```

3. Cek tool eksternal.

```bash
python main.py --check-tools
```

4. Jalankan backend API only.

```bash
python main.py --api-only
```

5. Atau jalankan test scan headless.

```bash
python main.py --test-scan example.com --scan-mode fast
```

## CLI Flags

| Flag | Fungsi |
|---|---|
| `--config` | Path file `.env` |
| `--check-tools` | Verifikasi tool lalu exit |
| `--test-scan TARGET` | Jalankan scan tanpa dashboard |
| `--api-only` | Nonaktifkan Telegram walau token ada |
| `--scan-mode fast|deep` | Pilih mode scan untuk `--test-scan` |
| `--log-level` | Override log level runtime |

## Telegram Bot

Telegram bot masih didukung, tetapi sifatnya opsional.

- Jika `TELEGRAM_BOT_TOKEN` tersedia dan Anda tidak memakai `--api-only`, backend akan mencoba menjalankan bot di background.
- Root Docker deployment tidak memakai mode ini. Container backend dijalankan dengan `CMD ["python3", "main.py", "--api-only"]`.

## Konfigurasi yang Paling Relevan

### AI

- `GROQ_API_KEYS`
- `GROQ_MODEL`
- `GROQ_MAX_TOKENS`
- `GROQ_TEMPERATURE`

### API

- `PENTESTBOT_API_PORT`
- `PENTESTBOT_API_TOKEN`
- `CORS_ORIGINS`

### Scan

- `MAX_CONCURRENT_SCANS`
- `SCAN_TIMEOUT`
- `NAABU_TOP_PORTS`
- `NAABU_RATE`
- `NUCLEI_SEVERITY`
- `NUCLEI_RATE_LIMIT`
- `ENABLE_AMASS`
- `ENABLE_WEB_DISCOVERY`
- `ENABLE_FINGERPRINT`
- `ENABLE_NIKTO`
- `ENABLE_WPSCAN`
- `ENABLE_JOOMSCAN`
- `ENABLE_S3SCANNER`
- `ENABLE_SSLYZE`

## Penyimpanan Runtime

Path default:

- `/app/data`
- `/app/logs`
- `/app/reports`

Database SQLite default:

- `/app/data/pentestbot.db`

## Catatan Implementasi

- `job_manager.py` adalah sumber kebenaran urutan stage.
- `normalizer.py` memutuskan finding mana yang masuk report final.
- `groq_ai.py` tidak hanya menulis section report, tetapi juga melakukan enrichment deskripsi finding prioritas.
- `vuln_scan.py` menjalankan `nuclei` dan `nikto` paralel, lalu menambah `wpscan` atau `joomscan` bila CMS terdeteksi.

## Docker

Docker image backend meng-include sebagian besar tool scanning penting, termasuk:

- ProjectDiscovery tools
- `nmap`
- `testssl.sh`
- `nikto`
- `whatweb`
- `wpscan`
- `joomscan`
- `dirsearch`

Detail deployment lintas service ada di `../DEPLOYMENT.md`.
