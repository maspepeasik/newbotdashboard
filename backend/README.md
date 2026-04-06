# PentestBot v2

Production-oriented Telegram bot for automated penetration testing pipelines, AI-assisted analysis, and PDF report delivery.

## Capabilities

- Telegram-triggered scan execution
- Multi-stage recon, scanning, vulnerability, and TLS workflow
- Focused web discovery from live endpoints and passive URL sources
- Async job management with queueing
- SQLite-backed scan history
- Groq-powered report analysis
- Filtered PDF report generation with lower noise from informational detections
- Docker-ready deployment with persistent volumes

## Project Structure

- `main.py`: entrypoint
- `config.py`: environment-driven runtime config
- `bot/`: Telegram bot handlers
- `core/`: job manager, queue manager, database
- `pipeline/`: scan stages
- `analysis/`: result aggregation and AI analysis
- `report/`: report builder and PDF generation
- `utils/`: command runner and logging
- `docker/`: container entrypoint

## Local Run

1. Copy environment file:

```bash
cp .env.example .env
```

2. Fill required values:

- `TELEGRAM_BOT_TOKEN`
- `GROQ_API_KEY`
- `ALLOWED_USER_IDS`

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Verify tool availability:

```bash
python3 main.py --check-tools
```

5. Start the bot:

```bash
python3 main.py
```

## Standalone Docker Deployment

The bot now includes:

- `Dockerfile`: production container image
- `docker-compose.yml`: standalone bot deployment
- `docker/entrypoint.sh`: runtime ownership fix for mounted volumes and nuclei template bootstrap

### 1. Prepare environment

```bash
cp .env.example .env
```

Set:

- `TELEGRAM_BOT_TOKEN`
- `GROQ_API_KEY`
- `ALLOWED_USER_IDS`

### 2. Build and run

```bash
docker compose up --build -d
```

Toggles yang relevan untuk deployment container:

- `ENABLE_WEB_DISCOVERY=true` untuk mengaktifkan `gau` + `katana`
- `ENABLE_SSLYZE=true` untuk validasi TLS sekunder
- `ENABLE_NIKTO=false` agar report tetap minim noise
- `MAX_DISCOVERED_URLS=150` untuk membatasi hasil crawling yang masuk pipeline

### 3. Inspect logs

```bash
docker compose logs -f
```

### 4. Stop the bot

```bash
docker compose down
```

## Docker Notes

- Scan data is stored in `/app/data`
- Application logs are stored in `/app/logs`
- Generated reports are stored in `/app/reports`
- Nuclei templates are persisted in a named volume under `/home/pentestbot/.config/nuclei`
- The container entrypoint fixes ownership for mounted volumes before starting the bot

This avoids the permission issues that typically happen when named Docker volumes are mounted into a non-root container.

## Combined Deployment With Dashboard

To run the dashboard and bot together, use the parent-level compose file:

## Important Legal Notice

Run scans only against systems you are explicitly authorized to test. Unauthorized scanning can be illegal and harmful.
