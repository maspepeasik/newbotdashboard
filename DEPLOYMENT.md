# PentestBot v2 — Docker Deployment

This parent folder orchestrates the current PentestBot dashboard architecture:

- `frontend/`: Next.js web dashboard
- `backend/`: Engine (FastAPI + Scanner Pipeline)
- `cloudflared`: Tunnel for public exposure (configured in `docker-compose.yml`)

The root compose file currently runs these three services only. The backend is started in API-only mode for the dashboard deployment.

## Preparation

1. Provide the main environment file (at the root of this project folder) by copying the example:

```bash
cp .env.example .env
```

2. Fill required secrets in `.env`:

- `GROQ_API_KEYS` (recommended, comma-separated)
- `CLOUDFLARE_TUNNEL_TOKEN` (if using cloudflared)
- `PENTESTBOT_API_TOKEN` (for secure API access)
- `NEXT_PUBLIC_API_URL` (recommended for frontend-to-backend communication)

> `GROQ_API_KEY` is still supported for backward compatibility, but `.env.example` and the current deployment flow use `GROQ_API_KEYS`.

## Start everything

```bash
docker compose up --build -d
```

## View logs

```bash
docker compose logs -f
```

## Stop everything

```bash
docker compose down
```

## Remove all service volumes

```bash
docker compose down -v
```

## Exposed ports

- `8000`: Engine API
- `3000`: Frontend Dashboard
