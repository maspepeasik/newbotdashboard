# Scan Bot — Docker Deployment

This parent folder orchestrates the entire PentestBot architecture:

- `frontend/`: Next.js web dashboard
- `backend/`: Engine (FastAPI + Scanner Pipeline)
- `cloudflared`: Tunnel for public exposure (configured in docker-compose.yml)

## Preparation

1. Provide the main environment file (at the root of this project folder) by copying the example:

```bash
cp .env.example .env
```

2. Fill required secrets in `.env`:

- `GROQ_API_KEY`
- `CLOUDFLARE_TUNNEL_TOKEN` (if using cloudflared)
- `PENTESTBOT_API_TOKEN` (for secure API access)

## Start everything

```bash
docker-compose up --build -d
```

## View logs

```bash
docker-compose logs -f
```

## Stop everything

```bash
docker-compose down
```

## Remove all service volumes

```bash
docker-compose down -v
```

## Exposed ports

- `8000`: Engine API
- `3000`: Frontend Dashboard
