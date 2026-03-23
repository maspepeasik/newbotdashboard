# Combined Docker Deployment

This parent folder can run both systems together:

- `dashboard/`: web dashboard, API, worker, PostgreSQL, Redis
- `pentestbot_2-main/`: Telegram automation bot

## Preparation

1. Copy both environment files:

```bash
cp dashboard/.env.example dashboard/.env
cp pentestbot_2-main/.env.example pentestbot_2-main/.env
```

2. Fill required secrets:

- `dashboard/.env`
  - `JWT_SECRET`
- `pentestbot_2-main/.env`
  - `TELEGRAM_BOT_TOKEN`
  - `GROQ_API_KEY`
  - `ALLOWED_USER_IDS`

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

- `3000`: Dashboard web UI
- `4000`: Dashboard API and Socket.IO
- `5432`: PostgreSQL
- `6379`: Redis
