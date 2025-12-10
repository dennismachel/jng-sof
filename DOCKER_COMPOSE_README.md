Quick Docker Compose (local) — app + Postgres

This repository includes a docker-compose.yml that runs a Postgres database and the web app together for local development and testing.

How it works
- "db" runs Postgres 15 and exposes standard port 5432.
- "web" builds from project root (your `Dockerfile`) and runs gunicorn listening on $PORT (8080).
- The `web` service is configured with `POSTGRES_HOST=db` so it connects over the internal Docker network.

Quick commands

1) Build and run (foreground):

   docker compose up --build

2) Build and run (detached/background):

   docker compose up -d --build

3) Check logs (web or db):

   docker compose logs -f web
   docker compose logs -f db

4) Smoke test

   curl -I http://localhost:8080/login

5) Stop and clean containers + volumes (wipes db data):

   docker compose down -v

Notes
- The compose file sets `USE_SQLITE_TESTING=0` so the app uses Postgres (not the sqlite fallback).
- The DB credentials in `docker-compose.yml` are placeholders (POSTGRES_USER=jnguser / POSTGRES_PASSWORD=examplepassword). For local development you may update them or use environment variables from a .env file if you prefer.
- The app will attempt to create tables on startup using the configured schema, so there is no separate migration step for this simple setup.

Troubleshooting
- If the web service starts but returns 500s, check `docker compose logs web` for tracebacks (often missing env vars or connection issues).
- If DB healthcheck fails, run `docker compose logs db` to inspect startup errors.
