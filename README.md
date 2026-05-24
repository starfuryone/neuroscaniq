# NeuroScanIQ

> **AI-Powered Internet Exposure Intelligence**
> Search and monitor internet-connected infrastructure — built exclusively for defensive cybersecurity and authorized asset monitoring.

NeuroScanIQ indexes publicly accessible internet infrastructure and transforms exposure data into searchable security intelligence. Inspired by Shodan and Censys, it is designed for security teams, researchers, and infrastructure operators who need visibility into their attack surface.

---

## Table of Contents

- [Features](#features)
- [Defensive-Only Posture](#defensive-only-posture)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
- [Environment Variables](#environment-variables)
- [Development](#development)
- [Production Deployment](#production-deployment)
- [API Documentation](#api-documentation)
- [Project Structure](#project-structure)
- [Security](#security)
- [License](#license)

---

## Features

- **Global search engine** — query exposed assets by IP, domain, port, service, ASN, organization, country, software, TLS certificate, HTTP title, and more, backed by OpenSearch.
- **Host detail intelligence** — open ports, banners, TLS metadata, HTTP headers, WHOIS, GeoIP, screenshots, historical observations, risk indicators, and timeline.
- **Attack surface monitoring** — track authorized assets with DNS TXT / email / file / ASN ownership validation. Detect new ports, service changes, TLS drift, and exposure changes.
- **Alerting** — email, webhook, and dashboard notifications with severity and history.
- **Interactive maps** — clustered markers, heatmaps, country/service/port filters.
- **Screenshot system** — headless Chromium captures of HTTP/HTTPS services, stored in object storage with thumbnails and indexed metadata.
- **Developer API** — REST endpoints, API key auth, rate limiting, usage tracking, OpenAPI/Swagger docs.
- **Admin dashboard** — user management, queue health, abuse signals, billing overview, search analytics, worker telemetry.
- **Stripe billing** — Free, Pro, and Enterprise plans with feature gating.
- **AI layer** — service classification, exposure categorization, risk prioritization, anomaly detection, infrastructure summarization.

## Defensive-Only Posture

NeuroScanIQ is intended **exclusively** for defensive cybersecurity and authorized monitoring. The platform:

- ❌ Does **not** include exploitation modules
- ❌ Does **not** include brute-force or credential-stuffing tooling
- ❌ Does **not** include malware functionality
- ✅ **Requires ownership proof** for any monitoring of an asset
- ✅ Excludes private IP ranges from scanning
- ✅ Filters and rejects exploit payloads in any user-supplied input
- ✅ Rate-limits aggressively and audit-logs all sensitive actions

## Architecture

```
                          ┌───────────────────────┐
                          │   Next.js Frontend    │
                          │  (Dashboard / Search) │
                          └──────────┬────────────┘
                                     │ HTTPS
                          ┌──────────▼────────────┐
                          │    NGINX (TLS, WAF)   │
                          └──────────┬────────────┘
                                     │
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
     ┌────────▼────────┐   ┌─────────▼────────┐   ┌─────────▼────────┐
     │  FastAPI API    │   │  Scanner Worker  │   │ Screenshot Worker│
     │  (Auth/Search)  │   │   (BullMQ-like)  │   │   (Chromium)     │
     └────────┬────────┘   └─────────┬────────┘   └─────────┬────────┘
              │                      │                      │
   ┌──────────┼──────────┬───────────┴──────────┐           │
   │          │          │                      │           │
┌──▼──┐  ┌────▼───┐ ┌────▼─────┐  ┌─────────────▼──┐  ┌─────▼──────┐
│ PG  │  │ Redis  │ │OpenSearch│  │     Stripe     │  │  S3/Minio  │
└─────┘  └────────┘ └──────────┘  └────────────────┘  └────────────┘
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 15, TypeScript, TailwindCSS, shadcn/ui, Framer Motion, Leaflet, Zustand |
| Backend | Python 3.12, FastAPI, SQLAlchemy 2, Pydantic v2, Alembic |
| Search | OpenSearch |
| Database | PostgreSQL 16 |
| Cache / Queue | Redis 7 (RQ for Python-side queues, mirroring BullMQ patterns) |
| Storage | S3-compatible (MinIO for local dev) |
| Auth | JWT (access + refresh), API keys |
| Billing | Stripe |
| Infra | Docker, Docker Compose, NGINX, GitHub Actions |

## Quick Start

### Prerequisites

- Docker 24+ and Docker Compose 2+
- 8 GB RAM minimum (OpenSearch is memory-hungry)
- Make (optional, for shortcuts)

### Boot the stack

```bash
git clone <your-fork> neuroscaniq
cd neuroscaniq
cp .env.example .env
# Edit .env with your secrets (JWT_SECRET, STRIPE_*, etc.)

docker compose up -d --build
```

Wait ~60 seconds for OpenSearch to be healthy, then:

```bash
# Run database migrations
docker compose exec api alembic upgrade head

# Seed an admin user
docker compose exec api python -m app.scripts.seed_admin

# Visit
open http://localhost:3000
```

API docs are served at `http://localhost:8000/docs` (Swagger) and `http://localhost:8000/redoc`.

## Environment Variables

See `.env.example` for the full list. Critical ones:

| Variable | Purpose |
|----------|---------|
| `JWT_SECRET` | Signing key for access tokens. Use 32+ random bytes. |
| `POSTGRES_*` | Database connection. |
| `OPENSEARCH_URL` | Search backend. |
| `REDIS_URL` | Cache + queues. |
| `S3_*` | Screenshot storage. |
| `STRIPE_SECRET_KEY` / `STRIPE_WEBHOOK_SECRET` | Billing. |
| `ALLOWED_SCAN_CIDRS` | Comma-separated CIDRs that workers are allowed to probe. Defaults to empty. |
| `BLOCKED_SCAN_CIDRS` | Always-blocked ranges (RFC1918, loopback, link-local seeded by default). |

## Development

Run services with hot reload:

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend
npm install
npm run dev
```

Run tests:

```bash
cd backend && pytest
cd frontend && npm test
```

## Production Deployment

Production uses `docker-compose.prod.yml` with:

- NGINX as TLS terminator (Let's Encrypt via certbot sidecar)
- PM2 ecosystem file for the Next.js frontend
- Read replicas optional for PostgreSQL
- Worker autoscaling via Docker Swarm or Kubernetes (manifests not bundled — use the Compose file as a template)

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

GitHub Actions CI/CD is wired in `.github/workflows/ci.yml`. It runs lint, type-check, tests, and builds production images.

## API Documentation

See `docs/API.md` and the live Swagger UI at `/docs`.

Key endpoints:

- `POST /api/v1/auth/register` — create account
- `POST /api/v1/auth/login` — issue JWT
- `GET /api/v1/search?q=...` — search exposed infrastructure
- `GET /api/v1/host/{ip}` — host detail
- `POST /api/v1/monitor` — register a monitored asset (requires ownership proof)
- `GET /api/v1/alerts` — fetch alerts
- `GET /api/v1/screenshots` — list screenshots

All endpoints require either a Bearer JWT or an `X-API-Key` header.

## Project Structure

```
neuroscaniq/
├── backend/              FastAPI API
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── models/       SQLAlchemy ORM
│   │   ├── schemas/      Pydantic models
│   │   ├── api/          Route modules
│   │   ├── core/         Security, deps, rate limiting
│   │   ├── services/     OpenSearch, Stripe, AI, etc.
│   │   ├── workers/      Background job handlers
│   │   └── db/           Session, base
│   ├── alembic/
│   └── tests/
├── frontend/             Next.js 15 dashboard
│   ├── src/
│   │   ├── app/
│   │   ├── components/
│   │   ├── lib/
│   │   └── store/
├── workers/              Standalone worker definitions
├── nginx/                Reverse proxy config
├── docs/
├── docker-compose.yml
├── docker-compose.prod.yml
├── ecosystem.config.js   PM2
└── .github/workflows/
```

## Security

- All passwords are hashed with Argon2id.
- JWTs are short-lived (15 min) with refresh tokens (7 days, rotated on use).
- API keys are stored as bcrypt hashes; only the prefix is shown after creation.
- CSP, HSTS, X-Frame-Options, and X-Content-Type-Options are set globally.
- Rate limiting is enforced per IP and per API key using a sliding window in Redis.
- Audit logs capture every admin action and every monitor creation.
- Workers run in their own containers with no inbound network capabilities.
- Ownership validation is required before any monitoring job is dispatched.

Report security issues to `security@example.com` (configure in your fork).

## License

This project is released under the MIT License. See `LICENSE` for details.

---

**NeuroScanIQ is a defensive cybersecurity tool. Do not use it against systems you do not own or have written authorization to test.**
