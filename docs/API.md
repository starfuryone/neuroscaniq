# NeuroScanIQ REST API Reference

All endpoints are prefixed with `/api/v1`. The OpenAPI spec is generated automatically and served at `GET /api/v1/openapi.json`. An interactive Swagger UI lives at `GET /api/v1/docs`.

## Authentication

Two authentication modes are supported:

**JWT Bearer (for browser sessions)** — issued by `/auth/login`. Access tokens are short-lived (15 min); refresh tokens are 7 days. Both are bound to distinct audiences (`neuroscaniq:access`, `neuroscaniq:refresh`) so a refresh cannot be replayed as an access token.

**API key (for programmatic clients)** — format `nsiq_<8-hex-prefix>_<32-char-secret>`. Pass via `Authorization: Bearer <key>` *or* `X-API-Key: <key>`. Only the prefix is stored unhashed; the secret is Argon2id-hashed at rest. Plaintext is shown exactly once at creation and cannot be recovered.

## Error envelope

Every non-2xx response follows the same shape:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Human-readable summary.",
    "details": { "field": "explanation" },
    "request_id": "01HXXXX..."
  }
}
```

`request_id` correlates with structured logs and the audit log; include it in bug reports.

## Rate limits

Sliding-window in Redis, plan-aware. Per-IP limits at the edge (NGINX) protect against bursts. Per-user quota headers on every response:

| Header | Meaning |
| --- | --- |
| `X-RateLimit-Limit` | Calls allowed in window |
| `X-RateLimit-Remaining` | Calls remaining |
| `X-RateLimit-Reset` | Unix seconds when window resets |

429 responses include `Retry-After`.

## Endpoints

### Health

- `GET /health` — liveness. Returns `{"status":"ok"}`.
- `GET /health/ready` — readiness; pings Postgres, Redis, OpenSearch.

### Auth

| Method | Path | Description |
| --- | --- | --- |
| POST | `/auth/register` | Create account. Body: `{ email, password, full_name }`. |
| POST | `/auth/login` | Exchange credentials for token pair. |
| POST | `/auth/refresh` | Body: `{ refresh_token }`. Returns a new pair; old refresh token's `jti` is revoked. |
| POST | `/auth/verify-email` | Body: `{ token }`. |
| POST | `/auth/password-reset/request` | Body: `{ email }`. Always returns 202, even for unknown emails (prevents enumeration). |
| POST | `/auth/password-reset/confirm` | Body: `{ token, new_password }`. |

### Users

| Method | Path | Description |
| --- | --- | --- |
| GET | `/users/me` | Current user. |
| PATCH | `/users/me` | Body: `{ full_name? }`. |
| POST | `/users/me/password` | Body: `{ current_password, new_password }`. |

### API keys

| Method | Path | Description |
| --- | --- | --- |
| GET | `/api-keys` | List your keys (no secrets). |
| POST | `/api-keys` | Body: `{ name }`. Returns `plaintext_key` once. |
| DELETE | `/api-keys/{id}` | Revoke. |

### Search

`GET /search`

Query params: `q` (string, Shodan-style), `page` (default 1), `page_size` (default 25, max 100), `sort` (`risk` \| `recent` \| `relevance`).

Supported filter keys in `q`:

- `port:443`, `port:80,443`
- `country:US`, `country:DE`
- `org:"Cloudflare"`, `asn:13335`
- `product:nginx`, `version:1.18`
- `tls.subject_cn:example.com`, `tls.issuer:Let's Encrypt`
- `tag:exposed_database`
- `risk:high`, `risk:critical`
- Free text matches HTTP titles, banners, server headers.

Returns:

```json
{
  "total": 41832,
  "page": 1,
  "page_size": 25,
  "took_ms": 142,
  "hits": [ { "ip": "...", "ports": [...], "risk_score": 78.2, ... } ],
  "facets": [ { "name": "country", "buckets": [ { "key": "US", "count": 9012 } ] } ],
  "query": "port:443 country:US"
}
```

### Hosts

| Method | Path | Description |
| --- | --- | --- |
| GET | `/hosts/{ip}` | Full host detail, services, TLS, HTTP, risk factors, AI summary. |
| GET | `/hosts/{ip}/history` | Append-only `HostObservation` rows. |
| GET | `/hosts/{ip}/screenshots` | Captured screenshots with presigned URLs (expire in 15 min). |

### Monitor

All `/monitor/*` endpoints require an authenticated user and enforce ownership-proof gating.

| Method | Path | Description |
| --- | --- | --- |
| GET | `/monitor/assets` | List assets owned by current user / org. |
| POST | `/monitor/assets` | Body: `{ kind: "ip"\|"cidr"\|"domain"\|"asn", value, label? }`. Status starts as `pending`. |
| DELETE | `/monitor/assets/{id}` | Revoke. |
| GET | `/monitor/assets/{id}/proofs` | Ownership proof attempts. |
| POST | `/monitor/assets/{id}/proofs` | Body: `{ method }`. Returns instructions + `expected_value`. |
| POST | `/monitor/assets/{id}/proofs/{proof_id}/verify` | Trigger verification check. |
| GET | `/monitor/monitors` | Active monitors. |
| POST | `/monitor/monitors` | Body: `{ asset_id, cadence: "hourly"\|"daily"\|"weekly" }`. Fails if asset not verified. |
| PATCH | `/monitor/monitors/{id}` | Body: `{ is_active?, cadence? }`. |
| DELETE | `/monitor/monitors/{id}` | Stop monitor. |

### Alerts

| Method | Path | Description |
| --- | --- | --- |
| GET | `/alerts` | Query: `unread_only`, `severity`, `limit`, `offset`. |
| POST | `/alerts/{id}/read` | Mark read. |
| POST | `/alerts/{id}/resolve` | Mark resolved. |

### Screenshots

| Method | Path | Description |
| --- | --- | --- |
| GET | `/screenshots` | Query: `q`, `technology`, `limit`, `offset`. Image URLs are presigned. |

### Billing

| Method | Path | Description |
| --- | --- | --- |
| GET | `/billing/subscription` | Current plan + quotas. |
| POST | `/billing/checkout` | Body: `{ plan: "pro"\|"enterprise" }`. Returns Stripe checkout URL. |
| POST | `/billing/portal` | Returns Stripe customer portal URL. |
| POST | `/billing/webhook` | Stripe webhook receiver. Verifies signature; updates `Subscription` rows. |

### Admin (role = admin only)

| Method | Path | Description |
| --- | --- | --- |
| GET | `/admin/stats` | Platform counters + queue depths. |
| GET | `/admin/users` | List users (paginated). |
| PATCH | `/admin/users/{id}` | Toggle `is_active`, role. |
| GET | `/admin/audit-log` | Most recent audit entries. |

## Plan quotas

| Plan | Searches/month | API calls/month | Monitors |
| --- | --- | --- | --- |
| `free` | 100 | 1,000 | 1 |
| `pro` | 10,000 | 100,000 | 25 |
| `enterprise` | 1,000,000 | 5,000,000 | 1,000 |

## Defensive posture

The platform refuses to issue probes against:

- RFC 1918 private space (10/8, 172.16/12, 192.168/16)
- Loopback (127/8, ::1)
- Link-local (169.254/16, fe80::/10)
- Multicast / reserved ranges
- Any public target not in `ALLOWED_SCAN_CIDRS` and not backed by a verified ownership proof

This check lives in `app/core/scan_guard.py` and is invoked unconditionally as the first step of every worker job. See `tests/test_scan_guard.py`.
