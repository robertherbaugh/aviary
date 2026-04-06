# Setup

## Prerequisites

- Node.js 22+
- Bun 1.3+
- uv
- Python 3.13+
- Docker (optional for local postgres)

## Local development

1. `cp docker/.env.example .env`
2. `docker compose -f docker/docker-compose.yml up -d postgres`
3. `bun install`
4. `bun run db:migrate:dev -- --name init` (or rely on API startup migration deploy)
5. `bun run db:generate`
6. `bun run db:seed`
7. Start services:
   - API: `bun --filter=@aviary/api run dev`
   - Web: `bun --filter=@aviary/web run dev`
   - Worker: `cd apps/worker && uv sync && uv run aviary-worker`
8. First auth flow:
   - If no users exist, open `http://localhost:3000/setup` to create the first admin
   - The setup page auto-detects and stores WebAuthn (`rpId`, `rpName`, `origin`) and TOTP issuer defaults in `app_config`
   - Then sign in at `http://localhost:3000/sign-in`
   - Optional TOTP MFA, WebAuthn passkeys, and OIDC SSO can be configured from `Automation Settings -> Security` in the web UI

## OIDC redirect URI defaults

When `OIDC_REDIRECT_URI` is not set in DB/env, the API derives a default callback URI from `AVIARY_DOMAIN`:
- Development (`NODE_ENV=development`): `http://<AVIARY_DOMAIN>/api/v1/auth/oidc/callback`
- Non-development: `https://<AVIARY_DOMAIN>/api/v1/auth/oidc/callback`

You can still set `OIDC_REDIRECT_URI` (or the redirect override in UI) to force an explicit value.

## WebAuthn configuration

For passkeys in non-localhost deployments, you can configure:
- `WEBAUTHN_RP_ID` (your domain, e.g. `aviary.example.com`)
- `WEBAUTHN_RP_NAME` (display name in authenticator prompts)
- `WEBAUTHN_ORIGIN` (full HTTPS origin, e.g. `https://aviary.example.com`)

These are optional when the request host/origin can be inferred; first-run setup can persist resolved defaults to `app_config`.

`MIGRATE_ON_STARTUP=true` (default) makes the API run `prisma migrate deploy` before listening.

## Production HTTPS / Traefik deployment

Aviary ships a `docker/docker-compose.traefik.yml` for production deployments that terminate TLS at an external [Traefik](https://traefik.io/) reverse proxy using Let's Encrypt certificates.

### Prerequisites

- A publicly reachable domain (e.g. `aviary.example.com`) with DNS pointing to your server.
- An external Docker network that Traefik is attached to (default name: `traefik`).
- Traefik configured with:
  - An `http` entrypoint on port 80 (for ACME HTTP-01 challenge and HTTP→HTTPS redirect).
  - A `websecure` entrypoint on port 443 (TLS).
  - A `letsencrypt` certificate resolver pointing at the Let's Encrypt ACME API, with a valid contact email:
    ```yaml
    # traefik static config (traefik.yml / CLI flags)
    certificatesResolvers:
      letsencrypt:
        acme:
          email: you@example.com          # required by Let's Encrypt
          storage: /letsencrypt/acme.json
          httpChallenge:
            entryPoint: web
    ```
  - A global HTTP→HTTPS redirect (recommended — configure once in Traefik's static config):
    ```yaml
    entryPoints:
      web:
        address: ":80"
        http:
          redirections:
            entryPoint:
              to: websecure
              scheme: https
              permanent: true
      websecure:
        address: ":443"
    ```

### Deployment steps

1. Copy and edit the stack environment file:
   ```bash
   cp docker/stack.env.example docker/stack.env
   ```
   Mandatory values to change:

   | Variable | Description |
   |---|---|
   | `AVIARY_DOMAIN` | Your public domain, e.g. `aviary.example.com` |
   | `POSTGRES_PASSWORD` | Strong random password |
   | `DATABASE_URL` | Must match `POSTGRES_PASSWORD` above |
   | `JWT_SECRET` | 32+ random bytes (e.g. `openssl rand -hex 32`) |
   | `CREDENTIAL_ENCRYPTION_KEY` | 32-char hex key for secret encryption (change from default!) |
   | `INTERNAL_API_TOKEN` | Shared secret between API and worker (change from default!) |
   | `LOCAL_BOOTSTRAP_ADMIN_PASSWORD` | Initial admin password (change immediately after first login) |
   | `TRAEFIK_CERTRESOLVER` | Name of the Traefik cert resolver (default: `letsencrypt`) |
   | `TRAEFIK_NETWORK` | External Docker network Traefik is attached to (default: `traefik`) |

2. Start the stack:
   ```bash
   docker compose -f docker/docker-compose.traefik.yml --env-file docker/stack.env up -d
   ```

3. First auth flow: open `https://<AVIARY_DOMAIN>/setup` to create the first admin account.

### How TLS works in this setup

- Traefik obtains and auto-renews certificates from Let's Encrypt via ACME HTTP-01.
- The API and web containers are reached only through the internal `traefik` Docker network; port 443 is never exposed directly from the containers.
- `NEXT_PUBLIC_API_BASE_URL` is hardcoded to `https://${AVIARY_DOMAIN}` in the compose file, so all frontend API calls use HTTPS.

### Cookie / token security note

Aviary uses **JWT Bearer tokens** (sent via `Authorization: Bearer …` headers), not HTTP cookies, for session authentication. There is therefore no `Secure` cookie flag to configure. Tokens are stored and transmitted by the frontend application and are never stored in browser cookies.

### Security hardening checklist

- [ ] Replace all `change-me` / `internal-token` / `0123456789abcdef…` placeholder values in `stack.env` before deploying.
- [ ] Ensure `JWT_SECRET` is at least 32 random bytes and kept secret.
- [ ] Ensure `CREDENTIAL_ENCRYPTION_KEY` is a unique 32-char hex value (not the example default).
- [ ] Confirm Traefik's ACME email address is a real, monitored address (Let's Encrypt sends expiry warnings there).
- [ ] Enable Traefik's global HTTP→HTTPS redirect so plain-HTTP requests are always upgraded.
- [ ] Restrict access to the Traefik dashboard if enabled (never expose it publicly without authentication).
- [ ] Change `LOCAL_BOOTSTRAP_ADMIN_PASSWORD` immediately after the first login and disable `LOCAL_BOOTSTRAP_ADMIN=true` if not needed.

### Staging / testing ACME certificates

To avoid Let's Encrypt rate limits while testing, point the cert resolver at the ACME staging endpoint in your Traefik config:

```yaml
certificatesResolvers:
  letsencrypt:
    acme:
      caServer: https://acme-staging-v02.api.letsencrypt.org/directory
      email: you@example.com
      storage: /letsencrypt/acme.json
      httpChallenge:
        entryPoint: web
```

Staging certificates are not trusted by browsers but are structurally valid — use them to verify the full ACME flow before switching to production.

## Observability (Prometheus + Grafana)

Aviary exposes a Prometheus-compatible `/metrics` endpoint on the API server.

### Metrics exposed

| Metric | Type | Labels | Description |
|---|---|---|---|
| `http_request_duration_seconds` | Histogram | `method`, `route`, `status_code` | HTTP request latency |
| `http_requests_total` | Counter | `method`, `route`, `status_code` | Total HTTP requests |
| `job_queue_depth` | Gauge | `queue`, `state` (`pending`/`active`) | pgBoss queue depth |

Node.js default metrics (event loop lag, GC, heap, etc.) are also included courtesy of `prom-client`.

### Local dev stack

Start the full observability stack alongside the existing dev services:

```bash
docker compose \
  -f docker/docker-compose.dev.yml \
  -f docker/docker-compose.observability.yml \
  up
```

- **Prometheus** — `http://localhost:9090`
- **Grafana** — `http://localhost:3001` (login: `admin` / `admin`)

The Grafana instance is pre-provisioned with the Aviary dashboard (`docs/grafana-dashboard.json`) wired to the Prometheus datasource. No manual import is required.

To change the Grafana port set `GRAFANA_PORT` in your `.env` file.

### Importing the dashboard manually

If you are connecting to an existing Grafana instance, import `docs/grafana-dashboard.json` via **Dashboards → Import** and select your Prometheus datasource.

## PostgreSQL major upgrade reset

If you previously ran an older PostgreSQL major version (for example 16/17) and switch to PostgreSQL 18, drop the old volume before starting Postgres:

`docker compose -f docker/docker-compose.yml down -v`
