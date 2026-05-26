# Docker Deployment Guide

Run Cygor with Docker Compose: the app container plus a PostgreSQL service. SQLite is used automatically if PostgreSQL is unavailable.

## Quick Start

### Production

```bash
git clone https://github.com/tjnull/cygor
cd cygor

# Default ports + settings
docker compose up --build

# Or use the wrapper script (auto-handles port conflicts)
./docker-compose-up.sh up --build
```

Open `http://localhost:8080`.

### Development (source mounted, hot-reload)

```bash
./docker-compose-up.sh dev up --build
# or:
docker compose -f docker-compose-dev.yaml up --build
```

## Compose services

### PostgreSQL

| Setting | Value |
|---|---|
| Image | `postgres:17-alpine` |
| Container | `cygor-postgres` (prod) / `cygor-postgres-dev` (dev) |
| Database | `cygor` |
| User | `cygor` |
| Password | `cygorpass` *(change for any non-toy deployment)* |
| Container port | `5432` (host port configurable, see below) |

### Cygor app

| Setting | Value |
|---|---|
| Image | Built from `Dockerfile` |
| Container | `cygor` (prod) / `cygor-dev` (dev) |
| Port | `8080` |
| Volumes | results + per-user config (see below) |

## Volumes

### Results volume

```yaml
volumes:
  - ${CYGOR_RESULTS_PATH:-./results}:/opt/cygor/results
```

Default: `./results` on host → `/opt/cygor/results` in the container. Override:

```bash
CYGOR_RESULTS_PATH=/opt/cygor-data docker compose up --build
```

### Per-user config volume

```yaml
volumes:
  - ${CYGOR_CONFIG_PATH:-./cygor-config}:/root/.cygor
```

Stores workspaces, installed plugins, and other per-user state under `/root/.cygor` in the container.

## Environment variables

| Variable | What it does |
|---|---|
| `CYGOR_RESULTS_PATH` | Host path for results volume (default: `./results`) |
| `CYGOR_RESULTS_DIR` | Results dir inside the container (default: `/opt/cygor/results`) |
| `CYGOR_WORKSPACE` | Active workspace directory (default: `/opt/cygor/results`) |
| `CYGOR_DB_URL` | DB connection string (auto-set by compose to point at the postgres service) |
| `CYGOR_DB_USER` | Postgres user (default: `cygor`) |
| `CYGOR_DB_PASSWORD` | Postgres password |
| `POSTGRES_HOST_PORT` | Host port for Postgres (resolves port conflicts) |
| `CYGOR_DEBUG` | `1` enables debug logging |
| `CYGOR_VERBOSE` | `0` normal / `1` verbose / `2` debug |

## Port configuration

| Profile | PostgreSQL host port | Cygor host port |
|---|---|---|
| Production | `5432` (if free) | `8080` |
| Development | `5434` (if free) | `8080` |
| Container-internal | `5432` (always) | `8080` (always) |

Pick a different Postgres host port without editing yaml:

```bash
POSTGRES_HOST_PORT=5435 docker compose up
```

The wrapper script auto-detects conflicts:

```bash
./docker-compose-up.sh up --build
```

## Production deployment

### 1. Replace default DB credentials

Edit `docker-compose.yaml`:

```yaml
services:
  postgres:
    environment:
      POSTGRES_USER: your_secure_user
      POSTGRES_PASSWORD: your_secure_password

  cygor:
    environment:
      - CYGOR_DB_URL=postgresql+psycopg_async://your_secure_user:your_secure_password@postgres:5432/cygor
```

### 2. Front with a reverse proxy (HTTPS)

The OSS web UI listens on plain HTTP. Terminate TLS at nginx/Traefik/Caddy:

```nginx
server {
    listen 443 ssl;
    server_name cygor.example.com;

    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

> The OSS edition has no authentication. Anyone who can reach the listener has full access — keep it behind a VPN, a reverse proxy with `auth_basic`, or `127.0.0.1` only.

### 3. Persistent volumes

```yaml
volumes:
  cygor-postgres-data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /opt/cygor/postgres-data
```

### 4. Resource limits

```yaml
services:
  cygor:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
```

## Development setup

### Hot reload

The dev compose file mounts the source tree:

```yaml
volumes:
  - ./cygor:/opt/cygor/cygor
```

Changes to source are visible immediately (a restart may be needed for some changes).

### Debug mode

```bash
CYGOR_DEBUG=1 CYGOR_VERBOSE=2 docker compose -f docker-compose-dev.yaml up
```

### Logs

```bash
docker compose logs -f                    # all services
docker compose logs -f cygor              # just cygor
docker compose logs --tail=100 cygor      # last 100 lines
```

## Managing containers

```bash
docker compose up -d        # detached start
docker compose down         # stop + remove
docker compose restart      # restart
docker compose ps           # status
```

Exec into the container:

```bash
docker exec -it cygor bash
docker exec cygor cygor --help
docker exec cygor tail -f /opt/cygor/results/cygor-web.log
```

## Backup & restore

### Database

```bash
# Dump
docker compose exec postgres pg_dump -U cygor cygor > backup.sql

# Restore
cat backup.sql | docker compose exec -T postgres psql -U cygor cygor
```

### Volumes

```bash
tar -czf results-backup.tar.gz ./results
tar -czf config-backup.tar.gz ./cygor-config
docker run --rm -v cygor_cygor-postgres-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/postgres-backup.tar.gz /data
```

## Manual single-container

If you don't need the compose Postgres service (SQLite fallback is fine):

```bash
docker build -t cygor .

docker run --rm \
  -v ./results:/opt/cygor/results \
  -e CYGOR_RESULTS_DIR=/opt/cygor/results \
  -p 8080:8080 \
  cygor web --host 0.0.0.0 --port 8080 --load-dir /opt/cygor/results
```

## Troubleshooting

### Container won't start

```bash
docker compose logs cygor
docker compose ps postgres
docker volume ls
```

### Database connection issues

```bash
docker compose exec postgres psql -U cygor -d cygor -c "SELECT 1;"
docker compose exec cygor env | grep CYGOR_DB
```

### Permission issues on bind mounts

```bash
sudo chown -R $USER:$USER ./results ./cygor-config
```

### Port already in use

```bash
sudo lsof -i :8080
# Edit docker-compose.yaml's ports section, or:
POSTGRES_HOST_PORT=5435 docker compose up
```

## Next Steps

- [Setting Up Workspaces](Setting-Up-Workspaces.md) — workspaces inside containerized installs
- [Web UI Quick Start](Web-UI-Quick-Start.md) — what to do once the container's up
- [Common Issues](Common-Issues.md) — broader troubleshooting
