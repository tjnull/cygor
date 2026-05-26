#!/bin/bash
# Wrapper script to check PostgreSQL port and start docker-compose

set -e

# Determine which compose file to use
COMPOSE_FILE="${1:-docker-compose.yaml}"
if [ "$COMPOSE_FILE" = "dev" ] || [ "$COMPOSE_FILE" = "docker-compose-dev.yaml" ]; then
    COMPOSE_FILE="docker-compose-dev.yaml"
    DEFAULT_PORT=5434
else
    COMPOSE_FILE="docker-compose.yaml"
    DEFAULT_PORT=5432
fi

echo "[*] Checking PostgreSQL port availability..."

# Auto-detect an available host port for PostgreSQL.
if command -v netstat >/dev/null 2>&1; then
    if netstat -tuln 2>/dev/null | grep -q ":${DEFAULT_PORT} "; then
        echo "[!] Port $DEFAULT_PORT is in use, trying alternative ports..."
        for port in $(seq $((DEFAULT_PORT + 1)) $((DEFAULT_PORT + 10))); do
            if ! netstat -tuln 2>/dev/null | grep -q ":$port "; then
                POSTGRES_HOST_PORT=$port
                echo "[*] Found available port: $POSTGRES_HOST_PORT"
                break
            fi
        done
        POSTGRES_HOST_PORT=${POSTGRES_HOST_PORT:-$DEFAULT_PORT}
    else
        POSTGRES_HOST_PORT=$DEFAULT_PORT
    fi
elif command -v ss >/dev/null 2>&1; then
    if ss -tuln 2>/dev/null | grep -q ":${DEFAULT_PORT} "; then
        echo "[!] Port $DEFAULT_PORT is in use, trying alternative ports..."
        for port in $(seq $((DEFAULT_PORT + 1)) $((DEFAULT_PORT + 10))); do
            if ! ss -tuln 2>/dev/null | grep -q ":$port "; then
                POSTGRES_HOST_PORT=$port
                echo "[*] Found available port: $POSTGRES_HOST_PORT"
                break
            fi
        done
        POSTGRES_HOST_PORT=${POSTGRES_HOST_PORT:-$DEFAULT_PORT}
    else
        POSTGRES_HOST_PORT=$DEFAULT_PORT
    fi
else
    POSTGRES_HOST_PORT=$DEFAULT_PORT
    echo "[*] Port checking tools not available, using default: $POSTGRES_HOST_PORT"
fi
export POSTGRES_HOST_PORT

echo "[*] Starting docker-compose with PostgreSQL host port: $POSTGRES_HOST_PORT"
echo "[*] Note: Internal connection (cygor -> postgres) uses port 5432 (Docker network)"
echo ""

# Shift to remove the compose file argument if it was provided
if [ "$1" = "dev" ] || [ "$1" = "docker-compose-dev.yaml" ]; then
    shift
fi

# Pass remaining arguments to docker compose
docker compose -f "$COMPOSE_FILE" "$@"

