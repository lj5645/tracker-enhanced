#!/bin/bash
set -euo pipefail

echo "=== Aquatic Tracker Monitoring Setup ==="

if ! command -v docker >/dev/null 2>&1; then
    echo "Docker is required. Install it first: https://docs.docker.com/engine/install/" >&2
    exit 1
fi

if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
else
    echo "Docker Compose is required (docker compose plugin or docker-compose)." >&2
    exit 1
fi

if [ -z "${GRAFANA_ADMIN_PASSWORD:-}" ]; then
    echo "Set GRAFANA_ADMIN_PASSWORD before running this script." >&2
    echo "Example: GRAFANA_ADMIN_PASSWORD='strong-password' ./monitoring/setup.sh" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "Starting Prometheus and Grafana..."
"${COMPOSE[@]}" up -d

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Services:"
echo "  - Prometheus: http://localhost:9090"
echo "  - Grafana:    http://localhost:3001"
echo ""
echo "Grafana login: admin / (the password you supplied)"
echo ""
echo "To stop services: cd monitoring && ${COMPOSE[*]} down"
echo "To view logs:     cd monitoring && ${COMPOSE[*]} logs -f"
