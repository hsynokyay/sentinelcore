#!/bin/bash
# SentinelCore Local Teardown — stops backend, frontend, and NATS.
# Does NOT stop PostgreSQL/Redis (keeps data intact).

set -e

echo "==> Stopping SentinelCore..."

lsof -ti:8080 | xargs kill 2>/dev/null && echo "    Backend stopped" || echo "    Backend not running"
lsof -ti:9090 | xargs kill 2>/dev/null || true
lsof -ti:3000 | xargs kill 2>/dev/null && echo "    Frontend stopped" || echo "    Frontend not running"
pkill -x nats-server 2>/dev/null && echo "    NATS stopped" || echo "    NATS not running"

echo ""
echo "PostgreSQL and Redis left running. To fully stop:"
echo "  brew services stop postgresql@16"
echo "  brew services stop redis"
