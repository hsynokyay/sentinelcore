#!/bin/bash
# SentinelCore Local Bring-Up Script
# One-command local demo startup for macOS (Homebrew-based).
#
# Prerequisites: Homebrew installed.
# Installs and starts: PostgreSQL 16, Redis, NATS (with JetStream).
# Runs migrations, seeds demo data, starts backend, prints next steps.

set -e

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

export PATH="/opt/homebrew/bin:/opt/homebrew/opt/postgresql@16/bin:$PATH"

echo "==> SentinelCore Local Bring-Up"
echo ""

# 1. Install infrastructure if missing
echo "==> Checking infrastructure..."
if ! brew list postgresql@16 &>/dev/null; then
  echo "    Installing postgresql@16..."
  brew install postgresql@16
fi
if ! brew list redis &>/dev/null; then
  echo "    Installing redis..."
  brew install redis
fi
if ! brew list nats-server &>/dev/null; then
  echo "    Installing nats-server..."
  brew install nats-server
fi

# 2. Start services
echo "==> Starting services..."
brew services start postgresql@16 >/dev/null 2>&1 || true
brew services start redis >/dev/null 2>&1 || true

# NATS as background process (not a brew service to avoid conflicts with JetStream flags)
if ! pgrep -x nats-server >/dev/null; then
  nats-server -js -p 4222 >/tmp/sentinelcore-nats.log 2>&1 &
  echo "    NATS started (pid $!)"
fi

sleep 2

# 3. Verify services
pg_isready >/dev/null 2>&1 || { echo "PostgreSQL not ready"; exit 1; }
redis-cli ping >/dev/null 2>&1 || { echo "Redis not ready"; exit 1; }
pgrep -x nats-server >/dev/null || { echo "NATS not running"; exit 1; }
echo "    PostgreSQL + Redis + NATS ready"

# 4. Create database and user
echo "==> Setting up database..."
createdb sentinelcore 2>/dev/null || true
createuser sentinelcore 2>/dev/null || true
psql -d sentinelcore -c "ALTER USER sentinelcore WITH PASSWORD 'dev-password';" >/dev/null 2>&1
psql -d sentinelcore -c "GRANT ALL ON DATABASE sentinelcore TO sentinelcore;" >/dev/null 2>&1
psql -d sentinelcore -c "ALTER DATABASE sentinelcore OWNER TO sentinelcore;" >/dev/null 2>&1

# 5. Run migrations (idempotent — most use IF NOT EXISTS)
echo "==> Running migrations..."
MIGRATION_STATE=$(psql -U sentinelcore -d sentinelcore -tAc "SELECT to_regclass('core.organizations');" 2>/dev/null || echo "")
if [ -z "$MIGRATION_STATE" ]; then
  for f in migrations/*.up.sql; do
    psql -U sentinelcore -d sentinelcore -f "$f" >/dev/null 2>&1 || true
  done
  echo "    Migrations applied"
else
  echo "    Schema already exists, skipping migrations"
fi

# 6. Seed demo data (idempotent)
echo "==> Seeding demo data..."
USER_COUNT=$(psql -U sentinelcore -d sentinelcore -tAc "SELECT count(*) FROM core.users;" 2>/dev/null || echo "0")
if [ "$USER_COUNT" = "0" ]; then
  psql -U sentinelcore -d sentinelcore -f scripts/seed.sql >/dev/null 2>&1
  # Set correct bcrypt hash for all demo users (password: SentinelDemo1!)
  HASH='$2a$12$6BetzYELAgBOrgh86UgCAuY5VkhT5iSYj.K2ZjLMvICUmxxgBlqDa'
  psql -U sentinelcore -d sentinelcore -c "UPDATE core.users SET password_hash = '$HASH';" >/dev/null 2>&1
  echo "    Demo data seeded (4 users, 25 findings, 5 surface entries)"
else
  echo "    Demo data already loaded"
fi

# 7. Start backend in background
echo "==> Starting control plane..."
lsof -ti:8080 | xargs kill 2>/dev/null || true
lsof -ti:9090 | xargs kill 2>/dev/null || true
sleep 1

CORS_ORIGIN="http://localhost:3000" \
  MSG_SIGNING_KEY="dev-signing-key-change-me" \
  nohup go run cmd/controlplane/main.go >/tmp/sentinelcore-api.log 2>&1 &
BACKEND_PID=$!
sleep 4

if curl -s http://localhost:8080/healthz | grep -q '"ok"'; then
  echo "    Control plane running on :8080 (pid $BACKEND_PID)"
else
  echo "    Control plane failed to start. See /tmp/sentinelcore-api.log"
  exit 1
fi

echo ""
echo "=============================================================="
echo "  SentinelCore is running!"
echo "=============================================================="
echo ""
echo "  Backend API:      http://localhost:8080"
echo "  Health check:     http://localhost:8080/healthz"
echo "  Metrics:          http://localhost:9090/metrics"
echo ""
echo "  Login credentials:"
echo "    admin@sentinel.io    / SentinelDemo1!  (platform_admin)"
echo "    secadmin@sentinel.io / SentinelDemo1!  (security_admin)"
echo "    analyst@sentinel.io  / SentinelDemo1!  (appsec_analyst)"
echo "    auditor@sentinel.io  / SentinelDemo1!  (auditor)"
echo ""
echo "  Next: start the frontend in a second terminal:"
echo "    cd web && npm install && npm run dev -- --webpack"
echo ""
echo "  Then open:  http://localhost:3000"
echo ""
echo "  Log file:   /tmp/sentinelcore-api.log"
echo "  Stop:       scripts/local-teardown.sh"
echo "=============================================================="
