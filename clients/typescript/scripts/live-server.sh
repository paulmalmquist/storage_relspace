#!/usr/bin/env bash
# Starts a throwaway Strongbox (fresh database, restricted runtime login, local keys and blobs) for
# the contract tests and the example, and prints the environment they need.
#
#   PG_ADMIN_URL=postgres://postgres:pw@localhost:5432/postgres scripts/live-server.sh > .live.env
#   . ./.live.env && npm test && npm run example
#   kill "$STRONGBOX_PID"
set -euo pipefail
: "${PG_ADMIN_URL:?set PG_ADMIN_URL to a superuser URL (any database)}"
PORT="${PORT:-18181}"
DB="${STRONGBOX_LIVE_DB:-strongbox_contract}"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
WORK="$(mktemp -d)"
go build -o "$WORK/strongbox" "$ROOT/cmd/strongbox" >&2

psql "$PG_ADMIN_URL" -v ON_ERROR_STOP=1 -q >&2 <<SQL
DROP DATABASE IF EXISTS $DB;
CREATE DATABASE $DB;
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'strongbox_contract_api') THEN
    CREATE ROLE strongbox_contract_api LOGIN PASSWORD 'contract-api';
  END IF;
END \$\$;
SQL

admin_url() { # same server and credentials as PG_ADMIN_URL, database $DB
  local base="${PG_ADMIN_URL%%\?*}" query=""
  [[ "$PG_ADMIN_URL" == *\?* ]] && query="?${PG_ADMIN_URL#*\?}"
  echo "${base%/*}/$DB$query"
}
HOSTPART="$(psql "$PG_ADMIN_URL" -Atc "SELECT coalesce(inet_server_addr()::text, 'localhost') || ':' || current_setting('port')")"
export STRONGBOX_ENV=dev STRONGBOX_APP_ENV=dev
export STRONGBOX_MIGRATION_DATABASE_URL="$(admin_url)"
export STRONGBOX_DATABASE_URL="postgres://strongbox_contract_api:contract-api@${HOSTPART/\/32/}/$DB?sslmode=disable"
export STRONGBOX_DEV_JWT_SECRET="contract-secret-0123456789abcdef0123456789"
export STRONGBOX_LOCAL_KEYRING_PATH="$WORK/keyring.json" STRONGBOX_BLOB_LOCAL_PATH="$WORK/blobs"
export STRONGBOX_UPLOAD_PART_BYTES=65536 STRONGBOX_RATE_SUBJECT_PER_SECOND=0 STRONGBOX_RATE_APP_PER_SECOND=0

SB="$WORK/strongbox"
"$SB" init -bootstrap-roles -runtime-login strongbox_contract_api >&2
for who in alice bob carol; do
  "$SB" principal put "$who@example.com" -scope '*' -us-person -cui-access -category '*' >&2
done
"$SB" admin app create demo:dev -name Demo -admin alice@example.com >&2
"$SB" admin member set demo:dev bob@example.com member >&2
"$SB" admin member set demo:dev carol@example.com member >&2
"$SB" serve -addr "127.0.0.1:$PORT" > "$WORK/serve.log" 2>&1 &
PID=$!
for _ in $(seq 50); do curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null && break; sleep 0.2; done
curl -sf "http://127.0.0.1:$PORT/healthz" >/dev/null || { cat "$WORK/serve.log" >&2; exit 1; }

cat <<ENV
export STRONGBOX_URL=http://127.0.0.1:$PORT
export STRONGBOX_APP=demo
export STRONGBOX_TOKEN_ALICE=$("$SB" token alice@example.com)
export STRONGBOX_TOKEN_BOB=$("$SB" token bob@example.com)
export STRONGBOX_TOKEN_CAROL=$("$SB" token carol@example.com)
export STRONGBOX_PID=$PID
export STRONGBOX_LOG=$WORK/serve.log
ENV
