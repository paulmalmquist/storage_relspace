#!/usr/bin/env bash
# Start the synthetic gallery on macOS/Linux with PG16, Go 1.26 and Node 22.
# Its random database and login names and local keyring survive a restart.
set -euo pipefail
: "${PG_ADMIN_URL:?Set PG_ADMIN_URL to a local PostgreSQL 16 admin URL}"
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
cd "$ROOT"
export DC_LAB_STATE="${DC_LAB_STATE:-$ROOT/.strongbox-dreamcatcher}"
umask 077
mkdir -p "$DC_LAB_STATE"
node --input-type=module <<'JS'
import {readFileSync,writeFileSync,existsSync} from 'node:fs';
import {execFileSync} from 'node:child_process';
import {randomBytes} from 'node:crypto';
const u=new URL(process.env.PG_ADMIN_URL);
if(!['postgresql:','postgres:'].includes(u.protocol)||!['127.0.0.1','localhost','[::1]'].includes(u.hostname)||[...u.searchParams.keys()].some(k=>k!=='sslmode'))throw Error('Use a loopback PostgreSQL admin URL');
const file=process.env.DC_LAB_STATE+'/database.json';
let state;
if(existsSync(file)){state=JSON.parse(readFileSync(file));if(state.server!==u.origin+u.host)throw Error('This demo state belongs to another local server');}
else{
 const id=randomBytes(8).toString('hex');state={db:'dc_demo_'+id,role:'dc_api_'+id,password:randomBytes(24).toString('hex'),server:u.origin+u.host};
 writeFileSync(file,JSON.stringify(state),{mode:0o600,flag:'wx'});
}
if(!/^dc_demo_[a-f0-9]{16}$/.test(state.db)||!/^dc_api_[a-f0-9]{16}$/.test(state.role)||!/^[a-f0-9]{48}$/.test(state.password))throw Error('Invalid demo state');
const psql=sql=>execFileSync('psql',['-X',u.href,'-v','ON_ERROR_STOP=1','-Atqc',sql],{encoding:'utf8'});
if(!psql("SELECT 1 FROM pg_roles WHERE rolname='"+state.role+"'").trim())psql("CREATE ROLE "+state.role+" LOGIN PASSWORD '"+state.password+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS");
if(!psql("SELECT 1 FROM pg_database WHERE datname='"+state.db+"'").trim())psql("CREATE DATABASE "+state.db);
u.pathname='/'+state.db;
const admin=u.href;u.username=state.role;u.password=state.password;
writeFileSync(process.env.DC_LAB_STATE+'/connection.json',JSON.stringify({admin,runtime:u.href,login:state.role}),{mode:0o600});
JS
connection(){ node -e "process.stdout.write(JSON.parse(require('fs').readFileSync(process.env.DC_LAB_STATE+'/connection.json'))[process.argv[1]])" "$1"; }
export STRONGBOX_MIGRATION_DATABASE_URL="$(connection admin)" STRONGBOX_DATABASE_URL="$(connection runtime)" DC_LAB_RUNTIME_LOGIN="$(connection login)"
export STRONGBOX_ENV=dev STRONGBOX_APP_ENV=dev STRONGBOX_AUTH_MODE=dev-hs256 STRONGBOX_KMS_BACKEND=local STRONGBOX_BLOB_BACKEND=local
export STRONGBOX_DEV_JWT_SECRET="$(node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))")"
export SB_BIN="$DC_LAB_STATE/strongbox"
go build -o "$SB_BIN" ./cmd/strongbox
if [[ "${1:-}" == "--test" ]]; then exec node --test examples/dreamcatcher/host/identity.test.mjs examples/dreamcatcher/lab/contract.test.mjs; fi
exec node examples/dreamcatcher/lab/start.mjs
