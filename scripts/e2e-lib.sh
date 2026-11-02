#!/usr/bin/env bash
# Shared helpers of the end-to-end scripts. Source it; it starts an isolated
# backend (own data dir, random ports) and cleans everything up on exit.
set -euo pipefail

BIN="${1:-bin/keywayd}"
ROOT="$(mktemp -d)"
DIR="$ROOT/data"
mkdir -p "$DIR"
PIDS=""
cleanup() {
  local rc=$?
  for p in $PIDS; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  if [ "$rc" != 0 ] && [ -f "$ROOT/backend.log" ]; then
    echo "--- backend log (tail) ---"; tail -40 "$ROOT/backend.log"
    for f in "$ROOT"/*.log; do echo "--- $(basename "$f") (tail) ---"; tail -15 "$f"; done
  fi
  rm -rf "$ROOT"
  exit "$rc"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }
ok() { echo "ok   $*"; }
free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }
bg() { "$@" & PIDS="$PIDS $!"; }
wait_port() { # wait_port PORT
  local i
  for i in $(seq 1 100); do
    python3 -c "import socket,sys; socket.create_connection(('127.0.0.1',$1),0.2)" 2>/dev/null && return 0
    sleep 0.1
  done
  fail "nothing listens on port $1"
}

API_PORT="$(free_port)"; SOCKS_PORT="$(free_port)"; HTTP_PORT="$(free_port)"

start_backend() {
  bg "$BIN" -port "$API_PORT" -data-dir "$DIR" >"$ROOT/backend.log" 2>&1
  local i
  for i in $(seq 1 100); do [ -s "$DIR/api-token" ] && break; sleep 0.1; done
  TOKEN="$(cat "$DIR/api-token")"
  B="http://127.0.0.1:$API_PORT"
}

# api METHOD PATH [JSON]: prints the body.
api() {
  local m="$1" p="$2" d="${3:-}"
  if [ -n "$d" ]; then
    curl -s -m 240 -X "$m" -H "X-Keyway-Token: $TOKEN" -H 'Content-Type: application/json' -d "$d" "$B$p"
  else
    curl -s -m 240 -X "$m" -H "X-Keyway-Token: $TOKEN" -H 'Content-Type: application/json' "$B$p"
  fi
}
jget() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; } # jget EXPR (d = parsed stdin)

# set_settings PYTHON-STATEMENTS: edits the settings object s and saves it.
set_settings() {
  local cur new
  cur="$(api GET /api/settings)"
  new="$(echo "$cur" | python3 -c "
import sys,json
d=json.load(sys.stdin); s=d.get('settings',d)
$1
print(json.dumps(s))")"
  local res
  res="$(api POST /api/settings "$new")"
  [ "$(echo "$res" | jget "d.get('ok')")" = True ] || fail "save settings: $res"
}

# use_ports: the local proxy ports of the test, never the defaults of a Keyway the developer runs.
use_ports() {
  set_settings "
for i in s['inbounds']:
    if i['tag']=='socks-in': i['port']=$SOCKS_PORT
    if i['tag']=='http-in': i['port']=$HTTP_PORT
    if i['tag']=='mixed-extra': i['enabled']=False
s['routingMode']='global'
s['autoSystemProxy']=False
$1"
}

add_node() { # add_node NAME PROFILE-JSON -> node id
  api POST /api/nodes "{\"name\":\"$1\",\"profile\":$2}" | jget "d['node']['id']"
}
connect_to() { # connect_to NODE-ID
  api POST /api/active "{\"id\":\"$1\"}" >/dev/null
  [ "$(api POST /api/connect | jget "d.get('ok')")" = True ] || fail "connect failed"
}
disconnect() { api POST /api/disconnect >/dev/null; }
running_label() { api GET /api/status | jget "d.get('engineLabel','')"; }
