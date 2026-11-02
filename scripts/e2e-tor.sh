#!/usr/bin/env bash
# End-to-end Tor test. It needs the real Tor network, so it can be slow or flaky
# and is not a merge gate. Tor and sing-box are downloaded through Keyway's own
# download code. Usage: scripts/e2e-tor.sh [path/to/keywayd]
source "$(dirname "$0")/e2e-lib.sh"

start_backend
use_ports "s['torEnabled']=True"

echo "== engines"
for e in sing-box tor; do
  [ "$(api POST /api/engines/$e/download '{}' | jget "d.get('ok')")" = True ] || fail "download $e"
  ok "downloaded $e"
done
SB="$(ls "$DIR"/engines/sing-box/v*/sing-box | head -1)"

# Right after bootstrap Tor may still be building its first exit circuits, so
# the first requests can fail fast: retry for a while.
check_tor() { # check_tor LABEL
  local r i
  for i in $(seq 1 8); do
    r="$(curl -s -m 30 --proxy "socks5h://127.0.0.1:$SOCKS_PORT" https://check.torproject.org/api/ip || true)"
    if [ "$(echo "$r" | jget "d.get('IsTor')" 2>/dev/null || true)" = True ]; then ok "$1: exit is Tor"; return 0; fi
    sleep 4
  done
  fail "$1: the exit is not Tor ($r)"
}

echo "== plain Tor"
TOR_ID="$(add_node "E2E Tor" '{"protocol":"tor","tor":{"bridges":"none"}}')"
connect_to "$TOR_ID"
[ "$(running_label)" = "Tor + sing-box" ] || fail "expected Tor + sing-box, got '$(running_label)'"
check_tor "plain Tor"
# Hidden services are slow and a single site can be down: try two, a few times.
CODE=000
for attempt in 1 2 3; do
  for site in 2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion; do
    CODE="$(curl -s -m 60 -o /dev/null -w '%{http_code}' --proxy "socks5h://127.0.0.1:$SOCKS_PORT" "http://$site/" || true)"
    case "$CODE" in 2??|3??) break 2 ;; esac
  done
done
case "$CODE" in 2??|3??) ;; *) fail "no .onion page loaded (last HTTP $CODE): hostnames must reach Tor unresolved" ;; esac
ok ".onion page loaded"
disconnect

echo "== chain: Shadowsocks -> Tor (Tor dials its first relay through the hop)"
SS_PORT="$(free_port)"; SSPASS="e2e-password-0123456789"
cat > "$ROOT/ss.json" <<JSON
{"log":{"level":"info"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":$SS_PORT,"method":"aes-128-gcm","password":"$SSPASS"}],"outbounds":[{"type":"direct"}]}
JSON
bg "$SB" run -c "$ROOT/ss.json" >"$ROOT/server-ss.log" 2>&1
wait_port "$SS_PORT"
SS_ID="$(add_node "E2E hop" "{\"protocol\":\"shadowsocks\",\"server\":\"127.0.0.1\",\"port\":$SS_PORT,\"cipher\":\"aes-128-gcm\",\"password\":\"$SSPASS\"}")"
CH="$(api POST /api/nodes "{\"name\":\"E2E hop to Tor\",\"chain\":[\"$SS_ID\",\"$TOR_ID\"]}" | jget "d['node']['id']")"
connect_to "$CH"
check_tor "chain through a hop"
grep -q "outbound connection to" "$ROOT/server-ss.log" || fail "Tor's connections did not go through the first hop"
ok "Tor's relay connections went through the first hop"
disconnect

echo "== chain rules"
BAD="$(api POST /api/chains/plan "{\"chain\":[\"$TOR_ID\",\"$TOR_ID\"]}")"
[ "$(echo "$BAD" | jget "d.get('ok')")" = False ] || fail "two Tor hops must be refused: $BAD"
ok "a chain with two Tor hops is refused"

echo "== turning Tor off"
connect_to "$TOR_ID"
set_settings "s['torEnabled']=False"
[ "$(api GET /api/status | jget "d['running']")" = False ] || fail "turning Tor off must disconnect"
[ "$(api GET /api/engines | grep -c '"name":"tor"' || true)" = 0 ] || fail "Tor engine still listed"
[ "$(api GET /api/nodes | grep -c '"protocol":"tor"' || true)" = 0 ] || fail "Tor nodes still listed"
if pgrep -f "$DIR/engines/tor" >/dev/null; then fail "tor is still running"; fi
ok "Tor off: disconnected, hidden, nothing running"
echo "e2e-tor OK"
