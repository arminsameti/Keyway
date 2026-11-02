#!/usr/bin/env bash
# End-to-end test with real engines and real connections, no internet needed
# for the proxying itself: sing-box runs as the "remote" server on loopback,
# Keyway connects to it, and a page on a local web server is fetched through
# the whole path. The server's own log proves the traffic really went through it.
# Engines are downloaded through Keyway's own download code.
# Usage: scripts/e2e.sh [path/to/keywayd]
source "$(dirname "$0")/e2e-lib.sh"

start_backend
use_ports ""

echo "== engines"
for e in sing-box xray; do
  [ "$(api POST /api/engines/$e/download '{}' | jget "d.get('ok')")" = True ] || fail "download $e"
  ok "downloaded $e"
done
SB="$(ls "$DIR"/engines/sing-box/v*/sing-box | head -1)"
[ -x "$SB" ] || fail "sing-box binary not found"

echo "== fixtures"
TARGET_PORT="$(free_port)"; SS1_PORT="$(free_port)"; VL_PORT="$(free_port)"
mkdir -p "$ROOT/web" && echo "e2e-ok" > "$ROOT/web/index.html"
bg python3 -m http.server "$TARGET_PORT" --bind 127.0.0.1 --directory "$ROOT/web" >"$ROOT/target.log" 2>&1
UUID="11111111-2222-4333-8444-555555555555"
SSPASS="e2e-password-0123456789"
cat > "$ROOT/ss1.json" <<JSON
{"log":{"level":"info"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":$SS1_PORT,"method":"aes-128-gcm","password":"$SSPASS"}],"outbounds":[{"type":"direct"}]}
JSON
cat > "$ROOT/vless.json" <<JSON
{"log":{"level":"info"},"inbounds":[{"type":"vless","listen":"127.0.0.1","listen_port":$VL_PORT,"users":[{"uuid":"$UUID"}]}],"outbounds":[{"type":"direct"}]}
JSON
bg "$SB" run -c "$ROOT/ss1.json" >"$ROOT/server-ss1.log" 2>&1
bg "$SB" run -c "$ROOT/vless.json" >"$ROOT/server-vless.log" 2>&1
wait_port "$TARGET_PORT"; wait_port "$SS1_PORT"; wait_port "$VL_PORT"
ok "target page and two fixture servers are up"

fetch() { curl -s -m 30 --proxy "socks5h://127.0.0.1:$SOCKS_PORT" "http://127.0.0.1:$TARGET_PORT/"; }
# through SERVER-LOG: the server logged the connection to the target
via() { grep -q ":$TARGET_PORT" "$ROOT/$1" || fail "$1 does not show the request: traffic bypassed the server"; }

SS_PROFILE="{\"protocol\":\"shadowsocks\",\"server\":\"127.0.0.1\",\"port\":$SS1_PORT,\"cipher\":\"aes-128-gcm\",\"password\":\"$SSPASS\"}"
VL_PROFILE="{\"protocol\":\"vless\",\"server\":\"127.0.0.1\",\"port\":$VL_PORT,\"uuid\":\"$UUID\",\"encryption\":\"none\",\"transport\":{\"type\":\"tcp\"},\"security\":{\"kind\":\"none\"}}"
SS_ID="$(add_node "E2E Shadowsocks" "$SS_PROFILE")"
VL_ID="$(add_node "E2E VLESS plain" "$VL_PROFILE")"

echo "== Shadowsocks on Xray"
set_settings "s['enginePreference']='xray'"
connect_to "$SS_ID"
LABEL="$(running_label)"; [ "$LABEL" = "Xray core" ] || fail "expected Xray core, got '$LABEL'"
[ "$(fetch)" = "e2e-ok" ] || fail "page not fetched through Shadowsocks/Xray"
via server-ss1.log; ok "Shadowsocks over Xray carried the request"
disconnect

echo "== Shadowsocks on sing-box"
set_settings "s['enginePreference']='sing-box'"
connect_to "$SS_ID"
LABEL="$(running_label)"; [ "$LABEL" = "sing-box" ] || fail "expected sing-box, got '$LABEL'"
[ "$(fetch)" = "e2e-ok" ] || fail "page not fetched through Shadowsocks/sing-box"
ok "Shadowsocks over sing-box carried the request"
disconnect

echo "== plain VLESS"
# Xray refuses VLESS without TLS to a public address (it allows a private one),
# so the planner must hand a public one to sing-box. Planning only: no server there.
PUB="$(add_node "E2E public plain VLESS" "{\"protocol\":\"vless\",\"server\":\"203.0.113.9\",\"port\":443,\"uuid\":\"$UUID\",\"encryption\":\"none\",\"transport\":{\"type\":\"tcp\"},\"security\":{\"kind\":\"none\"}}")"
set_settings "s['enginePreference']='xray'"
[ "$(api GET /api/nodes | jget "[n['engine'] for n in d['nodes'] if n['id']=='$PUB'][0]")" = sing-box ] || fail "plain VLESS to a public address must be planned on sing-box"
ok "plain VLESS to a public address is planned on sing-box"
connect_to "$VL_ID"
[ "$(fetch)" = "e2e-ok" ] || fail "page not fetched through plain VLESS (loopback)"
via server-vless.log; ok "plain VLESS to a private address carried the request"
disconnect

echo "== chain: Shadowsocks -> VLESS"
CH="$(api POST /api/nodes "{\"name\":\"E2E chain\",\"chain\":[\"$SS_ID\",\"$VL_ID\"]}" | jget "d['node']['id']")"
: > "$ROOT/server-ss1.log"
connect_to "$CH"
[ "$(fetch)" = "e2e-ok" ] || fail "page not fetched through the chain"
grep -q ":$VL_PORT" "$ROOT/server-ss1.log" || fail "first hop did not carry the connection to the second hop"
via server-vless.log; ok "the chain went through both servers in order"

echo "== latency test through the engines"
LAT="$(api POST /api/latency '{"mode":"real"}')"
[ "$(echo "$LAT" | jget "d['latency']['$SS_ID'] > 0")" = True ] || fail "real latency of the Shadowsocks server: $LAT"
ok "real latency test works"

echo "== disconnect leaves nothing behind"
disconnect
sleep 1
if pgrep -f "$DIR/config" >/dev/null; then fail "an engine is still running after disconnect"; fi
[ "$(api GET /api/status | jget "d['running']")" = False ] || fail "status still running"
ok "clean disconnect"
echo "e2e OK"
