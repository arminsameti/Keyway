#!/usr/bin/env bash
# End-to-end smoke test against an isolated data dir and random port.
set -euo pipefail
BIN="${1:-bin/keywayd}"
DIR="$(mktemp -d)"
PORT=$((20000 + RANDOM % 20000))
"$BIN" -port "$PORT" -data-dir "$DIR" >"$DIR/out.log" 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null || true; wait $PID 2>/dev/null || true; rm -rf "$DIR"' EXIT
for _ in $(seq 1 50); do [ -s "$DIR/api-token" ] && break; sleep 0.1; done
TOKEN="$(cat "$DIR/api-token")"
B="http://127.0.0.1:$PORT"
fail() { echo "FAIL: $*"; cat "$DIR/out.log"; exit 1; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

[ "$(code "$B/")" = 404 ] || fail "no web UI is served"
[ "$(code "$B/api/state")" = 401 ] || fail "missing token must be 401"
[ "$(code -H "X-Keyway-Token: $TOKEN" "$B/api/state")" = 200 ] || fail "token accepted"
[ "$(code -H "X-Keyway-Token: $TOKEN" -H 'Host: evil.example' "$B/api/state")" = 403 ] || fail "bad Host must be 403"
[ "$(code -X POST -H "X-Keyway-Token: $TOKEN" -H 'Origin: http://evil.example' -H 'Content-Type: application/json' -d '{}' "$B/api/disconnect")" = 403 ] || fail "bad Origin must be 403"
[ "$(code -X POST -H "X-Keyway-Token: $TOKEN" -H 'Content-Type: text/plain' -d '{}' "$B/api/disconnect")" = 415 ] || fail "non-JSON must be 415"
J=(-H "X-Keyway-Token: $TOKEN" -H 'Content-Type: application/json')
PREVIEW="$(curl -s -X POST "${J[@]}" -d '{"text":"trojan://p@a.example:443#A\nhttps://sub.example.net/x\nssr://abc"}' "$B/api/import/preview")"
echo "$PREVIEW" | grep -q '"ready":1' || fail "preview ready count: $PREVIEW"
echo "$PREVIEW" | grep -q '"subscriptions":1' || fail "preview subscription count: $PREVIEW"
echo "$PREVIEW" | grep -q 'ShadowsocksR is retired' || fail "preview ssr reason: $PREVIEW"
curl -s -H "X-Keyway-Token: $TOKEN" "$B/api/nodes" | grep -q '"nodes":\[\]' || fail "preview must not save nodes"
[ "$(code -H "X-Keyway-Token: $TOKEN" "$B/api/engines")" = 200 ] || fail "engines"
[ "$(code -H "X-Keyway-Token: $TOKEN" "$B/api/cores")" = 200 ] || fail "cores alias"
[ "$(code -X POST "${J[@]}" -d '{"profile":{"protocol":"http","server":"p.example","port":3128}}' "$B/api/nodes")" = 200 ] || fail "create node"
[ "$(code -X POST -H 'Content-Type: application/json' -d '{}' "$B/api/import/preview")" = 401 ] || fail "preview needs the token"
idof() { grep -o '"id":"[0-9a-f]*"' | head -1 | cut -d'"' -f4; }
A="$(curl -s -X POST "${J[@]}" -d '{"link":"trojan://p@a.example:443#A"}' "$B/api/nodes" | idof)"
C="$(curl -s -X POST "${J[@]}" -d '{"link":"vless://u@c.example:443?security=tls#C"}' "$B/api/nodes" | idof)"
[ -n "$A" ] && [ -n "$C" ] || fail "create the two servers of a chain"
# JSON bodies are built in variables: macOS's bash 3.2 brace-expands a {"a":["x","y"]} literal inside "$(...)".
PAIR="{\"chain\":[\"$A\",\"$C\"]}"
ONE="{\"chain\":[\"$A\"]}"
NAMED="{\"name\":\"Pair\",\"chain\":[\"$A\",\"$C\"]}"
[ "$(code -X POST "${J[@]}" -d "$PAIR" "$B/api/chains/plan")" = 200 ] || fail "chain plan"
[ "$(code -X POST "${J[@]}" -d "$ONE" "$B/api/chains/plan")" = 400 ] || fail "one server is not a chain"
[ "$(code -X POST "${J[@]}" -d "$NAMED" "$B/api/nodes")" = 200 ] || fail "create chain"
curl -s -H "X-Keyway-Token: $TOKEN" "$B/api/nodes" | grep -q '"chain":true' || fail "the chain is listed"
OVPN='client\ndev tun\nremote v.example 1194\nremote-cert-tls server\n<ca>\nCA\n</ca>\n<cert>\nC\n</cert>\n<key>\nK\n</key>\n'
curl -s -X POST "${J[@]}" -d "{\"text\":\"$OVPN\"}" "$B/api/import/preview" | grep -q '"protocol":"OpenVPN"' || fail "an .ovpn is recognised"
kill -TERM $PID; wait $PID || true
[ ! -e "$DIR/api-token" ] || fail "token file not removed on exit"
echo "smoke OK"
