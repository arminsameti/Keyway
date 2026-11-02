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

echo "== DNS settings"
# The real engines read each generated config (Xray -test, sing-box check) and carry the request.
dns_preview() { api GET "/api/nodes/$SS_ID/config" | jget "$1"; }
set_settings "s['enginePreference']='xray'; s['dnsMode']='secure'"
connect_to "$SS_ID"
LABEL="$(running_label)"; [ "$LABEL" = "Xray core" ] || fail "secure DNS: expected Xray core, got '$LABEL'"
[ "$(fetch)" = "e2e-ok" ] || fail "page not fetched with secure DNS on Xray"
[ "$(dns_preview "'dns-in' in d['configs'][0] and d['dns'][0].startswith('Secure DNS')")" = True ] || fail "preview lacks the secure DNS"
ok "secure DNS on Xray: config accepted, traffic flows, preview shows it"
disconnect
# Xray would read tls:// as a plain UDP server and say nothing: the planner must pick sing-box.
set_settings "s['dnsMode']='custom'; s['dns']=['tls://9.9.9.9']"
connect_to "$SS_ID"
LABEL="$(running_label)"; [ "$LABEL" = "sing-box" ] || fail "DNS over TLS: expected sing-box, got '$LABEL'"
[ "$(fetch)" = "e2e-ok" ] || fail "page not fetched with DNS over TLS on sing-box"
[ "$(dns_preview "'tls' in d['configs'][0] and d['dns'][0].startswith('Custom')")" = True ] || fail "preview lacks the custom DNS"
ok "DNS over TLS moved from Xray to sing-box"
disconnect
# A direct resolver for the bypassed domains, on both engines (custom routing: no geo data needed).
for PREF in xray sing-box; do
  set_settings "s['enginePreference']='$PREF'; s['routingMode']='custom'; s['directSites']='domain:direct.invalid'; s['proxySites']=''
s['dnsMode']='secure'; s['dnsDirect']='223.5.5.5'"
  connect_to "$SS_ID"
  [ "$(fetch)" = "e2e-ok" ] || fail "page not fetched with a direct DNS resolver on $PREF"
  [ "$(dns_preview "'223.5.5.5' in d['configs'][0] and 'bypassed domains' in d['dns'][0]")" = True ] || fail "preview lacks the direct resolver on $PREF"
  disconnect
done
ok "direct resolver accepted by both engines"
BAD="$(api GET /api/settings | python3 -c "
import sys,json
d=json.load(sys.stdin); s=d.get('settings',d); s['dnsMode']='custom'; s['dns']=['not a server']
print(json.dumps(s))")"
[ "$(api POST /api/settings "$BAD" | jget "d.get('ok')")" = False ] || fail "a malformed DNS server must be refused"
ok "malformed DNS server refused"
set_settings "s['dnsMode']='default'; s['dnsDirect']=''; s['dns']=['1.1.1.1','8.8.8.8','localhost']; s['routingMode']='global'"

echo "== chain: Shadowsocks -> VLESS"
CH="$(api POST /api/nodes "{\"name\":\"E2E chain\",\"chain\":[\"$SS_ID\",\"$VL_ID\"]}" | jget "d['node']['id']")"
: > "$ROOT/server-ss1.log"
connect_to "$CH"
[ "$(fetch)" = "e2e-ok" ] || fail "page not fetched through the chain"
grep -q ":$VL_PORT" "$ROOT/server-ss1.log" || fail "first hop did not carry the connection to the second hop"
via server-vless.log; ok "the chain went through both servers in order"

echo "== Mihomo (opt-in)"
# Mihomo is downloaded as a single gzip file and checked against the digest GitHub reports.
[ "$(api POST /api/engines/mihomo/download '{}' | jget "d.get('ok')")" = True ] || fail "download mihomo"
ok "downloaded mihomo"
# Nobody is moved onto it by installing it: the default preference still picks Xray.
set_settings "s['enginePreference']='xray'"
[ "$(api GET /api/nodes | jget "[n['engine'] for n in d['nodes'] if n['id']=='$SS_ID'][0]")" = xray ] || fail "an installed Mihomo took over a server under the Xray preference"
ok "installing Mihomo changes nothing under the default preference"
set_settings "s['enginePreference']='mihomo'"
connect_to "$SS_ID"
LABEL="$(running_label)"; [ "$LABEL" = "Mihomo" ] || fail "expected Mihomo, got '$LABEL'"
: > "$ROOT/server-ss1.log"
[ "$(fetch)" = "e2e-ok" ] || fail "page not fetched through Shadowsocks/Mihomo"
via server-ss1.log; ok "Shadowsocks over Mihomo carried the request"
sleep 2; fetch >/dev/null
[ "$(api GET /api/traffic | jget "d['upTotal'] > 0 and d['downTotal'] > 0")" = True ] || fail "no traffic counted for Mihomo"
ok "traffic counters work through Mihomo's controller"
: > "$ROOT/server-ss1.log"; : > "$ROOT/server-vless.log"
connect_to "$CH"
LABEL="$(running_label)"; [ "$LABEL" = "Mihomo" ] || fail "expected one Mihomo process for the chain, got '$LABEL'"
[ "$(fetch)" = "e2e-ok" ] || fail "page not fetched through the chain on Mihomo"
grep -q ":$VL_PORT" "$ROOT/server-ss1.log" || fail "first hop did not carry the connection to the second hop (Mihomo)"
via server-vless.log; ok "the chain went through both servers in order on Mihomo"
# Default-style routing needs geo data: Keyway fetches it, verified, before Mihomo starts.
set_settings "s['routingMode']='bypass-private'"
connect_to "$SS_ID"
[ -s "$DIR/engines/mihomo/data/GeoSite.dat" ] || fail "the geo data was not fetched"
[ "$(fetch)" = "e2e-ok" ] || fail "page not fetched with geo routing on Mihomo"
ok "geo routing works on Mihomo with verified geo data"
# Per-app rules (like TUN) only sing-box can do: it serves the apps and Mihomo feeds it through a bridge.
set_settings "
s['routingMode']='rules'; s['blockAds']=False
s['ruleSets']=[{'id':'e2e','name':'e2e','rules':[{'id':'r1','enabled':True,'entries':['process:no-such-program'],'outbound':'direct'}]}]
s['activeRuleSet']='e2e'"
: > "$ROOT/server-ss1.log"
connect_to "$SS_ID"
LABEL="$(running_label)"; [ "$LABEL" = "Mihomo + sing-box" ] || fail "expected Mihomo + sing-box for per-app rules, got '$LABEL'"
[ "$(fetch)" = "e2e-ok" ] || fail "page not fetched through Mihomo behind a sing-box relay"
via server-ss1.log; ok "per-app rules put a sing-box relay in front of Mihomo, and traffic still flows"
set_settings "s['routingMode']='global'; s['enginePreference']='xray'"
disconnect

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
