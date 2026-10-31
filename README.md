# xray-friendly

A small local manager for proxy engines ([Xray-core](https://github.com/XTLS/Xray-core) and [sing-box](https://github.com/SagerNet/sing-box)): import links or subscriptions, pick the fastest node, connect, and optionally set the macOS system proxy. A Go backend exposes a local JSON API; the macOS app in `native/` is the UI. The redesign is tracked in `design/IMPLEMENTATION_PLAN.md`.

## Quick start

```sh
make build && bin/xray-friendly      # API on http://127.0.0.1:12345 (token in ~/.xray-friendly/api-token)
make app                             # macOS app (SwiftUI, universal, macOS 14+) in dist/XrayFriendly.app
make test-native                     # Swift unit tests (native/), incl. the palette contrast check
make snapshots                       # render every screen, light and dark, to dist/snapshots/
```

Flags: `-port`, `-data-dir`, `-version`. Data lives in `~/.xray-friendly` (0700; files 0600).

## Layout

| Package | Role |
|---|---|
| `cmd/xray-friendly` | wiring, signals, token/port files |
| `internal/models` | persisted data types (schema 3), validation |
| `internal/profile` | engine-neutral server description, display strings, country codes |
| `internal/store` | atomic JSON persistence, backup, corruption quarantine |
| `internal/core` | list/download/verify (SHA2-256) engine releases, safe extraction |
| `internal/link` | share links ⇄ profiles (vmess, vless, trojan, ss, socks, hysteria2, hysteria, wireguard, tuic, anytls, naive), WireGuard `.conf`, OpenVPN `.ovpn`, Clash YAML, sing-box JSON, import classification |
| `internal/engine` | `Engine` interface, capability-based selection, chain planner (splits a chain into per-engine processes), shared process runner and latency probe |
| `internal/xray` | Xray: typed config built from a profile, `-test` preflight |
| `internal/singbox` | sing-box: typed config built from a profile, routing via local rule sets |
| `internal/sysproxy` | macOS `networksetup` wrapper with crash-recovery state |
| `internal/service` | all business logic, one lifecycle lock |
| `internal/api` | HTTP layer only: routing, security middleware |
| `native/` | SwiftPM package: `XrayFriendlyCore` (API client, models, form definitions; unit-tested) and the SwiftUI app |

## Security model

The API binds to 127.0.0.1 and is protected against other local pages and processes: Host allow-list (DNS rebinding), Origin / `Sec-Fetch-Site` checks (CSRF), a per-launch token in `X-XF-Token` (written to `api-token` for the native app), JSON-only bodies capped at 1 MiB, and a `default-src 'none'` CSP (the server renders no pages). Downloads only from GitHub hosts and verified before install: Xray against its `.dgst` file, sing-box against the SHA-256 digest GitHub's release API reports, sing-box rule sets against the git blob hash GitHub's contents API reports. Only whitelisted archive entries are extracted. Subscription fetches are SSRF-guarded (no loopback/private/link-local targets). Listeners on non-loopback addresses require credentials.

## Behaviour notes

- Connect runs `xray -test` on the new config before stopping the running instance.
- Each server runs on the engine that supports it; when several do, `settings.enginePreference` decides.
- **OpenVPN** runs on sing-box's `openvpn-client` endpoint in userspace: no administrator rights, no system interface. `.ovpn` files must embed their certificates and keys (`<ca>`, `<cert>`, `<key>`); TAP mode, static keys, passphrase-protected keys and OpenVPN-through-a-proxy are refused with a reason.
- **Chains** (`protocol: "chain"`, `Node.chain` = hop node IDs, entry first) route through any number of saved servers, mixing protocols freely. One engine process runs the whole chain when it can (sing-box `detour`, Xray `dialerProxy`); when hops need different engines they run as separate processes joined by a loopback SOCKS bridge with random per-connection credentials, and the chain stops if any of them dies. A UDP hop (WireGuard, Hysteria, TUIC, OpenVPN over UDP) needs the hop before it to carry UDP; the editor and the API report violations naming the hops.
- **Traffic**: the engine of the running connection exposes loopback-only counters (Xray's stats API, queried through `xray api statsquery`; sing-box's Clash API with a random secret). `GET /api/traffic` returns speed, totals and the last minute of samples; the main window and menu bar show them. An engine build without counters (sing-box without `with_clash_api`) simply shows nothing.
- **Rule sets** (`routingMode: "rules"`): `Settings.ruleSets` hold ordered rules `{entries, outbound}`; the first match wins and unmatched traffic uses the proxy. Entries use Xray syntax (`domain:`, `full:`, `keyword:`, `regexp:`, `geosite:`, `geoip:`, CIDR, `port:`, `process:`). sing-box ANDs different matchers inside one rule, so each kind becomes its own rule; `process:` entries work on sing-box only and are refused on Xray with a hint. `POST /api/routing/import` reads Clash rules or v2rayN/Xray routing JSON; `POST /api/routing/test` shows which rule a destination hits.
- **Per-server overrides** (`Node.overrides`): multiplexing on/off and concurrency, SNI, uTLS fingerprint and TLS fragmentation replace the global settings for one server. Fragmentation needs a TLS/Reality TCP server that is dialed directly (the first hop).
- **Custom servers** (`protocol: "custom"`): paste an Xray or sing-box outbound, a list of outbounds, or a whole config. Only the outbounds are used; the first one becomes the exit (`proxy`) and the app keeps its own inbounds, routing, DNS and counters. A custom server cannot be a chain hop. `GET /api/nodes/{id}/config` shows the configuration that would run for any server.
- **Per-app rules**: `app:/Applications/Slack.app` (every program inside that app), `process:Name` and `process-path:/exact/path` entries are matched by sing-box (`find_process`). When a rule uses one, sing-box serves the traffic; if the server itself needs Xray, sing-box runs as a relay behind it. Only programs that actually use the proxy are seen, unless TUN is on.
- **TUN** (`settings.tun`): sing-box's `tun` inbound (`auto_route`, DNS hijack) captures all traffic. The engine programs of the connection are routed direct so they cannot loop into the tunnel. Root is needed, so sing-box is started by `xf-tun-helper` (shipped next to the backend): by default through the macOS password dialog on every connect (`privilege: "prompt"`, the helper copies sing-box into a root-owned directory first); with `privilege: "helper"` a one-time install (Settings › Proxy › Allow Once…) puts a root-owned helper and sing-box copy under `/Library/Application Support/XrayFriendly` plus a sudoers rule for `xf-tun-helper run-pinned`. The helper refuses configs that touch files (log output, cache file, key paths), non-loopback listeners and remote rule sets, never follows symbolic links for its status files, and stops sing-box when the app exits or a stop file appears. While one-time authorization is installed any program running as you can start a TUN session; removing it deletes the rule. TUN and the helper were verified here only up to the generated configs and a fake helper: starting a real TUN interface needs your password.
- Local addresses inside a chain: a hop's address is dialed by the *previous* hop's server, so it must be reachable from there.
- "Real test" measures latency through each node with a temporary instance of its engine; TCP mode marks UDP protocols as N/A.
- `POST /api/import/preview` classifies pasted text (ready / subscription / skipped with a reason) without saving or fetching anything.
- Auto-pick switches only when the current node is dead or clearly slower (≥30% and ≥50 ms).
- The system proxy is restored on disconnect, shutdown, unexpected core exit and next start after a crash.
- Plain `http(s)://` links in the import box are treated as subscription URLs, not HTTP proxy nodes.

## Development

`make test` (race detector), `make vet`, `make lint`, `make smoke`, `make test-engines` (feeds every generated config, including chains, to the installed real `sing-box check` and `xray -test`). In progress (see the implementation plan): new protocols, Clash/sing-box subscriptions, the sing-box engine, the SwiftUI app. Not planned yet: traffic stats, kill switch, Windows/Linux system proxy, signing/notarization.
