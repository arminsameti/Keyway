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
- Local addresses inside a chain: a hop's address is dialed by the *previous* hop's server, so it must be reachable from there.
- "Real test" measures latency through each node with a temporary instance of its engine; TCP mode marks UDP protocols as N/A.
- `POST /api/import/preview` classifies pasted text (ready / subscription / skipped with a reason) without saving or fetching anything.
- Auto-pick switches only when the current node is dead or clearly slower (≥30% and ≥50 ms).
- The system proxy is restored on disconnect, shutdown, unexpected core exit and next start after a crash.
- Plain `http(s)://` links in the import box are treated as subscription URLs, not HTTP proxy nodes.

## Development

`make test` (race detector), `make vet`, `make lint`, `make smoke`, `make test-engines` (feeds every generated config, including chains, to the installed real `sing-box check` and `xray -test`). In progress (see the implementation plan): new protocols, Clash/sing-box subscriptions, the sing-box engine, the SwiftUI app. Not planned yet: traffic stats, kill switch, Windows/Linux system proxy, signing/notarization.
