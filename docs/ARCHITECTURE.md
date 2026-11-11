# Architecture

How Keyway is put together. Back to the [README](../README.md).

## Layout

| Package | Role |
|---|---|
| `cmd/keywayd` | wiring, signals, token and port files |
| `cmd/keyway-tun-helper` | root helper that validates a config and runs sing-box for TUN |
| `internal/models` | persisted data types (schema 3), validation |
| `internal/profile` | engine-neutral server description, overrides, custom servers |
| `internal/store` | atomic JSON persistence, backup, corruption quarantine |
| `internal/core` | list, download and verify engine releases, safe extraction |
| `internal/appupdate` | find the newest Keyway release and download its disk image, verified against `SHA256SUMS.txt` |
| `internal/link` | share links, WireGuard, OpenVPN, Clash and sing-box imports ⇄ profiles |
| `internal/engine` | `Engine` interface, capability-based selection, chain planner, process runner, latency probe |
| `internal/xray`, `internal/singbox`, `internal/tor` | config builders for each engine (`internal/tor` also reads Tor's bootstrap progress) |
| `internal/privileged` | helper validation, one-time install, elevated run |
| `internal/sysproxy` | macOS `networksetup` wrapper with crash recovery |
| `internal/service` | all business logic behind one lifecycle lock |
| `internal/api` | HTTP layer only: routing and security middleware |
| `native/` | SwiftPM package: `KeywayCore` (API client, models, forms) and the SwiftUI app |

## Security model

When Tor is enabled, its SOCKS port listens on loopback without a password (Tor cannot require one), so other programs on the same Mac can use it. It exposes only access through Tor and no secrets.

The API binds to 127.0.0.1 and defends against other local pages and processes: Host allow-list (DNS rebinding), Origin and `Sec-Fetch-Site` checks (CSRF), a per-launch token, JSON-only bodies capped at 1 MiB and a `default-src 'none'` CSP. Downloads come only from GitHub hosts (and `dist.torproject.org` for Tor) and are verified before install (Xray against its `.dgst`, sing-box against the SHA-256 GitHub reports, rule sets against the git blob hash). Only whitelisted archive entries are extracted. Subscription fetches are SSRF-guarded. Listeners on non-loopback addresses require credentials.

## Behaviour notes

- Connect runs the engine's config test on the new config before stopping the running instance.
- Each server runs on the engine that supports it; when several do, `settings.enginePreference` decides.
- **OpenVPN** runs on sing-box's userspace `openvpn-client`, with no admin rights. `.ovpn` files must embed their certificates and keys, or arrive in a `.zip` next to them (`POST /api/import/zip` resolves `ca`/`cert`/`key`/`tls-auth`/`tls-crypt` file references from the bundle). Profiles with `auth-user-pass` and no stored credentials import with a warning and stay editable; connecting, testing or measuring them is refused until the username and password are added (in the import sheet or the server's settings). TAP mode, static keys and passphrase-protected keys are refused with a reason.
- **Chains** (`protocol: "chain"`, `Node.chain` = hop IDs, entry first) run in one engine process when possible (sing-box `detour`, Xray `dialerProxy`). Hops needing different engines run as separate processes joined by a loopback SOCKS bridge with random per-connection credentials. A UDP hop needs the hop before it to carry UDP.
- **Traffic** comes from loopback-only counters (Xray stats API, sing-box Clash API with a random secret): `GET /api/traffic`.
- **Rule sets** (`routingMode: "rules"`): ordered rules `{entries, outbound}`, first match wins, default proxy. Entries: `domain:`, `full:`, `keyword:`, `regexp:`, `geosite:`, `geoip:`, CIDR, `port:`, `process:`, `process-path:`, `app:`. `POST /api/routing/import` reads Clash or v2rayN routing and `POST /api/routing/test` shows which rule a destination hits. Process and app entries need sing-box.
- **Per-app rules** use sing-box `find_process`. When a rule uses one and the server needs Xray, sing-box runs as a relay behind it. Without TUN only programs that use the proxy are seen.
- **Custom servers** (`protocol: "custom"`) use only the pasted outbounds; the app keeps its own inbounds, routing and DNS. `GET /api/nodes/{id}/config` shows the config that would run for any server.
- **Groups** (`AppData.groups`, `activeGroupId`): `activeNodeId` always mirrors the active group's current member, so connect logic only ever sees a node. The store reconciles groups on every update (pruned members, dropped groups of removed subscriptions). `url-test` reuses the auto-pick hysteresis and never picks Tor; the background loop re-tests only the active fallback/url-test group.
- A chain hop's address is dialed by the previous hop's server, so it must be reachable from there.
- "Real test" measures latency through a temporary instance of the server's engine; TCP mode marks UDP protocols as N/A.
- `POST /api/import/preview` classifies pasted text without saving or fetching anything.
- Auto-pick switches only when the current node is dead or at least 30% and 50 ms slower.
- Plain `http(s)://` links in the import box are treated as subscription URLs, not HTTP proxy nodes.

TUN and the helper were verified only up to the generated configs and a fake helper; starting a real TUN interface needs a password.
