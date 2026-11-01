# Keyway

A friendly macOS app for running proxies. Paste a link or a subscription, pick the fastest server, and connect. Keyway runs [Xray-core](https://github.com/XTLS/Xray-core) and [sing-box](https://github.com/SagerNet/sing-box) for you and chooses the right one for each server, so you never write a config file.

## Download and use

1. Download `Keyway-<version>-macOS.zip` from the [latest release](https://github.com/arminsameti/keyway/releases/latest) and unzip it.
2. Drag **Keyway.app** into Applications and open it. Requires macOS 14 or later, Apple silicon or Intel.
3. The builds are not notarized yet, so macOS may refuse the first launch. Right-click the app, choose **Open**, then confirm. If that still fails, run `xattr -dr com.apple.quarantine /Applications/Keyway.app` once.
4. Follow the three onboarding steps: download an engine, add servers, connect.

You can verify the download against the `.sha256` file on the release page.

### What it does

- **Import servers** from share links, subscription URLs, QR codes on screen, WireGuard `.conf`, OpenVPN `.ovpn`, Clash YAML or sing-box JSON.
- **Protocols:** VMess, VLESS (including Reality), Trojan, Shadowsocks, SOCKS, Hysteria and Hysteria2, TUIC, AnyTLS, NaiveProxy, WireGuard and OpenVPN.
- **Engines are managed for you.** Keyway downloads Xray and sing-box from their official releases, checks their checksums, keeps them updated, and runs whichever one supports your server.
- **Chains:** route through several servers in a row, mixing protocols.
- **Speed tests and auto-pick:** measure real latency through each server and switch to a faster one when the current one is slow or dead.
- **System proxy** is set on connect and restored on disconnect, shutdown or after a crash.
- **Routing rules:** global, bypass private and Chinese addresses, or your own rule sets (domains, IP ranges, ports, programs). Rules can be imported from Clash or v2rayN.
- **Per-app rules:** send or block traffic by application, for example `app:/Applications/Slack.app`.
- **TUN mode:** capture all traffic on the Mac, not just apps that respect the system proxy. This needs administrator rights, see below.
- **Per-server overrides** for multiplexing, SNI, uTLS fingerprint and TLS fragmentation, and **custom servers** from a pasted Xray or sing-box outbound.
- **Live traffic** speed and totals in the window and the menu bar.

### TUN mode and administrator rights

TUN starts sing-box as root. By default macOS asks for your password every time you connect. In Settings › Proxy you can instead choose **Allow Once…**, which installs a root-owned helper and a sudoers rule so later connects need no password. While that is installed, any program running as you can start a TUN session, and removing it deletes the rule. The helper refuses configs that touch files, listen on non-loopback addresses or use remote rule sets.

### Your data

Everything lives in `~/.keyway` (folder mode 0700, files 0600): servers, settings, downloaded engines. Nothing is sent anywhere except the downloads and subscription URLs you configure. Delete the folder to reset the app.

### Not included yet

A kill switch, Windows and Linux support, and signed or notarized builds.

## For developers

Keyway is a Go backend (`keywayd`) that exposes a local JSON API, plus a SwiftUI macOS app in `native/` that talks to it. The app bundles and starts the backend.

### Build

You need Go 1.22+ (use the latest Go for release builds; older toolchains produce binaries that current macOS refuses to start) and Xcode command line tools (Swift 5.10, macOS 14 SDK).

```sh
make build            # bin/keywayd and bin/keyway-tun-helper
make app              # universal dist/Keyway.app (SwiftUI, macOS 14+)
make run              # run the backend only: API on http://127.0.0.1:12345
make snapshots        # render every screen, light and dark, to dist/snapshots/
```

Backend flags: `-port`, `-data-dir`, `-version`. The API token is written to `~/.keyway/api-token` and sent as `X-Keyway-Token`.

### Checks

```sh
make vet && make lint
make smoke            # start the backend and call the API
```

CI (`.github/workflows/ci.yml`) runs gofmt, vet, the smoke test and the Swift build on every push and pull request.

### Release

Push a tag like `v0.2.0` (`git tag v0.2.0 && git push origin v0.2.0`). `.github/workflows/release.yml` builds the universal app on macOS, zips it with a SHA-256 file and publishes a GitHub release.

### Layout

| Package | Role |
|---|---|
| `cmd/keywayd` | wiring, signals, token and port files |
| `cmd/keyway-tun-helper` | root helper that validates a config and runs sing-box for TUN |
| `internal/models` | persisted data types (schema 3), validation |
| `internal/profile` | engine-neutral server description, overrides, custom servers |
| `internal/store` | atomic JSON persistence, backup, corruption quarantine |
| `internal/core` | list, download and verify engine releases, safe extraction |
| `internal/link` | share links, WireGuard, OpenVPN, Clash and sing-box imports ⇄ profiles |
| `internal/engine` | `Engine` interface, capability-based selection, chain planner, process runner, latency probe |
| `internal/xray`, `internal/singbox` | typed config builders for each engine |
| `internal/privileged` | helper validation, one-time install, elevated run |
| `internal/sysproxy` | macOS `networksetup` wrapper with crash recovery |
| `internal/service` | all business logic behind one lifecycle lock |
| `internal/api` | HTTP layer only: routing and security middleware |
| `native/` | SwiftPM package: `KeywayCore` (API client, models, forms) and the SwiftUI app |

### Security model

The API binds to 127.0.0.1 and defends against other local pages and processes: Host allow-list (DNS rebinding), Origin and `Sec-Fetch-Site` checks (CSRF), a per-launch token, JSON-only bodies capped at 1 MiB and a `default-src 'none'` CSP. Downloads come only from GitHub hosts and are verified before install (Xray against its `.dgst`, sing-box against the SHA-256 GitHub reports, rule sets against the git blob hash). Only whitelisted archive entries are extracted. Subscription fetches are SSRF-guarded. Listeners on non-loopback addresses require credentials.

### Behaviour notes

- Connect runs the engine's config test on the new config before stopping the running instance.
- Each server runs on the engine that supports it; when several do, `settings.enginePreference` decides.
- **OpenVPN** runs on sing-box's userspace `openvpn-client`, with no admin rights. `.ovpn` files must embed their certificates and keys; TAP mode, static keys and passphrase-protected keys are refused with a reason.
- **Chains** (`protocol: "chain"`, `Node.chain` = hop IDs, entry first) run in one engine process when possible (sing-box `detour`, Xray `dialerProxy`). Hops needing different engines run as separate processes joined by a loopback SOCKS bridge with random per-connection credentials. A UDP hop needs the hop before it to carry UDP.
- **Traffic** comes from loopback-only counters (Xray stats API, sing-box Clash API with a random secret): `GET /api/traffic`.
- **Rule sets** (`routingMode: "rules"`): ordered rules `{entries, outbound}`, first match wins, default proxy. Entries: `domain:`, `full:`, `keyword:`, `regexp:`, `geosite:`, `geoip:`, CIDR, `port:`, `process:`, `process-path:`, `app:`. `POST /api/routing/import` reads Clash or v2rayN routing and `POST /api/routing/test` shows which rule a destination hits. Process and app entries need sing-box.
- **Per-app rules** use sing-box `find_process`. When a rule uses one and the server needs Xray, sing-box runs as a relay behind it. Without TUN only programs that use the proxy are seen.
- **Custom servers** (`protocol: "custom"`) use only the pasted outbounds; the app keeps its own inbounds, routing and DNS. `GET /api/nodes/{id}/config` shows the config that would run for any server.
- A chain hop's address is dialed by the previous hop's server, so it must be reachable from there.
- "Real test" measures latency through a temporary instance of the server's engine; TCP mode marks UDP protocols as N/A.
- `POST /api/import/preview` classifies pasted text without saving or fetching anything.
- Auto-pick switches only when the current node is dead or at least 30% and 50 ms slower.
- Plain `http(s)://` links in the import box are treated as subscription URLs, not HTTP proxy nodes.

TUN and the helper were verified only up to the generated configs and a fake helper; starting a real TUN interface needs a password.

## Contributing

Issues and pull requests are welcome. Keyway is released under the [MIT License](LICENSE). Run `make vet` and `make smoke` before opening a PR.
