# Development

Keyway is a Go backend (`keywayd`) that exposes a local JSON API, plus a SwiftUI macOS app in `native/` that talks to it. The app bundles and starts the backend.

## Build

You need Go 1.22+ (use the latest Go for release builds; older toolchains produce binaries that current macOS refuses to start) and Xcode command line tools (Swift 5.10, macOS 14 SDK).

```sh
make build            # bin/keywayd and bin/keyway-tun-helper
make app              # universal dist/Keyway.app (SwiftUI, macOS 14+)
make run              # run the backend only: API on http://127.0.0.1:12345
make snapshots        # render every screen, light and dark, to dist/snapshots/
```

Backend flags: `-port`, `-data-dir`, `-version`. The API token is written to `~/.keyway/api-token` and sent as `X-Keyway-Token`.

## Checks

```sh
make vet && make lint
make smoke            # start the backend and call the API
make e2e              # real engines and connections through local fixture servers
make e2e-tor          # real Tor (needs the Tor network; slow, not a merge gate)
```

`make e2e` downloads sing-box and Xray through Keyway's own download code, runs sing-box as a fixture server on loopback, then connects through Shadowsocks (on both engines), plain VLESS and a two-hop chain. It fetches a local page through each and checks the server's log, so a request that bypasses the server fails. It also runs a real latency test and checks that disconnect leaves nothing running. `make e2e-tor` checks that the exit is Tor, loads an `.onion` page, runs a proxy-then-Tor chain and turns Tor off. Both use random ports and a temporary data directory, so they never touch a Keyway you have installed. `make lint` needs [golangci-lint](https://golangci-lint.run) v1.

CI (`.github/workflows/ci.yml`) runs on every push and pull request: gofmt, vet, golangci-lint and the smoke test; a full `make app` build of the macOS bundle with architecture and signature checks; and `make e2e`. `e2e-tor.yml` runs the Tor test on pushes to `master`, pull requests and nightly, without blocking merges.

## Release

Push a tag like `v0.2.0` (`git tag v0.2.0 && git push origin v0.2.0`). `.github/workflows/release.yml` builds the universal app on macOS, packages it as a DMG and a zip with a SHA-256 file, and publishes a GitHub release.
