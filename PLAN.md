# xray-friendly — remediation & restructuring plan

Result of the senior-dev review (security, correctness, structure, product gaps, hygiene).
Each item has an ID so it can be traced to the code that fixes it.

## Target architecture

```
cmd/xray-friendly      process wiring only (flags, listener, signals, shutdown order)
web/                   index.html + app.js + app.css, embedded via web/embed.go (single source, strict CSP)
internal/models        data types, defaults, Settings.Validate()
internal/store         JSON persistence: copy-on-read, atomic write, .bak, corrupt-file quarantine
internal/core          Xray core manager: semver, validation, checksum-verified download, safe unzip
internal/link          share-link parsers -> typed xray.Outbound (registry, base64 subscriptions)
internal/xray          typed config model + builder, process Runner (state machine), probe helpers
internal/sysproxy      macOS networksetup wrapper (validated services, SOCKS + HTTP/HTTPS)
internal/service       ALL business logic: connect/reconnect, latency, pick-fastest, auto-pick,
                       subscriptions, system-proxy lifecycle. One lifecycle lock.
internal/api           thin HTTP layer: routing, security middleware, JSON mapping
native/                Swift menu-bar shell
scripts/smoke.sh       isolated end-to-end smoke test (temp data dir, random port)
```

Dependency direction: `cmd -> api -> service -> {store, core, link, xray, sysproxy} -> models`.

## Phase 1 — Security (S)

| ID | Finding | Fix |
|----|---------|-----|
| S1 | No CSRF / DNS-rebinding protection on local API | Host allow-list, Origin + `Sec-Fetch-Site` check, per-launch token header (`X-XF-Token`), JSON-only Content-Type |
| S2 | Core version string used in paths (traversal -> RCE/RemoveAll) | Strict `^v\d+\.\d+\.\d+$` validation everywhere; stage + atomic rename; no RemoveAll on user-derived paths |
| S3 | Zip-slip, whole-file reads, 0755 everywhere | Extract only whitelisted root files (`xray`, `geoip.dat`, `geosite.dat`), size caps, streaming copy |
| S4 | Core download unverified | Resolve asset from the release API, verify SHA2-256 from the `.dgst` asset, host allow-list incl. redirects |
| S5 | SSRF in import/subscription fetch | Dialer `Control` hook rejects loopback/private/link-local/CGNAT after DNS resolution; http(s) only; size cap |
| S6 | `AllowLAN` creates an open proxy | Settings validation: non-loopback listeners require inbound credentials |
| S7 | No server timeouts / body limits | `ReadHeaderTimeout`, `ReadTimeout`, `IdleTimeout`, `MaxBytesReader` (1 MiB) |
| S8 | Secrets readable via API without auth | Token-gated; data dir 0700; config 0600 |

## Phase 2 — Correctness (B)

| ID | Finding | Fix |
|----|---------|-----|
| B1 | GitHub releases URL missing `/repos/` | Fixed; drafts/prereleases filtered; asset names read from release (no guessing) |
| B2 | Runner `Wait` goroutine clobbers state of newer process; TOCTOU; sleep hacks | Per-process struct with `done` chan; Stop waits (SIGTERM then kill); startup grace + immediate-exit detection |
| B3 | Connect reports ok though xray dies | `xray -test` preflight before touching the running instance + startup grace check |
| B4 | Store data race (shallow copies) | Deep-copy `Get`, copy-on-write `Update`, save-then-commit, errors returned |
| B5 | Corrupt `data.json` silently reset -> data loss | Quarantine as `.corrupt-<ts>`, `.bak` of last good, warning surfaced in UI |
| B6 | Lexicographic version sort | Numeric semver compare |
| B7 | Lifecycle locking gaps | Single `life` mutex in service for connect/disconnect/reconnect/auto-pick |
| B8 | Auto-pick flapping | Hysteresis: switch only if current is dead or new is >=30% and >=50 ms faster |
| B9 | TCP-dial "latency" wrong for UDP/CDN/Reality | Real through-proxy probe (temp xray instance); TCP mode kept as fast option; UDP nodes -> "n/a" in TCP mode |
| B10 | Routing settings partly ignored | `DirectSites`, `BlockedSites`, `BlockAds` honoured in every mode |
| B11 | Mux + vision flow, mux on grpc/h2/hysteria | Mux applied only where valid |
| B12 | `http` inbound given `udp`; invalid hysteria2 outbound | Typed inbound settings; hysteria via `hysteria` stream (obfs rejected explicitly; `pinSHA256` → `pinnedPeerCertSha256`, since Xray 26.3.27 rejects `allowInsecure`) |
| B13 | Pasted subscription URL parsed as HTTP proxy node | http(s) lines in the import box are treated as subscriptions |
| B14 | Dead code (`URLTest` unused, `webDir`, `nodesExtra`, helpers) | Removed or put to use |

## Phase 3 — Structure & quality (Q)

- Q1 Service layer; the 3x reconnect copy-paste and duplicated pick logic collapse into one place.
- Q2 Typed Xray config structs instead of `map[string]any`.
- Q3 Nodes persist only the raw link; outbounds are regenerated at connect (never stale).
- Q4 Parser registry instead of 7 copy-pasted blocks; no sentinel-string hacks; rune-safe, credential-free errors.
- Q5 HTTP: Go 1.22 method/path patterns, real status codes, one JSON envelope, typed requests, no swallowed decode errors.
- Q6 Single embedded UI (`web/`), no sync step; CSP without `unsafe-inline`; DOM built without `innerHTML`.
- Q7 `log/slog`, wrapped errors, no shadowed builtins, `any` everywhere.

## Phase 4 — Product gaps (P)

- P1 Base64 subscription bodies; persisted subscriptions with refresh / auto-update / remove-with-nodes.
- P2 Settings validation (ports, tags, ranges, DNS).
- P3 System proxy: validated services, SOCKS + HTTP/HTTPS, primary-service detection, auto on connect/off on disconnect, crash recovery, restore on exit.
- P4 Incremental logs endpoint + `/api/status`; auto-connect on launch; xray stale-process reaping.
- P5 More transports: xhttp, h2, kcp, tcp-http header; vless `encryption`.

## Phase 5 — Native app & repo hygiene (H)

- H1 Swift: async backend start + retry, token auth, live menu state, backend crash restart, launch-at-login, no main-thread blocking.
- H2 `Makefile`: `test` no longer swallows failures (`-race`), version ldflags, proper `lipo`, lint target.
- H3 `scripts/smoke.sh` on an isolated HOME/data dir, random port, trap cleanup.
- H4 `.gitignore`, `.golangci.yml`, CI workflow, module path de-placeholdered, README rewritten.

## Explicitly deferred

Clash/sing-box subscription formats, traffic statistics, kill-switch, fetching subscriptions *through* the local proxy,
Windows support, code-signing/notarisation (needs a Developer ID).

## Verification

`go build`, `go vet`, `go test -race ./...` (unit tests for store, core, link, xray, api middleware, service logic),
`scripts/smoke.sh` end-to-end with a fake xray binary. Swift cannot be compiled in the Linux sandbox — reviewed manually.
