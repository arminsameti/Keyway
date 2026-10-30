# Implementation plan — macOS redesign + sing-box engine

Source of truth: `design/DESIGN_HANDOFF.md` and `design/screens/*.dc.html`.
Status: **approved 2026-10-29.** Decisions are recorded in §7.

| Phase | State |
|---|---|
| 1 Backend groundwork | **Done 2026-10-29.** `make vet/test/smoke/app` green. Also verified against Xray 26.3.27 on a copy of the real data dir (migration, connect, real latency). |
| 2 Protocols & subscription formats | **Done 2026-10-29.** Parsers and fixtures for every listed format; WireGuard verified end to end on Xray 26.3.27. sing-box-only protocols parse and show "needs sing-box" until Phase 3. |
| 3 sing-box engine | **Done 2026-10-29.** Verified on sing-box 1.14.4: TUIC, Hysteria2+obfs, AnyTLS, Hysteria v1, ShadowTLS v3, insecure Trojan connect and carry traffic; NaiveProxy passes preflight (no trusted test server). Engine switching and rule-set routing verified. |
| 4 SwiftUI app | **Done 2026-10-29.** All six screens, universal binary (macOS 14+). Download jobs with progress and link/.conf parsing added to the API. |
| 5 Polish & acceptance | **Done 2026-10-29.** See `design/ACCEPTANCE.md`; a live VoiceOver pass and your visual sign-off are still open. |

## 0. Findings that shape the plan

| # | Finding | Consequence |
|---|---|---|
| F1 | sing-box releases publish **no checksum file**. The only SHA-256 is the `digest` field (`sha256:…`) that GitHub's release API returns for each asset (checked for v1.14.4). | Verify sing-box downloads against the API `digest`. That is the same trust root as Xray's `.dgst` (same release, same GitHub channel), but a different mechanism. **(Q6)** |
| F2 | sing-box ships `.tar.gz`, not zip. | `internal/core` needs a safe **tar.gz** extractor with the same S3 rules (whitelisted entries, size caps, no links, streaming). |
| F3 | The latest stable sing-box is 1.14.4; the mockups say "1.12" and "Xray core 25.10". | Treated as sample data. The UI shows real installed versions. The config builder targets the current 1.12+ JSON format (new DNS and route-action syntax), with minimum version 1.12. |
| F4 | NaiveProxy needs sing-box's optional `with_naive_outbound` build tag. I couldn't confirm the official darwin builds include it: running a downloaded binary was blocked at planning time. | Phase 3 checks `sing-box version` tags at runtime. If naive is missing, NaiveProxy nodes import as **skipped** with the reason "this sing-box build has no NaiveProxy support". |
| F5 | Xray rejects `allowInsecure` (26.3.27, verified earlier). The design's TLS section has "Pinned certificate SHA-256". | Matches the pin support added last session; the form maps to `pinnedPeerCertSha256` (Xray) / `certificate_public_key_sha256` (sing-box). |
| F6 | Parsers currently emit `xray.Outbound` directly. | A second engine needs an **engine-neutral profile** between parsing and config building (see §2). This is the core refactor of Phase 1. |
| F7 | `.inspector`, `Table` sections, `MenuBarExtra(.window)` need macOS 14. Current `LSMinimumSystemVersion` is 12. | Raise the minimum to **macOS 14 Sonoma**. |
| F8 | This Mac has Xcode 27.1 / Swift 6.4 / macOS 26. | Build the app as a **SwiftPM package** (`native/Package.swift`) with `swift build --arch arm64 --arch x86_64`. That fixes last session's arm64-only shell. No `.xcodeproj` to maintain; the Makefile keeps producing `dist/XrayFriendly.app`. |
| F9 | Only the Servers view and the Settings › Engines tab are mocked. Subscriptions, Routing, Activity and Settings General/Proxy/Routing/Advanced are named but not drawn. | **(Q2)** |
| F10 | The design's menu-bar icon is a shield (`checkmark.shield` when connected); last session we put your pixel logo in the menu bar. | **(Q1)** |
| F11 | The table shows a country code per server (`DE`, `NL`…), but nothing in the data has one. | **(Q3)** |

## 1. Phases

Each phase ends with `make test`, `make vet`, `make smoke`, fixes, and a short summary to you before the next one starts.

### Phase 1 — Backend groundwork (engine abstraction + API)

1. **`internal/profile`** (new, models layer): the engine-neutral description of one outbound.
   `Profile{Protocol, Server, Port, Auth (typed per protocol), Transport{Type, Path, Host, ServiceName, Mode, HeaderType, Seed}, Security{Kind: none|tls|reality, SNI, ALPN, Fingerprint, Insecure, PinSHA256, PublicKey, ShortID, SpiderX}, Extra (protocol-specific: WireGuard keys/addresses/reserved/MTU, TUIC CC/UDP mode/0-RTT, Hysteria up/down/obfs, SS method/plugin, SSH user/key/host key, ShadowTLS version/handshake/inner SS, Naive headers, HTTP TLS flag)}`.
   Also: `Validate()`, `DisplayTransport()` and `DisplaySecurity()` (the strings the table and inspector show, e.g. "Reality · Vision", "2022-blake3"), and `Capabilities()`, the feature set engines are matched against.
2. **`internal/link`** returns `Result{Node, Profile}` instead of `xray.Outbound`. The existing parsers are converted 1:1; their tests are kept and extended to assert the Profile. New `link.Encode(Profile) (string, bool)` produces a canonical share link where a scheme exists (Copy Link, QR, NodeID for manual nodes).
3. **`internal/xray`**: `BuildConfig(profile.Profile, Settings)` maps Profile → typed Xray outbound (moves the mapping that is in `link` today). Runner, `-test` preflight and probe unchanged.
4. **`internal/engine`** (new):
   ```go
   type Engine interface {
       Name() string                       // "xray", "sing-box"
       Supports(p profile.Profile) error   // nil, or a reason ("XHTTP is Xray-only")
       BuildConfig(p profile.Profile, s models.Settings) ([]byte, error)
       ProbeConfig(p profile.Profile, socksPort int) ([]byte, error)
       Check(ctx, bin, cfgPath, assetDir string) error   // xray -test / sing-box check
       Args(cfgPath string) []string
   }
   func Select(p profile.Profile, pref string, installed map[string]bool) (Engine, error)
   ```
   - **Selection is by capability, not only by protocol.** If both engines support the profile, the "When both engines support a protocol" preference decides. Otherwise the one that can run it wins: XHTTP, mKCP and HTTPUpgrade are Xray-only; Hysteria2 *with obfs* is sing-box-only; Xray rejects insecure TLS (F5).
   - **One process runner.** The existing `xray.Runner` (state machine, startup grace, crash detection, log ring, PID file, stale reaping) is already engine-agnostic. It moves to `internal/engine/runner.go`, parameterised by binary and args. `ReapStale` matches any binary under the engines dir.
5. **`internal/core`** → manages both engines under `engines/<name>/<version>/`:
   - Xray: as today (zip + `.dgst`).
   - sing-box: tar.gz + API digest (F1, F2).
   - The GitHub host allow-list, https-only and redirect checks, stage + atomic rename, strict version regexes per engine (`^v\d+\.\d+\.\d+$` for both; sing-box tags are `v1.14.4`) and size caps all stay. Prereleases are still filtered.
6. **Service**: `connectLocked` selects the engine per node and runs `Check` before stopping the running instance (B3 semantics kept). `Measure` probes through the right engine. TCP mode returns `n/a` for UDP protocols (Hysteria, Hysteria2, TUIC, WireGuard).
7. **API** (all behind the existing token, Host and Origin middleware, JSON-only, 1 MiB):

   | Method & path | Purpose |
   |---|---|
   | `POST /api/import/preview` | Dry-run parse of `{text}` → `[{line, status: ready\|subscription\|skipped, name, protocol, transport, engine, reason}]` plus counts. **Saves nothing, fetches nothing** (a subscription line is only classified, not downloaded). |
   | `POST /api/nodes` | Manual create from `{profile, name}` or `{link}`. Validates, picks the engine, stores. |
   | `PUT /api/nodes/{id}` | Edit (same body). The ID is stable for manual nodes. |
   | `POST /api/nodes/test` | "Test Connection" for an unsaved profile: one real probe through the right engine, nothing persisted. |
   | `GET /api/engines` | `[{name, installed[], active, latest, updateAvailable, protocols[], lastChecked, features[]}]` |
   | `POST /api/engines/{name}/download\|use\|check` | `download` takes `{version}` (empty = latest stable). |
   | `/api/cores*` | Kept as aliases for Xray during the transition. |
   | `GET /api/status` | Adds `uptimeSec`, `activeNodeId`, `activeLatencyMs`, `engine`, `engineVersion`, `protocol`, `transport`, `routingMode`, `systemProxy{on, services}`. |
   | — | Delete `web/`, the index/static routes and the token meta-tag injection (Q4). The CSP and security headers stay on every response. |
| `GET /api/nodes` | Each node gains derived `transport`, `security`, `sni`, `engine`, `engineReason`, `countryCode`, `hasLink`. |

### Phase 2 — New protocols and subscription formats (`internal/link`)

| Input | Notes |
|---|---|
| `wireguard://`, `wg://` | Keys, address list, reserved, MTU, keepalive, allowed IPs. |
| WireGuard `.conf` | `[Interface]`/`[Peer]`. Recognised in the import text and the File tab. One `.conf` = one node. |
| `tuic://` | v5 only: uuid:password, congestion_control, udp_relay_mode, alpn, sni, allow_insecure/pin. |
| `hysteria://` (v1) | auth, upmbps/downmbps, obfs, alpn, sni. |
| `anytls://` | password, sni, idle timeout. |
| `naive+https://` (`naive+quic://` skipped with reason) | user:pass, extra headers. |
| HTTP(S) upstream | Manual form only, as the spec says. The import box keeps treating `http(s)://` as a subscription (B13). |
| SSH, ShadowTLS v3 | No share-link scheme: manual form, Clash or sing-box JSON only. |
| `ssr://` | Recognised and **skipped**: "ShadowsocksR is retired — skipped". |
| Clash YAML | `proxies:` list → profiles for every supported `type`. Unknown types are skipped with a reason. **(Q5)** |
| sing-box JSON | `outbounds[]` → profiles. Selector, urltest, direct, block and dns outbounds are ignored silently. |

- The subscription body is detected in this order: sing-box JSON → Clash YAML → base64/plain links. `Subscription.Format` is persisted for the "· Clash format" group label.
- Nodes from Clash or sing-box have no share link, so they store their Profile (§3). Copy Link and QR are enabled only when `link.Encode` can produce a link.
- Tests: table-driven, one file per parser, covering a good link, every option, malformed input and credential-free errors. Clash and sing-box get fixture files covering every supported type, plus unknown and broken entries.

### Phase 3 — sing-box engine (`internal/singbox`)

- A typed config model and builder: inbounds `socks`/`http` from Settings (S6 rule unchanged); route rules mirroring the Xray routing modes (`DirectSites`, `ProxySites`, `BlockedSites`, `BlockAds`), with geosite/geoip rules as local `.srs` rule sets (see R3); DNS from Settings; outbound per protocol.
- Preflight `sing-box check -c`, then run with `sing-box run -c`. Startup grace, crash detection and system-proxy drop on unexpected exit, all through the shared runner.
- Real latency test: a temporary sing-box with one SOCKS inbound and a URL test through it (the `xray.URLTest` client code is engine-agnostic and moves to `engine`).
- The build's feature tags (`sing-box version` → `Tags:`) are cached per installed version and feed `Supports()` (F4).
- **Integration test** (opt-in, `XF_IT=1`): starts local servers with the installed engines, as in last session's hysteria2 check, and connects, routes traffic and probes through each engine for each protocol a local server can provide. Not part of `make test`, so CI stays offline.

### Phase 4 — Native SwiftUI app (`native/`)

SwiftPM layout: `native/Package.swift`; `Sources/XrayFriendly/{App, API, Model, Views/*, Support/*}`; `Tests/XrayFriendlyTests` (API decoding, view-model logic, formatters).

| Screen | Implementation |
|---|---|
| Main | `Window` + `NavigationSplitView` (sidebar · content) + `.inspector`. `Table` with `Section` per source, sortable Latency column, `contextMenu`, `onKeyPress(.return)` and double-click to connect. Protocol chips as a toggle row. Toolbar: title and subtitle, `.searchable` (⌘F), Test Latency split `Menu` with `primaryAction` (⌘T), Add (⌘N). |
| Connection card | The status, active server and latency, protocol · transport, uptime timer, routing mode, the "Auto-select fastest" `Toggle` (→ `settings.autoPick`) and the Connect/Disconnect button, all as in the mockup. |
| Menu bar | `MenuBarExtra(.window)`: status + `Toggle(.switch)`, "Choose Fastest Automatically", top 5 by latency, "All Servers ▸" (a `Menu`), System Proxy switch + ports, the commands with their shortcuts. |
| Add Servers | `.sheet`: segmented `Picker` with the three tabs. Live preview (debounced `POST /api/import/preview`), status icons, footer primary button with counts ("Add 4 Servers & 1 Subscription"). File/QR tab: `fileImporter`; QR decoded locally with `CIDetector`. |
| New Server | Separate `Window` scene: a protocol `List` grouped by engine, a right `Form(.grouped)` built from a Swift port of the `defs` table (fields exactly as in the mockup), engine badge, footer Test Connection / Cancel / Add Server. Paste a link anywhere (⌘V when no text field has focus, plus a menu command) to fill the form. Also used for **Edit** (title "Edit Server", button "Save"). |
| Settings | `Settings` scene with `TabView`: General, Proxy, Routing, Engines, Advanced. Engines matches the mockup; the others follow its style (Q2). |
| Onboarding | First-launch `Window` when no engine or no servers. Step 1 downloads the engine(s) with progress (polls the download job). Step 2 offers Paste / Scan QR on screen (ScreenCaptureKit + CIDetector; asks for Screen Recording permission) / Open File. Step 3 connects. "Open at login" checkbox (`SMAppService`) and Skip. |

- **Backend lifecycle** stays as today: it starts the bundled Go binary, reads `api-token` and `api-port`, restarts on crash and stops on quit.
- **Activation policy:** `.regular` while any window is open and `.accessory` otherwise (last session's behaviour, now driven by scene phase).
- **Visual rules:** dynamic semantic colours with the design hexes as light-mode references, defined in code via `NSColor(name:dynamicProvider:)`, so no asset catalog is needed. Accent `#0064D2` via `.tint`. Latency labels "Fast" / "OK" / "Slow" / "Timeout" / "n/a" with the specified colours. SF Symbols only, no emoji. VoiceOver labels on icon-only buttons and full keyboard navigation.
- **Downloads with progress:** `POST /api/engines/{name}/download` becomes a job (`{jobId}`) with `GET /api/jobs/{id}` → `{progress, state, error}`, so onboarding can show the progress bar. The download is still verified before install.
- **The web UI (`web/`)** was deleted in Phase 1 (Q4).

### Phase 5 — Polish and acceptance

Work through the acceptance checklist in DESIGN_HANDOFF.md:
- **Contrast:** check text colours ≥ 4.5:1 in light and dark with a script over the palette.
- **Keyboard:** walk every screen.
- **VoiceOver:** audit labels.
- **Docs:** update README and PLAN.

I can't take screenshots on this Mac (no Screen Recording permission for this process), so you'll need to do the visual pass, or grant that permission so I can compare against the mockups myself.

## 2. Package boundaries after the change

```
cmd -> api -> service -> {store, core, link, engine, sysproxy} -> models
                          engine -> {xray, singbox} -> profile -> models
                          link   -> profile
```
`profile` sits beside `models` (pure data + validation, no I/O).

## 3. Data model and migration (SchemaVersion 2 → 3)

| Change | Detail |
|---|---|
| `Node.Profile json.RawMessage` (optional) | Set for nodes without a share link (manual SSH/ShadowTLS/HTTP, Clash, sing-box). `RawLink` stays authoritative when present. Manual nodes with a link-capable protocol store the canonical link (spec: "store a canonical link or a typed JSON blob"). |
| No persisted `Engine` field | Derived at read time from Profile + preference + installed engines, so changing the preference or installing sing-box never leaves stale data. Exposed in the API view. *Deviation from the spec's suggestion "add Engine (derived at parse time)" — same information, never stale. Tell me if you want it persisted anyway.* |
| `Subscription.Format` | `base64` \| `clash` \| `sing-box` \| `links`. |
| `AppData.ActiveCore` → `AppData.Engines map[string]string` | Active version per engine. Migrated: `{"xray": ActiveCore}`. |
| `AppData.EngineCheck map[string]EngineCheck` | Last check time and latest version seen, for "Version X is available". |
| New settings | `EnginePreference` (`xray`\|`sing-box`, default `xray`), `AutoDownloadEngines` (default true), `EngineUpdateCheck` (`never`\|`daily`\|`weekly`, default `weekly`), `LatencyMethod` (`tcp`\|`real`, default `real`). |
| Directories | `cores/<v>/` → `engines/xray/<v>/` by `os.Rename` at startup. If the rename fails, keep reading `cores/` (no data loss). |

The migration is idempotent and runs inside `store.Update` (the existing `.bak` covers rollback). Tests cover v2 → v3 with the active core, nodes and settings.

## 4. Files

- **Add:**
  - `internal/profile/{profile.go,display.go,profile_test.go}`
  - `internal/engine/{engine.go,select.go,runner.go,probe.go,*_test.go}`
  - `internal/singbox/{types.go,config.go,features.go,*_test.go}`
  - `internal/core/{targz.go,singbox.go}` and tests
  - `internal/link/{wireguard.go,tuic.go,hysteria1.go,anytls.go,naive.go,ssr.go,clash.go,singboxjson.go,encode.go}` and tests and `testdata/`
  - `internal/api/handlers_engines.go`, `handlers_nodes.go`
  - `native/Package.swift`, `native/Sources/**`, `native/Tests/**`
- **Change:**
  - `internal/link/*` (return Profile)
  - `internal/xray/config.go` (from Profile)
  - `internal/xray/runner.go` (moves to `engine`)
  - `internal/core/manager.go` (multi-engine)
  - `internal/service/*`, `internal/models/*`, `internal/api/server.go`, `handlers.go`
  - `cmd/xray-friendly/main.go`, `Makefile`, `native/Info.plist`, `scripts/smoke.sh` (preview, engines aliases)
  - README, PLAN
- **Remove:** `native/XrayFriendlyApp.swift`, once the SwiftUI app replaces it in Phase 4.

## 5. Test strategy

- **Unit:**
  - every parser, both config builders (golden JSON per protocol, run through `xray -test` / `sing-box check` when `XF_IT=1`)
  - engine selection matrix, migration v2 → v3
  - tar.gz extractor (traversal, symlink and size-cap cases, mirroring the zip tests)
  - sing-box digest verification (match, mismatch, missing digest → refuse)
- **API:**
  - new endpoints, including "preview never writes the store" and "preview never fetches"
  - token, Host and Origin enforced on every new route
- **Smoke:** extended with preview, `/api/engines` and `/api/cores` alias checks.
- **Swift:** `swift test` for the API client and view models; `make app` builds and signs (`codesign --verify --strict`).
- **Manual:** the acceptance checklist; dark mode and VoiceOver passes need your eyes (see Phase 5).

## 6. Risks

| # | Risk | Mitigation |
|---|---|---|
| R1 | sing-box config schema changes between minor versions (1.11 → 1.12 removed legacy DNS and special outbounds). | Target ≥ 1.12. Treat "this engine version is too old" as a `Supports` reason. Golden tests plus `sing-box check` in integration tests. |
| R2 | Size: Phase 4 is most of the work (six screens, ~3–4k lines of Swift). | Ship screens one at a time inside Phase 4; Main and MenuBar first, so the app is usable throughout. |
| R3 | sing-box has no `geosite.dat`; geosite/geoip rules need `.srs` rule sets, which sing-box fetches remotely by default. | Download the rule sets alongside the engine (same GitHub allow-list, verified by API digest) and reference them as local files. Never fetch at runtime. If a rule can't be mapped, connect fails with a clear reason instead of silently dropping the rule. |
| R4 | Hysteria2 is supported by both engines, but features differ (obfs only in sing-box; insecure only in sing-box). | Capability-based selection (§Phase 1.4), unit-tested as a matrix. |
| R5 | The Scan-QR-on-screen flow needs Screen Recording permission, and macOS asks once per app. | Ask only when the button is pressed. Explain why in the prompt string; fall back to Open File. |
| R6 | Unsigned app: `SMAppService` login item and Screen Recording need a stable signature. | Ad-hoc signing works locally; real distribution needs a Developer ID (out of scope, as before). |

## 7. Decisions (approved 2026-10-29)

- **Q1 — Menu-bar icon:** SF Symbol shield (`checkmark.shield` when connected), template image. The pixel logo stays the app icon.
- **Q2 — Unmocked views:** built from the existing settings fields, in the visual language of the Engines tab; reviewed by you before Phase 5.
- **Q3 — Country codes:** taken from the node name (leading flag emoji or ISO code), with the emoji removed from the display name. No GeoIP lookups.
- **Q4 — `web/`: deleted in Phase 1.** The Go server becomes API-only. Until the native window lands in Phase 4, the menu-bar menu still works (Connect, Disconnect, Pick Fastest), but adding servers needs the API directly.
- **Q5 — YAML:** add `gopkg.in/yaml.v3`.
- **Q6 — sing-box verification:** the GitHub release API `digest` (`sha256:`) is the checksum source; a missing digest refuses the download.
- **Q7 — Minimum macOS 14 Sonoma.**
