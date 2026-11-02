# v2ray-core Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add v2ray-core as an opt-in third proxy engine that runs only servers whose every setting it honours.

**Architecture:** `internal/v2ray` holds a strict allowlist and wraps the Xray config builder, converting chain dialing to `proxySettings` and refusing any remaining Xray-only key. `engine.V2Ray` plugs that into the existing planner, last in the engine list, so plans change only when the user picks the `v2ray` preference.

**Tech Stack:** Go, SwiftUI, v2ray-core v5.53.0 (v4 JSON config format).

**Spec:** `docs/superpowers/specs/2026-11-01-v2ray-design.md`

## Global Constraints

- Engine name `v2ray`; display name `V2Ray core`; preference value `v2ray`; `EnginePreference` default stays `xray`.
- Engine slot goes last in `cmd/keywayd/main.go`, after Tor.
- Everything `v2ray.Supports` accepts must also pass `xray.Supports`.
- Never rely on `v2ray test` to reject an unknown field: it silently ignores them.
- The Tor work on `feature/tor` is uncommitted and touches the same files. It must be committed, by the user, before Task 1, so each task's commit holds only that task's change.
- The repo has no Go tests yet. Add `_test.go` files beside the code. Use the standard `testing` package only.
- The probe binary is at `/private/tmp/claude-501/-Users-armin-Projects-xray-friendly/d1a57e05-fc5d-4ca9-9db7-6e7029048589/scratchpad/v2ray-bin/v2ray`. If it has been cleaned up, download `v2ray-macos-arm64-v8a.zip` from release v5.53.0 and verify SHA-256 `75d0b4bf571b33aff8fb3eacb4a7ff16061a2d227503d75c5247852ef0958b15`.

## Review Focus

1. A saved preference of `v2ray` when v2ray-core is not installed and neither is any other capable engine: the user should get the normal "download it" flow, not an error. Test in Task 3.
2. A chain mixing supported and unsupported hops, such as `VMess → Reality`, under preference `v2ray`: each hop must land on an engine that can run it, with a loopback bridge between them. Test in Task 3.
3. A per-server override that adds a fragment or fingerprint to a server v2ray-core otherwise supports: the server must move to Xray, not lose the override. Test in Task 2.
4. An upgrade where an older Keyway reads a `v2ray` preference after a downgrade: validation rejects it there, which is accepted and noted in the Task 3 commit message. Nothing to build.
5. An imported Shadowsocks server with a `2022-` cipher in mixed case: the check must be case-insensitive. Test in Task 2.

---

### Task 1: Prove the three open behaviours

Throwaway work in the scratchpad. No repo code. This task decides the fingerprint rule for Task 2.

**Files:**
- Modify: `docs/superpowers/specs/2026-11-01-v2ray-design.md` (findings table; the fingerprint line, if proven)

**Interfaces:**
- Produces: a yes or no for each question below, recorded in the spec.

- [ ] **Step 1: TLS on a chained hop**

Make a self-signed certificate. Run a VMess-over-TLS v2ray server as the exit and a plain VMess server as the first hop. Run a client with `"proxySettings":{"tag":"hop-1","transportLayer":true}` on the exit, then repeat without `transportLayer`.

Expected: with `transportLayer: true`, traffic flows and both access logs show it. Without it, the exit connection fails or arrives without TLS. If `transportLayer: true` does not work, stop and report: the chaining design must change.

- [ ] **Step 2: Password-protected SOCKS bridge**

Run one v2ray process with Keyway's bridge inbound shape (`auth: password`, `accounts:[{user,pass}]`). Run a second with a `socks` outbound using `servers:[{address,port,users:[{user,pass}]}]`, and send traffic through it.

Expected: traffic flows, and a wrong password is refused.

- [ ] **Step 3: TLS fingerprint**

Point a client with `tlsSettings.fingerprint: "chrome"` at a local listener that records the ClientHello. Compare with a run without the field.

Expected: if the two hellos differ, fingerprints are honoured. Remove the fingerprint rejection from spec section 1. Otherwise leave it.

- [ ] **Step 4: Record the results in the spec**

Update the findings table and move each item out of "Not yet tested".

- [ ] **Step 5: Commit**

```bash
git add docs/superpowers/specs/2026-11-01-v2ray-design.md
git commit -m "docs: record v2ray-core chaining and fingerprint findings"
```

### Task 2: `internal/v2ray` allowlist and config adapter

**Files:**
- Modify: `internal/xray/types.go` (`Outbound`, near line 91)
- Create: `internal/v2ray/config.go`
- Test: `internal/v2ray/config_test.go`

**Interfaces:**
- Produces:
  - `xray.ProxySettings{Tag string "tag"; TransportLayer bool "transportLayer"}` and `Outbound.ProxySettings *ProxySettings` (`json:"proxySettings,omitempty"`)
  - `v2ray.Supports(p profile.Profile) error`
  - `v2ray.SupportsSegment(hops []profile.Profile, hasUpstream bool) error`
  - `v2ray.BuildConfig(seg profile.Segment, s models.Settings) ([]byte, error)`
  - `v2ray.ProbeConfig(seg profile.Segment, port int) ([]byte, error)`

- [ ] **Step 1: Write the failing tests**

- `TestSupportsAllowed`, table-driven: VMess over TCP, WS, gRPC, H2 and KCP; Trojan over TLS; Shadowsocks `aes-128-gcm`; SOCKS; HTTP; VLESS with TLS all return nil.
- `TestSupportsRejected`, table-driven, each asserting a non-nil error: Reality; VLESS with `Flow` set; VLESS without TLS to a private address; VLESS with `Encryption` not `none`; XHTTP; HTTPUpgrade; `2022-blake3-aes-128-gcm`; `2022-BLAKE3-AES-128-GCM`; WireGuard; Hysteria2; TUIC; Custom; Tor; `PinSHA256` set; `Insecure` set; gRPC with `Authority`; `Overrides.Fragment` set; and `Security.Fingerprint` or `Overrides.Fingerprint` set, unless Task 1 proved fingerprints work.
- `TestSupportsSegmentKCPNotChained`: one KCP hop is nil; two hops with KCP, or KCP with `hasUpstream`, return an error.
- `TestBuildConfigChain`: for two VMess hops, the unmarshalled exit outbound has `proxySettings == {"tag":<hop tag>,"transportLayer":true}`, and the output contains no `dialerProxy`.
- `TestBuildConfigUpstream`: a segment with `Upstream` has `proxySettings.tag == "bridge"` on the first hop.
- `TestRefuseXrayKeys`, table-driven over `dialerProxy`, `realitySettings`, `xhttpSettings`, `httpupgradeSettings`, `flow`, `pinnedPeerCertSha256`, `fragment`: `refuseXrayKeys` returns an error naming the key, at any JSON depth.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/v2ray/`
Expected: FAIL to compile, `undefined: Supports`.

- [ ] **Step 3: Implement `internal/v2ray/config.go`**

`Supports` starts with `xray.Supports`, and the allowlist in spec section 1 follows it. Rejection messages name the engine that can run the server. `SupportsSegment` mirrors `xray.SupportsSegment`, adding `Supports` per hop and calling `xray.SupportsSegment` for the TCP rule.

`BuildConfig` calls `xray.BuildConfig`, then `adapt(cfg)` moves each `StreamSettings.Sockopt.DialerProxy` to `ProxySettings{Tag, TransportLayer: true}` and sets `Sockopt` to nil. It marshals with `json.MarshalIndent`, then calls `refuseXrayKeys(b []byte) error`, which walks decoded JSON recursively. `ProbeConfig` is the same around `xray.ProbeConfig`.

`refuseXrayKeys` errors wrap as `internal error: v2ray config contains %q`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/v2ray/ ./internal/xray/ && go vet ./internal/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/xray/types.go internal/v2ray
git commit -m "feat: add v2ray-core allowlist and config adapter"
```

### Task 3: Engine, download source and selection

**Files:**
- Create: `internal/engine/v2ray.go`
- Modify: `internal/engine/engine.go:17-20`, `internal/core/manager.go` (beside `SingBoxSource`, near line 94), `internal/models/validate.go:24`, `internal/models/types.go:84`, `internal/service/traffic.go:142`, `cmd/keywayd/main.go:94-106`
- Test: `internal/engine/plan_test.go`, `internal/core/manager_test.go`, `internal/service/traffic_test.go`, `internal/models/validate_test.go`

**Interfaces:**
- Consumes: `v2ray.Supports`, `SupportsSegment`, `BuildConfig`, `ProbeConfig` from Task 2.
- Produces: `engine.NameV2Ray = "v2ray"`, `engine.V2RayDisplayName = "V2Ray core"`, `engine.V2Ray{}` implementing `Engine`, and `core.V2RaySource`.

- [ ] **Step 1: Write the failing tests**

`plan_test.go`, using `[]Engine{Xray{}, &SingBox{}, V2Ray{}}`:
- `TestDefaultPreferenceSkipsV2Ray`: with preference `xray` and all engines installed, a VMess server plans on `xray`.
- `TestV2RayPreferencePicksSupported`: with preference `v2ray`, VMess plans on `v2ray`, and Reality VLESS plans on `xray`.
- `TestV2RayPreferenceNotInstalled`: with preference `v2ray` and v2ray-core not installed, VMess plans on `xray` with no error.
- `TestV2RayPreferenceNothingInstalled`: with nothing installed, `PlanSegments` returns a `*NotInstalledError`.
- `TestV2RayMixedChain`: `VMess → Reality` under preference `v2ray` plans a working split: every hop lands on an engine that passes `SupportsSegment`.

`manager_test.go`: `TestParseSHA256V2RayDgst` feeds the real four-line `.dgst` text and expects `75d0b4bf…8b15`. `TestV2RaySourceFiles` asserts `Files` holds exactly `v2ray`, `geoip.dat`, `geosite.dat`.

`traffic_test.go`: `TestParseStatsV2RayOutput` feeds this recorded `api stats -json` output and expects up `1688`, down `1460`:

```json
{"stat":[{"name":"outbound>>>direct>>>traffic>>>uplink"},{"name":"outbound>>>proxy>>>traffic>>>uplink","value":"584"},{"name":"outbound>>>proxy>>>traffic>>>downlink","value":"647"},{"name":"outbound>>>hop-1>>>traffic>>>uplink","value":"1104"},{"name":"outbound>>>hop-1>>>traffic>>>downlink","value":"813"}]}
```

`validate_test.go`: `v2ray` is accepted as a preference; `v3ray` is rejected.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/engine/ ./internal/core/ ./internal/service/ ./internal/models/`
Expected: FAIL to compile, `undefined: V2Ray`.

- [ ] **Step 3: Implement**

- `engine/v2ray.go` follows `engine/xray.go`. `Check` uses `exec.CommandContext` with a 15-second timeout, `v2ray test -c <path>`, `V2RAY_LOCATION_ASSET=<AssetDir>`, and `TailOf` for errors, as `Tor.Check` does. `Launch` uses `Args: {"run", "-c", cfgPath}` with the same variable.
- `core.V2RaySource`: `Name` `V2Ray core`, `Repo` `v2fly/v2ray-core`, `Binary` `v2ray`, `ArchiveZip`, `ChecksumDgst`, the `Files` map modelled on `XraySource`. `Assets` returns `v2ray-macos-arm64-v8a.zip` on arm64 and `v2ray-macos-64.zip` on amd64, with `xrayAssets` as the model.
- `enginePrefs` adds `v2ray`, and the comment at `types.go:84` is updated.
- `trafficSourceFor` adds a `NameV2Ray` branch: `exec.CommandContext(ctx, in.Bin, "api", "stats", "-json", "--server="+addr)`, parsed by `parseXrayStats`.
- `main.go` adds a manager at `filepath.Join(enginesDir, engine.NameV2Ray)` and a final slot `{Engine: engine.V2Ray{}, Manager: v2rayCores}`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./... && go build ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal cmd
git commit -m "feat: add opt-in v2ray-core engine

An older Keyway rejects the v2ray preference on downgrade."
```

### Task 4: End-to-end test against the real binary

**Files:**
- Create: `internal/v2ray/integration_test.go`

**Interfaces:**
- Consumes: `v2ray.BuildConfig` from Task 2.

- [ ] **Step 1: Write `TestChainEndToEnd`**

`t.Skip` unless `KEYWAY_V2RAY_BIN` is set. Start a local HTTP target, a plain VMess first hop and a VMess-over-TLS exit, each with an access log. Build a client config with `BuildConfig`, run it, and fetch through its SOCKS inbound.

Assert: the body matches, both access logs have a line, and `api stats -json` shows a non-zero `proxy` counter.

- [ ] **Step 2: Run it**

Run: `KEYWAY_V2RAY_BIN=<probe binary> go test ./internal/v2ray/ -run TestChainEndToEnd -v`
Expected: PASS, not SKIP.

- [ ] **Step 3: Commit**

```bash
git add internal/v2ray/integration_test.go
git commit -m "test: run a two-hop chain through the real v2ray binary"
```

### Task 5: App and README

**Files:**
- Modify: `native/Sources/Keyway/Views/Panes.swift:285-288,376`, `native/Sources/Keyway/Palette.swift:53-55`, `README.md`

**Interfaces:**
- Consumes: engine name `v2ray` and the preference value from Task 3.

- [ ] **Step 1: Update the Settings pane**

Add `Text("Prefer V2Ray core").tag("v2ray")`. Set the row label to `When more than one engine supports a protocol`. Change the card glyph so `v2ray` shows `V2`.

- [ ] **Step 2: Add the badge colour**

`Palette.engineBadge` gets a distinct `v2rayBadge`, using the same structure as `singBoxBadge`. It needs readable contrast in light and dark mode.

- [ ] **Step 3: Update the README**

Add a V2Ray core row to the engine table listing the allowlist's protocols, note that it's opt-in, and restore the tagline to `**A native macOS client for Xray, V2Ray and sing-box, with proxy chaining.**`.

- [ ] **Step 4: Verify**

Run: `make app` and launch the app.
Expected: Settings › Engines shows a V2Ray core card, Download installs v5.53.0, "Prefer V2Ray core" sticks after restart, and a VMess server's plan shows `V2Ray core`.

- [ ] **Step 5: Commit**

```bash
git add native README.md
git commit -m "feat: add V2Ray core to engine settings"
```
