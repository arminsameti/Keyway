# v2ray-core engine — design

Status: draft for review. Scope: v2ray-core as a selectable engine. Depends on the uncommitted Tor work on
`feature/tor`, which changes the same engine files.

## Goal

Users can choose v2ray-core (`v2fly/v2ray-core`) to run the servers it fully supports. Keyway downloads,
verifies, updates and switches it like Xray and sing-box. Nothing changes for anyone who does not choose it.

Success: a VMess, Trojan or VLESS-over-TLS server connects and carries traffic through the real `v2ray`
binary, the user can see that it did, and a server is never run with a setting silently dropped.

## Decisions

- **Opt-in only.** It is selected by a new preference value, `v2ray`, and sits last in the engine list.
- **Wrapper, not a new builder.** `internal/v2ray` calls the Xray config builder and adapts the result. This
  keeps inbound, routing, DNS and stats logic in one place.
- **Strict allowlist.** Every server v2ray-core accepts must be a subset of what `xray.Supports` accepts, so
  the wrapper can always build on the Xray builder.
- **Older JSON format (v4).** v5's native format is not used.
- **Not a route to more protocols.** Hysteria2 is left out of this version even though v2ray-core has it.

## Findings from v5.53.0

Tested on darwin/arm64 with local VMess servers.

| Check | Result |
|---|---|
| Keyway-shaped config with SOCKS and HTTP inbounds, geo rules, stats, sniffing | Loads and carries traffic |
| Two-hop VMess chain over TCP with `proxySettings` | Passed through both hops, shown in both access logs |
| `v2ray api stats -json --server=<addr>` | Per-outbound counters; a zero counter has no `value` key |
| `v2ray test` on a config it rejects | Exits 1 |
| `sockopt.dialerProxy` | **Passes `v2ray test`, then is silently ignored: the hop is skipped** |
| Reality and `flow: xtls-rprx-vision` | Pass `v2ray test`; assumed ignored, not run live |
| `network: httpupgrade`, `network: xhttp`, Shadowsocks 2022 ciphers | Rejected with an error |

`v2ray test` therefore cannot be the safety net for unknown fields. The allowlist and the output check in
section 2 are.

Not yet tested, and required by the first implementation task:

- **`proxySettings.transportLayer`.** v2ray's documentation says `streamSettings` do not apply to an outbound
  using `proxySettings` unless `transportLayer` is true. The probe used plain TCP, so it could not show this.
  A chained hop with TLS must be proven to still use TLS.
- **Password-protected SOCKS bridge.** Both the inbound and outbound side between processes.
- **TLS `fingerprint`.** Whether the v4 format honours it, shown by inspecting a real ClientHello.

## 1. Allowlist (`internal/v2ray`)

`v2ray.Supports(p)` first requires `xray.Supports(p) == nil`, then allows only the following.

| Setting | Allowed |
|---|---|
| Protocols | VMess, Trojan, Shadowsocks (non-2022 ciphers), SOCKS, HTTP, VLESS |
| VLESS | `Security.Kind == "tls"`, empty `Flow`, `Encryption` empty or `none` |
| Transports | `tcp`, `ws`, `grpc`, `h2`, `kcp` |
| Security | `none` or `tls` |

Rejected, each with a reason naming the engine that can run it:

- Reality, `Flow`, XHTTP, HTTPUpgrade, Shadowsocks 2022, WireGuard, Hysteria2, all sing-box-only protocols
- Custom configs and Tor
- `Security.PinSHA256` and `Security.Insecure`
- `Transport.Authority` on gRPC
- `Overrides.Fragment`
- `Security.Fingerprint` or `Overrides.Fingerprint` set, unless the first implementation task proves
  fingerprints are honoured. If it does, this line is removed from the code and this spec.

Pinning stays off v2ray-core because Keyway writes `pinnedPeerCertSha256` as hex, while v2ray's field is
`pinnedPeerCertificateChainSha256`. An ignored pin would look like protection and give none.

`SupportsSegment` applies `Supports` to every hop, and allows chaining and upstream bridges only for hops that
pass Xray's TCP-stream rule (`kcp` is excluded).

## 2. Config building

`v2ray.BuildConfig` and `v2ray.ProbeConfig`:

1. Check `SupportsSegment`.
2. Call `xray.BuildConfig` or `xray.ProbeConfig`.
3. For each outbound with `sockopt.dialerProxy`, set `proxySettings` to that tag with `transportLayer: true`,
   and clear the sockopt.
4. Refuse the config if it still contains an Xray-only key: `dialerProxy`, `realitySettings`,
   `xhttpSettings`, `httpupgradeSettings`, `flow`, `pinnedPeerCertSha256` or `fragment`.

Step 4 walks the marshalled JSON, so it also catches these keys if the Xray builder later emits them on a new
path. `internal/xray` gains only a `ProxySettings` field on `Outbound`.

## 3. Engine and download

- `engine.V2Ray` in `internal/engine/v2ray.go`: name `v2ray`, display name `V2Ray core`.
- `Check` runs `v2ray test -c <cfg>` with `V2RAY_LOCATION_ASSET` set. `Launch` runs `v2ray run -c <cfg>` with
  the same variable. Keyway's config files already end in `.json`, which v2ray uses to detect the format.
- `core.V2RaySource`: repo `v2fly/v2ray-core`, `ArchiveZip`, `ChecksumDgst`, members `v2ray`, `geoip.dat` and
  `geosite.dat`, assets `v2ray-macos-arm64-v8a.zip` and `v2ray-macos-64.zip`. The real `.dgst` file has the
  `SHA2-256= <hex>` line that `parseSHA256` already reads.
- `cmd/keywayd/main.go` adds the slot after Tor, last in the list. Xray and sing-box keep their rank, so the
  default plan for every server is unchanged.

## 4. Selection

- `models.enginePrefs` gains `v2ray`. `EnginePreference` keeps its `xray` default.
- With preference `v2ray`, the existing planner picks it for servers it supports. Other servers go to Xray or
  sing-box.
- The planner still prefers an installed engine in a tie. Choosing the preference without installing v2ray-core
  leaves servers on an installed engine.
- Settings that need sing-box (TUN, per-app rules) keep the existing sing-box relay after a v2ray-core step.

## 5. Traffic stats

`trafficSourceFor` gains a v2ray branch running `v2ray api stats -json --server=<addr>`. The output has the
shape `parseXrayStats` already reads, including string values and missing `value` keys, so that parser is reused.

## 6. App

- `Panes.swift`: add "Prefer V2Ray core". Change the row label to "When more than one engine supports a
  protocol".
- `Panes.swift` engine card and `Palette.engineBadge`: `V2` badge with its own colour.
- `link/encode.go`, custom configs and the `/api/cores*` routes are untouched.
- README: add v2ray-core to the engine table. The tagline can then say Xray, V2Ray and sing-box truthfully.

## 7. Errors

- A server v2ray-core cannot run is never an error while another engine can run it. The planner's existing
  reason list covers the case where none can.
- If step 4 of section 2 trips, connecting fails with the offending key named. It is a bug, not a fallback.
- `v2ray test` output goes through the same tail logic as the other engines.

## 8. Testing

Unit tests:

- Allowlist: each row and rejection in section 1.
- Golden configs: single hop, chain, upstream bridge, relay-fed segment.
- A chained config has `proxySettings` with `transportLayer: true` and no `dialerProxy` key.
- Fail-closed: a config holding each listed key is refused.
- `parseXrayStats` with the recorded v2ray output, including missing values.
- Planner: default preference gives plans identical to before, and preference `v2ray` picks v2ray-core only
  for supported hops.
- `.dgst` parsing against the real v5.53.0 file.

Integration test, skipped unless `KEYWAY_V2RAY_BIN` is set: local servers, the generated config, a two-hop
chain with TLS on the exit, access logs on both hops, stats non-zero.

Manual: download from Settings › Engines, choose the preference, connect to a real server, confirm the plan
shows V2Ray core.

## Out of scope

- v5 native config format
- Hysteria2 and any other protocol beyond the allowlist
- Custom configs for v2ray-core
- Making v2ray-core a default for any protocol
- The v2fly listing PR, which follows once this is released
