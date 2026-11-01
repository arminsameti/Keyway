# Keyway — macOS redesign handoff

Design canvas (source of truth, interactive): https://claude.ai/artifact/93MWk2QcZTqxzxY2ip2Feb
Screen sources: `design/screens/*.dc.html` — HTML mockups. Read them for exact layout, copy, sizes and colors.
The `<script data-dc-script>` block at the bottom of each file holds the sample data and state logic (which
states exist, what each control does). They are **reference mockups, not production code** — don't ship them.

## Goal

Replace the current 3-column emoji web UI (`web/`) with a native-feeling macOS app, and add support for more
protocols via a second engine (sing-box).

**Recommended implementation:** SwiftUI in `native/`, talking to the existing Go API on 127.0.0.1
(keep the token/Host/Origin security model). Map screens to native components:

| Screen file | SwiftUI |
|---|---|
| `Main.dc.html` | `WindowGroup` + `NavigationSplitView` (sidebar · content · inspector via `.inspector`) , `Table` for servers |
| `MenuBar.dc.html` | `MenuBarExtra(...).menuBarExtraStyle(.window)` |
| `Import.dc.html` | `.sheet` on the main window |
| `NewServer.dc.html` | separate `Window` scene (or sheet), `Form` with `.formStyle(.grouped)` |
| `Settings.dc.html` | `Settings` scene with `TabView` (General, Proxy, Routing, Engines, Advanced) |
| `Onboarding.dc.html` | first-launch `Window`, shown when no core or no servers |

If you keep the web UI instead, rebuild `web/` to match these screens exactly (same CSP rules: no inline script/style,
no innerHTML) — but native is preferred.

## Visual rules

- System font (SF Pro), 13 px body, 11 px secondary, 15–17 px titles. Use system semantic colors natively; the mockup
  hexes are the light-mode reference.
- Accent `#0064D2` (darker than system blue so white-on-accent passes 4.5:1). Natively: `.tint` / AccentColor asset.
- Status colors: connected green `#28A745` (fills) / `#1A7F37` (text); warn `#A64B00`; error `#B3261E`; secondary text `#6E6E73`.
- Latency label: <100 ms green "Fast", <200 orange "OK", else red "Slow"; `Timeout` red; `n/a` gray (UDP protocol in TCP mode).
- No emoji anywhere. Icons = SF Symbols (globe, dot.radiowaves.up.forward, arrow.triangle.branch, waveform.path.ecg,
  cpu, bolt, plus, magnifyingglass, doc.on.doc, qrcode, checkmark.shield).
- Support Dark Mode (MenuBar mockup has a dark tweak showing the palette), Dynamic Type-ish sizing, full keyboard
  navigation, VoiceOver labels on icon-only buttons.

## Behavior per screen

**Main window**
- Sidebar: Servers (count), Subscriptions, Routing, Activity (logs) · Engines. Footer card shows System Proxy state.
- Toolbar: title + "N servers · N protocols · N sources", search field, "Test Latency" split button
  (menu: TCP quick test / Real test), Add (+ → Import sheet). Shortcuts: ⌘T test, ⌘N add, ⌘F search.
- Connection card: status, active server + latency, protocol · transport, uptime, routing mode; "Auto-select fastest"
  checkbox (maps to `settings.autoPick`); Connect/Disconnect button.
- Protocol filter chips (All + each protocol with counts), only show protocols present.
- Table grouped by source (subscription name + "updated X ago" + format, then "Added Manually").
  Columns: status dot, country code + name (+ "Active"), Protocol, Transport, Latency (sortable). Single-click selects,
  double-click / Return connects. Context menu: Connect, Test, Copy Link, Show QR, Edit, Delete.
- Inspector: name, source, latency, Address, Port, Protocol, Transport, Security, SNI, Engine; Connect/Disconnect,
  Copy Link, QR Code; local proxy ports + "Copy terminal export command".

**Menu bar popover** — status + big switch, "Choose Fastest Automatically", top 5 servers by latency with checkmark,
"All Servers ▸", System Proxy switch with ports, commands: Test Latency ⌘T, Add Servers from Clipboard ⇧⌘V,
Open… ⌘O, Settings… ⌘,, Quit ⌘Q. Menu bar icon: shield, with checkmark when connected.

**Add Servers sheet** — segmented: Paste Links / Subscription URL / File or QR Image. Live preview list of parsed
results before adding: ready (green check, name, protocol · transport, engine if sing-box), subscription (https lines),
skipped (warning + reason). Primary button states the count ("Add 4 Servers & 1 Subscription"). "Enter Manually…"
opens New Server. Needs a **dry-run parse endpoint** (see API).

**New Server** — left list of protocols grouped by engine; right grouped form: Server (name, address, port),
Authentication (per protocol, see `defs` in NewServer.dc.html script — exact fields), then Transport & Security
(VLESS/VMess/Trojan), TLS (TLS-based QUIC/HTTP protocols) or Network (WireGuard). Engine badge top right.
Footer: Test Connection, Cancel, Add Server. Pasting a link anywhere fills the form.

**Settings › Engines** — cards for Xray core and sing-box: installed version, protocols handled, update state,
Update / Other versions / Check Now. Behavior: engine preference when both support a protocol, auto-download engine
when needed, update check frequency, latency method. Local proxy ports (SOCKS 10808, HTTP 10809), Allow LAN
(requires credentials — existing S6 rule).

**Onboarding** — 3 steps: engine download (with progress), add servers (Paste / Scan QR on screen / Open File),
connect. "Open at login and keep in the menu bar" checkbox; "Skip for Now".

## New protocols & backend work

| Protocol | Engine | Link scheme |
|---|---|---|
| VLESS, VMess, Trojan, Shadowsocks, SOCKS5 | Xray (existing) | existing |
| HTTP / HTTPS upstream | Xray | `http://`/`https://` only in manual form (import box keeps treating https as subscription) |
| Hysteria2 | Xray (existing) | `hysteria2://`, `hy2://` |
| WireGuard | Xray | `wireguard://`, `wg://`, and `.conf` files |
| TUIC v5 | sing-box | `tuic://` |
| Hysteria v1 | sing-box | `hysteria://` |
| AnyTLS | sing-box | `anytls://` |
| ShadowTLS v3 | sing-box | sing-box JSON / Clash only |
| NaiveProxy | sing-box | `naive+https://` |
| SSH | sing-box | manual form |
| ShadowsocksR | — | recognized and skipped with a clear reason |

Subscriptions: add Clash YAML and sing-box JSON parsing alongside base64 (currently "deferred" in PLAN.md).

Suggested structure:
- `internal/engine`: interface `Engine{ Name(); Supports(protocol) bool; BuildConfig(...); Run/Test/Probe }`;
  move `internal/xray` behind it; add `internal/singbox` (config builder + runner, same `-test`/check preflight,
  startup-grace and crash-detection semantics as the Xray runner).
- `internal/core` → generalize to download/verify both engines (GitHub host allow-list, checksum verification,
  safe extraction — keep S2–S4 guarantees). sing-box releases publish checksums; verify them.
- `models.Node`: add `Engine` (derived at parse time) and keep RawLink authoritative; for manually created nodes store
  a canonical link or a typed JSON blob.
- `internal/link`: register new parsers; parser returns protocol, transport, security, engine, display name.
- Service: pick engine per node at connect; latency "real" test must run through the right engine; TCP mode = n/a for
  UDP protocols (Hysteria*, TUIC, WireGuard).

API additions:
- `POST /api/import/preview` → parsed items `{status: ready|subscription|skipped, name, protocol, transport, engine, reason}` without saving.
- `POST /api/nodes` (manual create) and `PUT /api/nodes/{id}` (edit).
- `GET /api/engines`, `POST /api/engines/{name}/download|use|check` (keep `/api/cores*` as aliases during transition).
- `GET /api/status` should include uptime, active node latency, engine name.

## Acceptance checklist

- [ ] All six screens implemented, matching layout/copy of the mockups; light + dark mode.
- [ ] Every control reachable by keyboard; VoiceOver labels; text contrast ≥ 4.5:1.
- [ ] Import preview shows ready/subscription/skipped before saving.
- [ ] New protocols parse, connect and latency-test on the correct engine; unit tests per parser and config builder.
- [ ] Engine downloads verified; existing security tests still pass (`make test`, `make smoke`).
