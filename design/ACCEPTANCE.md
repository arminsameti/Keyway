# Acceptance — macOS redesign

The checklist from `DESIGN_HANDOFF.md`, with the evidence for each item. 2026-10-29.

| # | Item | Status | Evidence |
|---|---|---|---|
| 1 | All six screens implemented, matching layout/copy of the mockups; light + dark mode | **Done.** Final look still needs your eyes in the live app. | `make snapshots` renders Main (connected and idle), MenuBar, Import, New Server, Settings › Engines and Onboarding with the mockups' sample data, in light and dark. Compared against `design/screens/*.dc.html`, and the differences found were fixed (list below). Offscreen renders show no window toolbar and draw prominent buttons grey (the window is never key); both are rendering limits, not app behaviour. |
| 2 | Every control reachable by keyboard; VoiceOver labels; text contrast ≥ 4.5:1 | **Done for contrast and shortcuts. Keyboard and VoiceOver were audited in code only**, not with VoiceOver running. | `ContrastTests` checks 26 text/background pairs in light and dark, including macOS's real window backgrounds. Shortcuts: ⌘T, ⌘N, ⌘F, ⌘O, ⇧⌘V, ⌘, and ⌘Q; Return or double-click connects; Escape and Return work in sheets. Icon-only buttons are labelled and decorative images hidden. |
| 3 | Import preview shows ready/subscription/skipped before saving | **Done** | `POST /api/import/preview`. Tests prove it saves and fetches nothing (`TestImportPreviewSavesNothing`, smoke). The sheet's primary button states the counts. |
| 4 | New protocols parse, connect and latency-test on the correct engine; unit tests per parser and config builder | **Done.** NaiveProxy traffic not tested. | Parser and fixture tests in `internal/link`, builder tests in `internal/xray` and `internal/singbox`, and a selection matrix in `internal/engine`. Verified live: WireGuard on Xray 26.3.27; TUIC, Hysteria2 with obfuscation, AnyTLS, Hysteria v1, insecure Trojan and ShadowTLS v3 on sing-box 1.14.4. NaiveProxy passes sing-box's own config check, but there was no NaiveProxy server with a trusted certificate to test traffic against. |
| 5 | Engine downloads verified; existing security tests still pass (`make test`, `make smoke`) | **Done** | Xray is checked against its `.dgst` file, sing-box against GitHub's API digest, and rule sets against their git blob hash. Tampered or missing checksums are refused (tests). Token, Host and Origin checks are tested on every route. |

## Differences from the mockups (deliberate)

- **The protocol chips wrap onto a second line** when they don't fit, like the mockup's `flex-wrap`.
- **Two text colours are slightly darker** to reach 4.5:1 on macOS's real window background: secondary `#6E6E73` → `#68686D`, green text `#1A7F37` → `#1A7A35`. The reasons are noted next to the values in `DesignColors.swift`.
- **The New Server form shows extra fields only when a choice needs them:** Short ID for Reality, Host for WebSocket/HTTP-style transports, an obfuscation password for Salamander, and a password for SSH password login.
- **NaiveProxy's TLS section has only the server name**, because sing-box rejects ALPN and pinning for NaiveProxy.
- **The sidebar's Engines item** opens the Engines settings pane inside the main window.

## Fixed during review

- Port numbers showed as `10,808` (SwiftUI number formatting).
- Empty badge bubbles appeared next to Routing and Activity.
- The protocol chips scrolled sideways instead of wrapping.
- The inspector's main button wasn't full width.
- The System Proxy switch wasn't at the card's trailing edge.
- "All Servers" in the menu bar looked like an accent-coloured pull-down.
- New Server set field labels in monospace, and its UDP note was right-aligned.
- Onboarding's step text was cut off.
- ⌘F relied on a hidden button; it is now a menu command (Edit › Find Servers).
- The status dot read an empty VoiceOver label on rows that aren't active.
