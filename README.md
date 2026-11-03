<div align="center">

<img src="assets/icon.png" alt="Keyway logo: a keyhole with a three-hop route through it" width="120">

# Keyway

**A native macOS client for Xray, sing-box, V2Ray core, Mihomo and Tor, with proxy chaining.**

Import a link or subscription, chain servers together, and connect in one click.
Built in SwiftUI. No Electron, no web view, no config files.

[**Download for macOS**](https://github.com/arminsameti/keyway/releases/latest) · [Features](#features) · [FAQ](#faq) · [Docs](#documentation) · [Contribute](CONTRIBUTING.md)

![Platform](https://img.shields.io/badge/macOS-14%2B-black) ![Apple silicon and Intel](https://img.shields.io/badge/Apple%20silicon%20%2B%20Intel-universal-blue) ![License: MIT](https://img.shields.io/badge/license-MIT-green)

<img src="docs/screenshots/servers-light.png#gh-light-mode-only" alt="Keyway server list on macOS, connected, with latency per server" width="860">
<img src="docs/screenshots/servers-dark.png#gh-dark-mode-only" alt="Keyway server list on macOS in dark mode, connected, with latency per server" width="860">

</div>

Keyway is a free, open-source macOS app for people who use **Xray-core**, **sing-box**, **V2Ray core**, **Mihomo** or **Tor** and want a client that feels like a Mac app. It downloads and manages the engines, picks the right one for every server, and lets you build **multi-hop proxy chains** across protocols.

## Install

```bash
brew tap arminsameti/tap
brew trust arminsameti/tap   # recent Homebrew versions ask you to trust third-party taps
brew install --cask keyway
```

Or download `Keyway-<version>-macOS.dmg` from the [latest release](https://github.com/arminsameti/Keyway/releases/latest), drag it to **Applications** and open it. It needs macOS 14 Sonoma or later, on Apple silicon or Intel.

The builds are not notarized yet, so a manual download may be refused on first launch. Right-click the app, choose **Open**, then confirm. If that still fails, run `xattr -dr com.apple.quarantine /Applications/Keyway.app` once. Homebrew does this for you.

Then follow the three onboarding steps: download an engine, add servers, connect.

## Features

- **A real Mac app.** SwiftUI, menu bar controls, light and dark mode, keyboard shortcuts, VoiceOver labels. No Electron, no web view.
- **Proxy chaining.** Route traffic through any number of servers and mix protocols, for example OpenVPN → VLESS Reality → WireGuard. The editor tells you which hop breaks a chain and why, and **Test Connection** checks every hop before you save.
- **Every protocol.** VLESS (Reality, Vision, XHTTP), VMess, Trojan, Shadowsocks, Hysteria2, TUIC, WireGuard, OpenVPN and more. Keyway runs each server on an engine that supports it.
- **Import from anywhere.** Share links, subscription URLs, a QR code on your screen, WireGuard and OpenVPN files, Clash YAML and sing-box JSON.
- **Subscriptions and groups.** Traffic used, quota and expiry next to each subscription, plus Manual, Fallback and Fastest groups that act as one server.
- **Fast.** Test latency through the real engine, and let auto-select pick the fastest server without flapping between similar ones.
- **Routing and DNS.** Global, bypass, or your own rule sets, per-app rules, secure DNS, FakeIP, and TUN mode to capture all traffic.
- **Tor (optional).** Use a Tor server on its own or as a hop in a chain, with obfs4, Snowflake and meek bridges.
- **Private.** Everything stays on your Mac in `~/.keyway`. Keyway sends nothing except engine downloads, your subscription URLs and a daily check for the newest release, which you can turn off.

<p align="center">
<img src="docs/screenshots/proxy-chain.png" alt="Keyway with a three-hop chain selected: OpenVPN, then VLESS Reality, then WireGuard" width="760">
</p>

| Engine | Protocols |
|---|---|
| **Xray-core** | VLESS, VMess, Trojan, Shadowsocks, SOCKS5, HTTP, WireGuard, Hysteria2 |
| **sing-box** | Hysteria and Hysteria2, TUIC, AnyTLS, ShadowTLS, NaiveProxy, WireGuard, OpenVPN, plus the Xray protocols |
| **V2Ray core** (optional) | VLESS over TLS, VMess, Trojan, Shadowsocks, SOCKS5, HTTP |
| **Mihomo** (optional) | VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, WireGuard, SOCKS5, HTTP |

## FAQ

**Is it a V2Ray / Xray client for Mac?**
Yes. It imports V2Ray and Xray links and subscriptions, and runs Xray-core, with V2Ray core as an option.

**Does it work on Apple silicon and Intel Macs?**
Yes. The release is a universal build for macOS 14 or later.

**Does it include a system-wide VPN mode?**
Yes, TUN mode. It needs administrator approval. See [Engines, DNS and TUN](docs/ENGINES.md#tun-mode-and-administrator-rights).

**Why does macOS warn me when I open it?**
The builds are not notarized yet. See [Install](#install) for the one-time fix.

**Is it safe?**
The source is public. Engine downloads come only from official releases and are verified before install, and the local API only accepts requests carrying a per-launch token. See [SECURITY.md](SECURITY.md) to report a problem.

**Is Keyway a proxy or VPN service?**
No. It is a client. You bring your own servers or subscription.

**What is missing?**
A kill switch, Windows and Linux support, and signed or notarized builds.

## Documentation

- [User guide](docs/GUIDE.md): imports, subscriptions and groups, routing, privacy
- [Engines, Tor, DNS and TUN](docs/ENGINES.md): how Keyway picks an engine, and the details of each
- [Development](docs/DEVELOPMENT.md): build, checks and releases
- [Architecture](docs/ARCHITECTURE.md): layout, security model and behaviour notes

## Contributing

Issues and pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) first. Keyway is released under the [MIT License](LICENSE).
