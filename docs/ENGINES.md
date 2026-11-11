# Engines, Tor, DNS and TUN

How Keyway picks an engine for each server, and the details of the optional engines, Tor, DNS and TUN mode. Back to the [README](../README.md).

## Engines

| Engine | Protocols |
|---|---|
| **Xray-core** | VLESS (Reality, Vision, XHTTP), VMess, Trojan, Shadowsocks (incl. 2022), SOCKS5, HTTP, WireGuard, Hysteria2 |
| **sing-box** | Hysteria and Hysteria2, TUIC v5, AnyTLS, ShadowTLS, NaiveProxy, WireGuard, OpenVPN, plus VLESS, VMess, Trojan and Shadowsocks |
| **V2Ray core** (optional) | VLESS over TLS, VMess, Trojan, Shadowsocks, SOCKS5, HTTP |
| **Mihomo** (optional) | VLESS (Reality, Vision), VMess, Trojan, Shadowsocks (incl. 2022), Hysteria2, TUIC v5, AnyTLS, WireGuard, SOCKS5, HTTP |

Keyway downloads Xray and sing-box from their official GitHub releases, verifies their checksums, keeps them updated, and runs whichever engine supports each server. When both can, you choose the preference. Servers that need a specific engine (for example plain VLESS without TLS, which current Xray refuses) are moved to the right one automatically.

Each server can also pin its own core: open the server's **Advanced** settings and set **Core** to Xray, sing-box, V2Ray, Mihomo or Tor instead of Automatic. A pinned core must support the server or connecting fails with the reason; chains respect every hop's pin (conflicting pins split the chain into more processes). Custom configs already pin their JSON dialect (Xray or sing-box) by definition.

V2Ray core is optional. Download it in **Settings › Engines** and choose **Prefer V2Ray core** to run the servers it supports through v2ray-core itself. Keyway only uses it when every setting of a server takes effect there, so Reality, Vision, pinned certificates and servers with a TLS fingerprint stay on Xray or sing-box.

Mihomo (the Clash.Meta core) is optional too: download it in **Settings › Engines** and choose **Prefer Mihomo**. It is GPL-3.0 software that Keyway only downloads and runs as a separate program; Keyway does not link or bundle it. Releases come from [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo) and are checked against the SHA-256 GitHub reports for them, since Mihomo publishes no checksum file; its geo data comes from MetaCubeX/meta-rules-dat and is checked the same way, and Mihomo is never allowed to download anything itself. Keyway only runs a server on Mihomo when every setting of it was checked to work there. XHTTP, mKCP, QUIC transport, Hysteria v1, ShadowTLS, NaiveProxy, SSH, OpenVPN, Tor, Cloudflare WARP reserved bytes, TLS fragmentation and chains with a UDP hop stay on Xray or sing-box, and so do the TUN interface and per-app rules: with those on, sing-box serves your apps in front of Mihomo.

## Tor (optional)

Turn on **Settings › Engines › Enable Tor** to use the Tor network from Keyway. It is off by default, and while it is off nothing about Tor is shown, downloaded or run.

- **A Tor server is a normal entry in your list.** Connect to it directly, or put it anywhere in a chain: `Tor → VLESS`, `VLESS → Tor`, or `A → Tor → B`. A chain can have one Tor hop.
- **Bridges** for networks where Tor is blocked: obfs4, Snowflake, meek, or your own lines from bridges.torproject.org.
- **Limits:** Tor carries TCP only, so WireGuard, Hysteria and other UDP hops cannot come after it, and Snowflake cannot sit behind another hop. Tor needs sing-box installed too, which Keyway downloads for you; it serves your apps, the system proxy and routing rules. Auto-select never picks Tor.
- Tor is downloaded from the Tor Project (its Expert Bundle) and checked against the SHA-256 they publish.

## DNS

By default nothing changes: Xray asks the servers it always did (`1.1.1.1, 8.8.8.8, localhost`) and sing-box asks the system resolver. Under **Settings › DNS** you can instead pick:

- **System:** every engine asks macOS.
- **Secure DNS:** Cloudflare and Google over HTTPS, sent through your proxy server.
- **Custom servers:** your own list, also sent through the proxy. Entries are an IP address, `localhost`, `https://host/path` (DoH) or `tls://host` (DoT).
- **Direct resolver (optional):** an IP such as `223.5.5.5` that answers for the domains your routing sends direct, reached without the proxy.
- **FakeIP (TUN only):** lookups get placeholder addresses and the real name goes to the proxy.

The engines differ, so Keyway checks before it picks one. Xray core and V2Ray core cannot do DNS over TLS (they read `tls://1.1.1.1` as a plain UDP server and say nothing), so such a server runs on sing-box. V2Ray core also cannot look up the host name of a DoH server or keep a direct resolver, and cannot pin its queries to the proxy beyond the default route, so those settings move servers to Xray core or sing-box. sing-box has no failover between DNS servers and asks only the first. The config preview shows the effective DNS of each process.

## TUN mode and administrator rights

TUN starts sing-box as root. By default macOS asks for your password every time you connect. In Settings › Proxy you can instead choose **Allow Once…**, which installs a root-owned helper and a sudoers rule so later connects need no password. While that is installed, any program running as you can start a TUN session, and removing it deletes the rule. The helper refuses configs that touch files, listen on non-loopback addresses or use remote rule sets.
