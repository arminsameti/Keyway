# User guide

The features in more detail. Back to the [README](../README.md).

## Import from anywhere

Share links (`vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`, `tuic://` and more), **subscription URLs**, a **QR code on your screen**, WireGuard `.conf`, OpenVPN `.ovpn` (or a **`.zip` of `.ovpn` files with their `ca.crt` / `client.crt` / `client.key` files**), **Clash YAML** and **sing-box JSON**. Subscriptions refresh automatically.

## Subscription details and groups

- **Usage and expiry.** When your provider sends the standard `Subscription-Userinfo`, `Profile-Title` and `Profile-Update-Interval` headers, Keyway shows traffic used, the quota, an "expires in N days" line and the provider's refresh interval next to the subscription. A provider's interval replaces your global one, but turning automatic refresh off still wins.
- **Groups** act as one server. Pick **Manual** (you choose the server), **Fallback** (the first server in the list that works) or **Fastest** (re-tested regularly, and it only switches when another server is clearly faster, so it does not flap). Select a group like any server, in the window or the menu bar. Make one by hand, or from a subscription's **Group** menu to cover all its servers.
- **Clash groups** (`proxy-groups`) of type select, url-test and fallback are imported as groups. load-balance, relay and unknown types are skipped, and the import says so. Entries that are not servers (DIRECT, REJECT, other groups) are left out and counted.
- A group can hold servers and chains, but a group cannot be a hop inside a chain. While a group is active, "choose fastest automatically" over all servers is paused.

## Routing and control

- **Routing modes:** global, bypass private and Chinese addresses, or your own **rule sets** (domains, `geosite`, `geoip`, IP ranges, ports, programs). Import rules from Clash or v2rayN and test which rule a destination hits.
- **Per-app rules:** proxy, bypass or block by application, for example `app:/Applications/Slack.app`.
- **DNS:** in **Settings › DNS** choose how names resolve: the original default, the system resolver, built-in secure DNS (DNS over HTTPS through the proxy), or your own servers (IP, `https://` DoH, `tls://` DoT). An optional direct resolver answers for the domains your routing bypasses, and FakeIP is available in TUN mode. See [DNS](ENGINES.md#dns).
- **TUN mode:** capture all traffic on the Mac, not only apps that respect the system proxy. See [TUN mode](ENGINES.md#tun-mode-and-administrator-rights).
- **System proxy** is set on connect and restored on disconnect, quit or after a crash.
- **Per-server overrides:** multiplexing, SNI, uTLS fingerprint and TLS fragmentation.
- **Custom servers:** paste your own Xray or sing-box outbound JSON.
- **Live traffic:** upload and download speed and totals in the window and the menu bar.

## Private by design

Everything stays on your Mac in `~/.keyway` (owner-only permissions). Keyway sends nothing anywhere except the engine downloads, the subscription URLs you add, and a once-a-day request to GitHub for the newest Keyway release number. That update check carries nothing that identifies you or your Mac, and you can turn it off in Settings › General › Updates. The local API only listens on `127.0.0.1` and is protected by a per-launch token. Keyway is open source under the MIT license, so you can read exactly what it does.
