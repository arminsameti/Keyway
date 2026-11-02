import SwiftUI
import KeywayCore

/// How Keyway resolves domain names: the resolver mode, its servers, a separate
/// resolver for bypassed domains and FakeIP for TUN.
struct DNSPane: View {
    @Environment(AppModel.self) private var model
    @State private var servers = ""
    @State private var direct = ""
    @FocusState private var focus: Field?

    private enum Field { case servers, direct }

    private var mode: String { model.settings.dnsMode }
    private var encrypted: Bool { mode == "secure" || mode == "custom" }

    private static let presets: [(name: String, server: String)] = [
        ("Cloudflare (DNS over HTTPS)", "https://1.1.1.1/dns-query"),
        ("Google (DNS over HTTPS)", "https://8.8.8.8/dns-query"),
        ("Quad9 (DNS over TLS, sing-box)", "tls://9.9.9.9"),
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            CardSection(title: "Name resolution",
                        caption: "How Keyway looks up domain names. A lookup that skips the proxy, or goes to a server you do not trust, can reveal your browsing.",
                        footnote: modeNote) {
                CardRow(label: "Resolver", first: true) {
                    Picker("Resolver", selection: settingBinding(model, \.dnsMode)) {
                        Text("Default").tag("default")
                        Text("System").tag("system")
                        Text("Secure DNS through the proxy").tag("secure")
                        Text("Custom servers through the proxy").tag("custom")
                    }
                    .labelsHidden().fixedSize()
                }
                if mode == "default" || mode == "custom" {
                    CardRow(label: mode == "custom" ? "Servers" : "Servers (Xray only)") {
                        TextField("1.1.1.1, https://dns.google/dns-query", text: $servers).frame(width: 340).labelsHidden()
                            .font(.system(size: 12, design: .monospaced))
                            .focused($focus, equals: .servers)
                            .onSubmit(commitServers)
                    }
                }
                if mode == "custom" {
                    CardRow(label: "Fill in from a preset") {
                        Menu("Choose…") {
                            ForEach(Self.presets, id: \.server) { p in
                                Button(p.name) { servers = p.server; commitServers() }
                            }
                        }
                        .fixedSize()
                    }
                }
            }
            if encrypted {
                CardSection(title: "Bypassed domains",
                            footnote: "Domains your routing sends direct (such as geosite:cn) are resolved by this server instead, reached without the proxy. Use an IP address like 223.5.5.5, or an https:// or tls:// address with an IP. Leave it empty to use the servers above for everything. V2Ray core cannot do this, so such servers move to Xray core or sing-box.") {
                    CardRow(label: "Direct resolver", first: true) {
                        TextField("optional, e.g. 223.5.5.5", text: $direct).frame(width: 340).labelsHidden()
                            .font(.system(size: 12, design: .monospaced))
                            .focused($focus, equals: .direct)
                            .onSubmit(commitDirect)
                    }
                }
            }
            CardSection(title: "System-wide capture (TUN)",
                        footnote: model.settings.tun.enabled
                            ? "FakeIP answers every lookup with a placeholder address and sends the real name to the proxy, so nothing resolves on this Mac. sing-box only."
                            : "FakeIP works with system-wide capture. Turn it on under Proxy › System-wide capture (TUN) first.") {
                CardRow(label: "FakeIP", first: true) {
                    Toggle("FakeIP", isOn: settingBinding(model, \.fakeIp)).labelsHidden()
                        .disabled(!model.settings.tun.enabled)
                }
            }
        }
        .frame(maxWidth: 680)
        .onAppear(perform: load)
        .onChange(of: model.settings.dns) { load() }
        .onChange(of: model.settings.dnsDirect) { load() }
        .onChange(of: focus) { old, _ in
            if old == .servers { commitServers() }
            if old == .direct { commitDirect() }
        }
    }

    private var modeNote: String {
        switch mode {
        case "system":
            return "Every engine asks macOS. Lookups leave this Mac outside the proxy, so your network provider can see them."
        case "secure":
            return "Cloudflare, then Google, over HTTPS and through your proxy server, so your network cannot read or change the lookups. sing-box asks only the first server."
        case "custom":
            return "Use IP addresses, https:// (DNS over HTTPS) or tls:// (DNS over TLS). Queries go through the proxy. DNS over TLS runs on sing-box only, and sing-box asks only the first server. V2Ray core accepts IP addresses and DoH by IP only; other servers move to another engine."
        default:
            return "Keyway's original behavior: Xray asks the servers above, sing-box asks the system resolver."
        }
    }

    private func load() {
        servers = model.settings.dns.joined(separator: ", ")
        direct = model.settings.dnsDirect
    }

    private func commitServers() {
        let list = servers.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard list != model.settings.dns else { return }
        var s = model.settings
        s.dns = list
        model.save(s)
    }

    private func commitDirect() {
        let value = direct.trimmingCharacters(in: .whitespaces)
        guard value != model.settings.dnsDirect else { return }
        var s = model.settings
        s.dnsDirect = value
        model.save(s)
    }
}
