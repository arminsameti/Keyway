import AppKit
import SwiftUI
import KeywayCore

/// The Settings scene: General, Proxy, Routing, Engines, Advanced.
struct SettingsView: View {
    @State var tab = "general"

    var body: some View {
        TabView(selection: $tab) {
            pane { GeneralPane() }.tabItem { Label("General", systemImage: "gearshape") }.tag("general")
            pane { ProxyPane() }.tabItem { Label("Proxy", systemImage: "server.rack") }.tag("proxy")
            pane { RoutingForm() }.tabItem { Label("Routing", systemImage: "arrow.triangle.branch") }.tag("routing")
            pane { EnginesPane() }.tabItem { Label("Engines", systemImage: "cpu") }.tag("engines")
            pane { AdvancedPane() }.tabItem { Label("Advanced", systemImage: "slider.horizontal.3") }.tag("advanced")
        }
        .frame(width: 760, height: 640)
        .tint(Palette.accent)
    }

    private func pane<V: View>(@ViewBuilder _ v: () -> V) -> some View {
        ScrollView { v().padding(.horizontal, 40).padding(.vertical, 22).frame(maxWidth: .infinity) }
    }
}

struct GeneralPane: View {
    @Environment(AppModel.self) private var model
    @State private var atLogin = false

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            CardSection(title: "Startup") {
                CardRow(label: "Open at login and keep in the menu bar", first: true) {
                    Toggle("Open at login", isOn: Binding(get: { atLogin }, set: { model.setOpensAtLogin($0); atLogin = model.opensAtLogin }))
                        .labelsHidden().toggleStyle(.checkbox)
                }
                CardRow(label: "Connect when Keyway starts") {
                    Toggle("Connect at start", isOn: settingBinding(model, \.autoConnect)).labelsHidden().toggleStyle(.checkbox)
                }
            }
            CardSection(title: "Connection") {
                CardRow(label: "Turn on the macOS system proxy when connecting", first: true) {
                    Toggle("System proxy on connect", isOn: settingBinding(model, \.autoSystemProxy)).labelsHidden().toggleStyle(.checkbox)
                }
                CardRow(label: "Choose the fastest server automatically") {
                    Toggle("Auto-select fastest", isOn: settingBinding(model, \.autoPick)).labelsHidden().toggleStyle(.checkbox)
                }
                CardRow(label: "Re-check every") {
                    Stepper("\(model.settings.autoPickMin) min", value: settingBinding(model, \.autoPickMin), in: 1...1440, step: 5)
                        .disabled(!model.settings.autoPick)
                }
            }
            CardSection(title: "Subscriptions") {
                CardRow(label: "Refresh subscriptions", first: true) {
                    Picker("Refresh subscriptions", selection: settingBinding(model, \.subUpdateHours)) {
                        Text("Never").tag(0); Text("Every 6 hours").tag(6); Text("Every 12 hours").tag(12)
                        Text("Daily").tag(24); Text("Every 2 days").tag(48); Text("Weekly").tag(168)
                    }.labelsHidden().fixedSize()
                }
            }
            UpdateCard()
        }
        .frame(maxWidth: 680)
        .onAppear { atLogin = model.opensAtLogin }
    }
}

struct ProxyPane: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            CardSection(title: "Local listeners", caption: "Apps connect to these addresses. Ports also appear in Settings › Engines.") {
                ForEach(Array(model.settings.inbounds.enumerated()), id: \.element.tag) { i, ib in
                    CardRow(label: "\(ib.protocol == "http" ? "HTTP" : "SOCKS5") · \(ib.tag)", first: i == 0) {
                        Text(verbatim: "\(ib.listen):\(ib.port)").font(.system(size: 12, design: .monospaced)).foregroundStyle(Palette.secondary)
                        Toggle(ib.tag, isOn: Binding(get: { ib.enabled }, set: { on in
                            var s = model.settings
                            s.inbounds[i].enabled = on
                            model.save(s)
                        })).labelsHidden()
                    }
                }
            }
            TunCard()
            CardSection(title: "Multiplexing", footnote: "Shares one connection for many requests. Not used with XTLS Vision, gRPC, HTTP/2 or QUIC protocols.") {
                CardRow(label: "Multiplex connections", first: true) {
                    Toggle("Multiplex", isOn: settingBinding(model, \.mux)).labelsHidden()
                }
                CardRow(label: "Streams per connection") {
                    Stepper("\(model.settings.muxConcurrency)", value: settingBinding(model, \.muxConcurrency), in: 1...1024)
                        .disabled(!model.settings.mux)
                }
            }
        }
        .frame(maxWidth: 680)
    }
}

struct AdvancedPane: View {
    @Environment(AppModel.self) private var model
    @State private var dns = ""
    @State private var apiPort = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            CardSection(title: "Engine") {
                CardRow(label: "Log level", first: true) {
                    Picker("Log level", selection: settingBinding(model, \.logLevel)) {
                        ForEach(["debug", "info", "warning", "error", "none"], id: \.self) { Text($0.capitalized).tag($0) }
                    }.labelsHidden().fixedSize()
                }
                CardRow(label: "DNS servers (Xray)") {
                    TextField("DNS servers", text: $dns).frame(width: 260).labelsHidden()
                        .font(.system(size: 12, design: .monospaced))
                        .onSubmit {
                            var s = model.settings
                            s.dns = dns.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                            model.save(s)
                        }
                }
            }
            CardSection(title: "App", footnote: "Changing the API port takes effect after Keyway restarts.") {
                CardRow(label: "Local API port", first: true) {
                    TextField("API port", text: $apiPort).frame(width: 72).multilineTextAlignment(.trailing).labelsHidden()
                        .onSubmit {
                            guard let p = Int(apiPort), (1...65535).contains(p) else { apiPort = String(model.settings.apiPort); return }
                            var s = model.settings
                            s.apiPort = p
                            model.save(s)
                        }
                }
                CardRow(label: "Data folder") {
                    Button("Show in Finder") { NSWorkspace.shared.selectFile(nil, inFileViewerRootedAtPath: model.backend.dataDir) }
                }
            }
        }
        .frame(maxWidth: 680)
        .onAppear {
            dns = model.settings.dns.joined(separator: ", ")
            apiPort = String(model.settings.apiPort)
        }
    }
}
