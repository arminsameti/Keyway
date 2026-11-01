import SwiftUI
import KeywayCore

/// The menu bar popover (design/screens/MenuBar.dc.html).
struct MenuBarView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Divider().padding(.horizontal, 10)

            Text("Server").font(.system(size: 11, weight: .semibold)).foregroundStyle(Palette.secondary)
                .padding(.horizontal, 12).padding(.top, 8).padding(.bottom, 4)
            MenuRow(checked: model.settings.autoPick) {
                Text("Choose Fastest Automatically")
            } action: { model.setAutoPick(!model.settings.autoPick) }

            ForEach(model.topServers) { n in
                let on = !model.settings.autoPick && n.id == (model.connected ? model.status.activeNodeId : model.activeNodeId)
                MenuRow(checked: on) {
                    Text(n.countryCode ?? "").font(.system(size: 10, weight: .bold)).foregroundStyle(Palette.secondary).frame(width: 18, alignment: .leading)
                    Text(n.displayName).lineLimit(1)
                    Spacer()
                    Text(Format.latency(n.latencyMs)).font(.system(size: 12)).monospacedDigit()
                        .foregroundStyle(n.latencyMs >= 0 && n.latencyMs < 100 ? Palette.greenText : n.latencyMs >= 0 ? Palette.warn : Palette.secondary)
                } action: {
                    if model.settings.autoPick { model.setAutoPick(false) }
                    model.connect(n.id)
                }
                .accessibilityLabel("\(n.displayName), \(Format.latencyLong(n.latencyMs))")
            }
            Menu {
                ForEach(model.nodes) { n in
                    Button("\(n.displayName)  \(Format.latency(n.latencyMs))") { model.connect(n.id) }
                }
            } label: {
                HStack {
                    Text("All Servers").foregroundStyle(Color.primary)
                    Spacer()
                    Image(systemName: "chevron.right").font(.system(size: 10, weight: .semibold)).foregroundStyle(Color.primary)
                }
                .contentShape(Rectangle())
            }
            .menuStyle(.button)
            .buttonStyle(.plain)
            .menuIndicator(.hidden)
            .padding(.leading, 32).padding(.trailing, 10).frame(height: 30)
            .disabled(model.nodes.isEmpty)
            .accessibilityLabel("All servers")

            Divider().padding(.horizontal, 10).padding(.vertical, 6)

            HStack {
                Text("System Proxy")
                Spacer()
                Toggle("System proxy", isOn: Binding(get: { model.status.systemProxyOn }, set: { model.setSystemProxy($0) }))
                    .toggleStyle(.switch).controlSize(.small).labelsHidden().tint(Palette.green)
            }
            .padding(.horizontal, 12).frame(height: 34)
            Text(ports).font(.system(size: 11)).foregroundStyle(Palette.secondary)
                .padding(.horizontal, 12).padding(.bottom, 8)

            Divider().padding(.horizontal, 10).padding(.bottom, 4)

            command("Test Latency", "⌘T") { model.testLatency() }.keyboardShortcut("t")
            command("Add Servers from Clipboard", "⇧⌘V") { open(); model.addFromClipboard() }.keyboardShortcut("v", modifiers: [.command, .shift])
            command("Open Keyway…", "⌘O") { open() }.keyboardShortcut("o")
            SettingsLink {
                HStack { Text("Settings…"); Spacer(); Text("⌘,").foregroundStyle(Palette.secondary).font(.system(size: 12)) }
                    .padding(.horizontal, 12).frame(height: 28).contentShape(Rectangle())
            }
            .buttonStyle(MenuButtonStyle())
            .simultaneousGesture(TapGesture().onEnded { Activation.bringForward() })
            .keyboardShortcut(",")
            command("Quit Keyway", "⌘Q") { NSApp.terminate(nil) }.keyboardShortcut("q")
        }
        .padding(6)
        .frame(width: 340)
        .tint(Palette.accent)
    }

    private var header: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(model.connected ? "Connected" : "Not Connected").font(.system(size: 15, weight: .bold))
                TimelineView(.periodic(from: .now, by: 1)) { ctx in
                    Text(subtitle(ctx.date)).font(.system(size: 12)).foregroundStyle(Palette.secondary).lineLimit(1)
                }
            }
            Spacer()
            Toggle("Connection", isOn: Binding(get: { model.connected }, set: { $0 ? model.connect(model.activeNodeId.isEmpty ? model.nodes.first?.id : nil) : model.disconnect() }))
                .toggleStyle(.switch).labelsHidden().tint(Palette.green)
                .disabled(model.nodes.isEmpty || model.connecting)
                .accessibilityLabel("Connection")
        }
        .padding(.leading, 12).padding(.trailing, 10).padding(.vertical, 12)
    }

    private func subtitle(_ now: Date) -> String {
        guard model.connected else { return "Traffic is going out directly" }
        var up = model.status.uptimeSec
        if let s = model.status.startedAt, s > .distantPast { up = Int(now.timeIntervalSince(s)) }
        let speed = model.traffic.available ? " · ↓ \(Format.rate(model.traffic.downBps))" : ""
        return "\(model.status.activeNode) · \(Format.latency(model.status.activeLatencyMs)) · \(Format.uptime(up))\(speed)"
    }

    private var ports: String {
        [model.socksPort.map { "SOCKS 127.0.0.1:\($0)" }, model.httpPort.map { "HTTP 127.0.0.1:\($0)" }].compactMap { $0 }.joined(separator: " · ")
    }

    private func open() {
        openWindow(id: "main")
        Activation.bringForward()
    }

    private func command(_ title: String, _ key: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack { Text(title); Spacer(); Text(key).foregroundStyle(Palette.secondary).font(.system(size: 12)) }
                .padding(.horizontal, 12).frame(height: 28).contentShape(Rectangle())
        }
        .buttonStyle(MenuButtonStyle())
    }
}

/// A selectable row with a leading checkmark column, as in a native menu.
struct MenuRow<Content: View>: View {
    let checked: Bool
    @ViewBuilder var content: Content
    var action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: "checkmark").font(.system(size: 11, weight: .bold)).opacity(checked ? 1 : 0).frame(width: 16)
                    .accessibilityHidden(true)
                content
            }
            .padding(.leading, 8).padding(.trailing, 10).frame(height: 30).contentShape(Rectangle())
        }
        .buttonStyle(MenuButtonStyle())
        .accessibilityAddTraits(checked ? .isSelected : [])
    }
}

/// Highlights on hover like a menu item.
struct MenuButtonStyle: ButtonStyle {
    @State private var hover = false
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .foregroundStyle(hover ? Color.white : Color.primary)
            .background(RoundedRectangle(cornerRadius: 6).fill(hover ? Palette.accent : (configuration.isPressed ? Color.primary.opacity(0.1) : .clear)))
            .onHover { hover = $0 }
    }
}
