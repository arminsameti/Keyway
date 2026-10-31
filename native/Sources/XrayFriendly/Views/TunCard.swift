import SwiftUI
import XrayFriendlyCore

/// Settings for capturing all traffic with a TUN interface.
struct TunCard: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        CardSection(title: "System-wide capture (TUN)",
                    caption: "Sends all of this Mac's traffic through the proxy, including apps that ignore the system proxy. Needs administrator rights, and sing-box carries the traffic.",
                    footnote: footnote) {
            CardRow(label: "Capture all traffic", first: true) {
                Toggle("Capture all traffic", isOn: settingBinding(model, \.tun.enabled)).labelsHidden()
            }
            CardRow(label: "Administrator rights") {
                Picker("Administrator rights", selection: settingBinding(model, \.tun.privilege)) {
                    Text("Ask for my password every time").tag("prompt")
                    Text("Allow once").tag("helper")
                }
                .labelsHidden().fixedSize()
            }
            if model.settings.tun.privilege == "helper" { helperRow }
            CardRow(label: "Network stack") {
                Picker("Network stack", selection: settingBinding(model, \.tun.stack)) {
                    Text("Mixed (recommended)").tag("mixed")
                    Text("System").tag("system")
                    Text("gVisor").tag("gvisor")
                }
                .labelsHidden().fixedSize()
            }
            CardRow(label: "Strict routing") {
                Toggle("Strict routing", isOn: settingBinding(model, \.tun.strict)).labelsHidden()
            }
        }
        .onAppear { model.refreshTunHelper() }
    }

    @ViewBuilder
    private var helperRow: some View {
        let h = model.tunHelper
        CardRow(label: h.installed ? "Allowed once" + (h.pinnedVersion.map { " · sing-box \($0)" } ?? "") : "Not set up yet") {
            if !h.available {
                Text("The helper is missing from this build").foregroundStyle(Palette.warn)
            } else if h.installed {
                if h.outdated { Button("Update") { model.setTunHelper(install: true) }.disabled(model.tunBusy) }
                Button("Remove") { model.setTunHelper(install: false) }.disabled(model.tunBusy)
            } else {
                Button("Allow Once…") { model.setTunHelper(install: true) }.disabled(model.tunBusy)
            }
        }
    }

    private var footnote: String {
        var t = "Strict routing also stops apps from bypassing the tunnel over another network interface. "
        if model.settings.tun.privilege == "helper" {
            t += "“Allow once” stores a copy of the helper and sing-box where only administrators can change them, and lets this account start them without a password. Remove it here at any time. While it is allowed, any program running as you can start a TUN session."
        } else {
            t += "macOS asks for your password each time you connect, and the tunnel stops when you disconnect or quit the app."
        }
        return t
    }
}
