import SwiftUI
import KeywayCore

/// "Advanced" settings of one server. Anything left on "Use global setting"
/// follows the app-wide settings.
struct ServerOverridesSection: View {
    @Binding var overrides: ServerOverrides

    private enum Tri: String, CaseIterable { case global = "Use global setting", on = "On", off = "Off" }

    private var mux: Binding<Tri> {
        Binding(get: { overrides.mux.map { $0 ? .on : .off } ?? .global },
                set: { overrides.mux = $0 == .global ? nil : $0 == .on })
    }

    private var fragmentOn: Binding<Bool> {
        Binding(get: { overrides.fragment != nil }, set: { overrides.fragment = $0 ? ServerOverrides.Fragment() : nil })
    }

    var body: some View {
        Section {
            Picker("Multiplexing", selection: mux) {
                ForEach(Tri.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }
            if overrides.mux == true {
                TextField("Connections per tunnel", value: Binding(get: { overrides.muxConcurrency ?? 0 }, set: { overrides.muxConcurrency = $0 }),
                          format: .number, prompt: Text("Global setting"))
            }
            TextField("Server name (SNI)", text: Binding(get: { overrides.sni ?? "" }, set: { overrides.sni = $0 }), prompt: Text("From the server"))
            Picker("TLS fingerprint", selection: Binding(get: { overrides.fingerprint ?? "" }, set: { overrides.fingerprint = $0.isEmpty ? nil : $0 })) {
                Text("From the server").tag("")
                ForEach(ServerOverrides.fingerprints, id: \.self) { Text($0).tag($0) }
            }
            Toggle("Split the TLS handshake (fragment)", isOn: fragmentOn)
            if overrides.fragment != nil {
                TextField("Piece size (bytes)", text: Binding(get: { overrides.fragment?.length ?? "" }, set: { overrides.fragment?.length = $0 }),
                          prompt: Text("100-200"))
                TextField("Delay between pieces (ms)", text: Binding(get: { overrides.fragment?.interval ?? "" }, set: { overrides.fragment?.interval = $0 }),
                          prompt: Text("10-20"))
            }
        } header: {
            Text("Advanced")
        } footer: {
            Text("Fragmenting helps against filters that read the server name; it needs a TLS or Reality server that this app connects to directly (the first server of a chain). The piece size and delay apply to Xray; sing-box uses its own defaults.")
                .font(.system(size: 11)).foregroundStyle(Palette.secondary).frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
