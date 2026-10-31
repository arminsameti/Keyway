import SwiftUI
import XrayFriendlyCore

struct CustomConfigEditor: View {
    @Binding var form: CustomForm

    var body: some View {
        Form {
            Section("Server") {
                TextField("Name", text: $form.name, prompt: Text("Shown in the server list"))
                Picker("Written for", selection: $form.engine) {
                    ForEach(CustomForm.engines, id: \.0) { Text($0.1).tag($0.0) }
                }
            }
            Section {
                TextEditor(text: $form.config)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(minHeight: 280)
                    .scrollContentBackground(.hidden)
                    .padding(4)
                    .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .textBackgroundColor)))
                    .overlay(alignment: .topLeading) {
                        if form.config.isEmpty {
                            Text(CustomForm.placeholder).font(.system(size: 11, design: .monospaced)).foregroundStyle(Palette.secondary)
                                .padding(.horizontal, 9).padding(.vertical, 8).allowsHitTesting(false)
                        }
                    }
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Palette.cardBorder))
                    .accessibilityLabel("Outbound JSON")
            } header: {
                Text("Outbound JSON")
            } footer: {
                Text("One outbound, a list of outbounds, or a full config: only its outbounds are used. The first one is where your traffic leaves; the app renames its tag to “proxy”. Its own ports and routing rules apply, so inbounds and routing in your JSON are ignored.")
                    .font(.system(size: 11)).foregroundStyle(Palette.secondary).frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
    }
}
