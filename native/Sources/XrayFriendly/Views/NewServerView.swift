import AppKit
import SwiftUI
import XrayFriendlyCore

/// The New Server / Edit Server window (design/screens/NewServer.dc.html).
struct NewServerView: View {
    let target: EditorTarget
    /// Protocol selected when the window opens for a new server.
    var initialProtocol: String?
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    @State private var form = ServerForm(protocolID: "vless")
    @State private var forms: [String: ServerForm] = [:] // keep what was typed per protocol
    @State private var status: String?
    @State private var statusIsError = false
    @State private var busy = false

    private var editingID: String? { if case .edit(let id) = target { return id } else { return nil } }

    var body: some View {
        HStack(spacing: 0) {
            protocolList
            Divider()
            VStack(spacing: 0) {
                header.padding(.horizontal, 22).padding(.top, 18)
                Form {
                    ForEach(form.sections) { section in
                        Section {
                            ForEach(section.fields) { field($0) }
                        } header: {
                            Text(section.title)
                        } footer: {
                            if let note = section.note {
                                Text(note).font(.system(size: 11)).foregroundStyle(Palette.secondary).frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                }
                .formStyle(.grouped)
                .scrollContentBackground(.hidden)
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) { footer }
        .frame(width: 760, height: 720)
        .tint(Palette.accent)
        .navigationTitle(editingID == nil ? "New Server" : "Edit Server")
        .onPasteCommand(of: [.plainText]) { providers in
            _ = providers.first?.loadObject(ofClass: NSString.self) { s, _ in
                if let s = s as? String { Task { @MainActor in await fill(from: s) } }
            }
        }
        .task(id: target) { await loadForEdit() }
        .onAppear { if editingID == nil, let p = initialProtocol { form = ServerForm(protocolID: p) } }
    }

    // MARK: layout

    private var protocolList: some View {
        List(selection: Binding(get: { form.protocolID }, set: { switchProtocol($0) })) {
            ForEach([("xray", "Xray core"), ("sing-box", "sing-box")], id: \.0) { engine, title in
                Section(title) {
                    ForEach(ServerForms.all.filter { $0.engine == engine }) { d in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(d.label).font(.system(size: 13, weight: .semibold)).foregroundStyle(.primary)
                            Text(d.hint).font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 2)
                        .tag(d.id)
                        .accessibilityLabel("\(d.label), \(d.hint)")
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .frame(width: 210)
        .accessibilityLabel("Protocol")
    }

    private var header: some View {
        let d = form.def
        let badge = Palette.engineBadge(form.engine)
        return HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(d.label).font(.system(size: 17, weight: .bold))
                Text(d.about).font(.system(size: 12)).foregroundStyle(Palette.secondary)
            }
            Spacer()
            Text("Runs on \(model.engineBadge(form.engine))")
                .font(.system(size: 11, weight: .semibold)).foregroundStyle(badge.fg)
                .padding(.horizontal, 8).padding(.vertical, 4)
                .background(RoundedRectangle(cornerRadius: 6).fill(badge.bg))
        }
    }

    private var footer: some View {
        VStack(spacing: 0) {
            Divider()
            HStack(spacing: 8) {
                Button("Test Connection") { test() }.disabled(busy)
                Text(status ?? "Paste a link anywhere in this window to fill the form")
                    .font(.system(size: 12))
                    .foregroundStyle(statusIsError ? Palette.error : (status == nil ? Palette.secondary : Palette.greenText))
                    .lineLimit(2)
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(editingID == nil ? "Add Server" : "Save") { save() }
                    .buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction).disabled(busy)
            }
            .padding(.horizontal, 16).padding(.vertical, 12)
            .background(.bar)
        }
    }

    @ViewBuilder
    private func field(_ f: FormField) -> some View {
        let text = Binding(get: { form.values[f.key] ?? "" }, set: { form.values[f.key] = $0 })
        switch f.kind {
        case .text:
            LabeledContent(f.label) {
                TextField(f.label, text: text, prompt: Text(f.key == "port" ? form.portPlaceholder : f.placeholder))
                    .labelsHidden().multilineTextAlignment(.trailing)
                    .font(f.mono ? .system(size: 11, design: .monospaced) : .system(size: 13))
            }
        case .secret:
            LabeledContent(f.label) {
                SecureField(f.label, text: text, prompt: Text(f.placeholder))
                    .labelsHidden().multilineTextAlignment(.trailing)
                    .font(f.mono ? .system(size: 11, design: .monospaced) : .system(size: 13))
            }
        case .select(let options):
            Picker(f.label, selection: Binding(get: { form.choice(f) }, set: { form.values[f.key] = $0 })) {
                ForEach(options, id: \.self) { Text($0).tag($0) }
            }
            .disabled(options.count < 2)
        case .toggle:
            Toggle(f.label, isOn: Binding(get: { form.flags[f.key] ?? false }, set: { form.flags[f.key] = $0 }))
        }
    }

    // MARK: actions

    private func switchProtocol(_ id: String) {
        guard id != form.protocolID else { return }
        forms[form.protocolID] = form
        var next = forms[id] ?? ServerForm(protocolID: id)
        // carry over what is protocol-independent
        for k in ["name", "address"] where (next.values[k] ?? "").isEmpty { next.values[k] = form.values[k] }
        form = next
        status = nil
    }

    private func loadForEdit() async {
        guard let id = editingID, let client = model.client else { return }
        do {
            let body = try await client.nodeProfile(id)
            form = ServerForm(profile: body.profile, name: body.name)
        } catch {
            show(error.localizedDescription, error: true)
        }
    }

    private func fill(from text: String) async {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard t.contains("://") || t.lowercased().contains("[interface]"), let client = model.client else { return }
        do {
            let body = try await client.parseLink(t)
            form = ServerForm(profile: body.profile, name: body.name)
            show("Filled from the pasted link.", error: false)
        } catch {
            show(error.localizedDescription, error: true)
        }
    }

    private func test() {
        guard let client = model.client else { return }
        do {
            let (name, profile) = try form.profile()
            busy = true
            show("Testing through \(model.engineBadge(form.engine))…", error: false)
            Task {
                defer { busy = false }
                do {
                    let ms = try await client.testServer(name: name, profile: profile)
                    show("Works · \(Format.latencyLong(ms))", error: false)
                } catch {
                    show(error.localizedDescription, error: true)
                }
            }
        } catch {
            show(error.localizedDescription, error: true)
        }
    }

    private func save() {
        guard let client = model.client else { return }
        do {
            let (name, profile) = try form.profile()
            busy = true
            Task {
                defer { busy = false }
                do {
                    let node: Node
                    if let id = editingID {
                        node = try await client.updateNode(id, name: name, profile: profile)
                    } else {
                        node = try await client.createNode(name: name, profile: profile)
                    }
                    await model.refreshState()
                    model.selectedNodeID = node.id
                    dismiss()
                } catch {
                    show(error.localizedDescription, error: true)
                }
            }
        } catch {
            show(error.localizedDescription, error: true)
        }
    }

    private func show(_ message: String, error: Bool) {
        status = message
        statusIsError = error
    }
}
