import AppKit
import SwiftUI
import KeywayCore

/// The New Server / Edit Server window (design/screens/NewServer.dc.html).
struct NewServerView: View {
    let target: EditorTarget
    /// Protocol selected when the window opens for a new server.
    var initialProtocol: String?
    /// A ready-made chain and plan shown instead of loading (snapshot rendering).
    var sampleChain: (chain: ChainForm, plan: ChainPlan)?
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    @State private var form = ServerForm(protocolID: "vless")
    @State private var forms: [String: ServerForm] = [:] // keep what was typed per protocol
    @State private var overrides = ServerOverrides()
    @State private var customMode = false
    @State private var custom = CustomForm()
    @State private var chainMode = false
    @State private var chain = ChainForm()
    @State private var chainPlan: ChainPlan?
    @State private var chainProblem: String?
    @State private var planning = false
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
                if chainMode {
                    ChainEditor(chain: $chain, plan: chainPlan, problem: chainProblem, planning: planning)
                } else if customMode {
                    CustomConfigEditor(form: $custom)
                } else {
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
                        if form.protocolID != "wireguard" && form.protocolID != "openvpn" {
                            ServerOverridesSection(overrides: $overrides)
                        }
                    }
                    .formStyle(.grouped)
                    .scrollContentBackground(.hidden)
                }
            }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) { footer }
        .frame(width: 760, height: 720)
        .tint(Palette.accent)
        .navigationTitle(editingID == nil ? "New Server" : "Edit Server")
        .onPasteCommand(of: [.plainText]) { providers in
            guard !chainMode, !customMode else { return }
            _ = providers.first?.loadObject(ofClass: NSString.self) { s, _ in
                if let s = s as? String { Task { @MainActor in await fill(from: s) } }
            }
        }
        .task(id: target) { await loadForEdit() }
        .task(id: chain.hops) { await planChain() }
        .onAppear {
            guard editingID == nil else { return }
            if sampleChain != nil || target == .newChain || initialProtocol == "chain" { chainMode = true } else if let p = initialProtocol { form = ServerForm(protocolID: p) }
        }
    }

    // MARK: layout

    private var protocolList: some View {
        List(selection: Binding(get: { chainMode ? "chain" : customMode ? "custom" : form.protocolID }, set: { id in
            chainMode = id == "chain"
            customMode = id == "custom"
            if !chainMode && !customMode { switchProtocol(id) }
        })) {
            Section("Combine") {
                VStack(alignment: .leading, spacing: 1) {
                    Text("Proxy Chain").font(.system(size: 13, weight: .semibold)).foregroundStyle(.primary)
                    Text("Several servers in a row").font(.system(size: 11)).foregroundStyle(.secondary)
                }
                .padding(.vertical, 2)
                .tag("chain")
                .accessibilityLabel("Proxy Chain, several servers in a row")
                VStack(alignment: .leading, spacing: 1) {
                    Text("Custom Config").font(.system(size: 13, weight: .semibold)).foregroundStyle(.primary)
                    Text("Your own Xray or sing-box JSON").font(.system(size: 11)).foregroundStyle(.secondary)
                }
                .padding(.vertical, 2)
                .tag("custom")
                .accessibilityLabel("Custom Config, your own Xray or sing-box JSON")
            }
            ForEach([("xray", "Xray core"), ("sing-box", "sing-box")] + (model.settings.torEnabled ? [("tor", "Tor")] : []), id: \.0) { engine, title in
                Section(title) {
                    ForEach(ServerForms.all.filter { $0.engine == engine }) { d in
                        VStack(alignment: .leading, spacing: 1) {
                            Text(d.label).font(.system(size: 13, weight: .semibold)).foregroundStyle(.primary)
                            Text(d.hint).font(.system(size: 11)).foregroundStyle(.secondary)
                        }
                        .padding(.vertical, 0)
                        .tag(d.id)
                        .accessibilityLabel("\(d.label), \(d.hint)")
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .environment(\.defaultMinListRowHeight, 32)
        .frame(width: 210)
        .accessibilityLabel("Protocol")
    }

    private var header: some View {
        let title = chainMode ? "Proxy Chain" : customMode ? "Custom Config" : form.def.label
        let about = chainMode
            ? "Route through several servers in a row, such as OpenVPN, then Xray, then WireGuard. Each server only knows its neighbours."
            : customMode ? "Paste an outbound written for Xray or sing-box. The app adds its own ports, routing rules and traffic counters around it."
            : form.def.about
        let engine = chainMode ? (chainPlan?.engine ?? "xray") : customMode ? custom.engine : form.engine
        let badge = Palette.engineBadge(engine)
        let badgeText: String? = chainMode ? chainPlan.map { "Runs on \($0.engineName)" } : "Runs on \(model.engineBadge(customMode ? custom.engine : form.engine))"
        return HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.system(size: 17, weight: .bold))
                Text(about).font(.system(size: 12)).foregroundStyle(Palette.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            if let badgeText {
                Text(badgeText)
                    .font(.system(size: 11, weight: .semibold)).foregroundStyle(badge.fg)
                    .padding(.horizontal, 8).padding(.vertical, 4)
                    .background(RoundedRectangle(cornerRadius: 6).fill(badge.bg))
            }
        }
    }

    private var footer: some View {
        VStack(spacing: 0) {
            Divider()
            HStack(spacing: 8) {
                Button("Test Connection") { test() }.disabled(busy)
                Text(status ?? (chainMode ? "Test Connection checks every hop end to end" : customMode ? "Test Connection runs your outbound and fetches a page through it" : "Paste a link or a config file anywhere in this window to fill the form"))
                    .font(.system(size: 12))
                    .foregroundStyle(statusIsError ? Palette.error : (status == nil ? Palette.secondary : Palette.greenText))
                    .lineLimit(2)
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(editingID == nil ? (chainMode ? "Add Chain" : customMode ? "Add Custom Server" : "Add Server") : "Save") { save() }
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
        case .multiline:
            VStack(alignment: .leading, spacing: 4) {
                Text(f.label)
                TextEditor(text: text)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(height: 72)
                    .scrollContentBackground(.hidden)
                    .padding(4)
                    .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .textBackgroundColor)))
                    .overlay(alignment: .topLeading) {
                        if (form.values[f.key] ?? "").isEmpty {
                            Text(f.placeholder).font(.system(size: 11, design: .monospaced)).foregroundStyle(Palette.secondary)
                                .padding(.horizontal, 9).padding(.vertical, 8).allowsHitTesting(false)
                        }
                    }
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Palette.cardBorder))
                    .accessibilityLabel(f.label)
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
            if let hops = body.chain {
                chainMode = true
                chain = ChainForm(name: body.name, hops: hops)
            } else if let p = body.profile, p.protocol == "custom" {
                customMode = true
                custom = CustomForm(profile: p, name: body.name)
            } else if let p = body.profile {
                form = ServerForm(profile: p, name: body.name)
                overrides = body.overrides ?? ServerOverrides()
            }
        } catch {
            show(error.localizedDescription, error: true)
        }
    }

    /// Asks the backend what saving this chain would do. It is the one source of
    /// truth for the rules (UDP between hops, which engines can run which hops).
    private func planChain() async {
        if let sampleChain { chain = sampleChain.chain; chainPlan = sampleChain.plan; return }
        chainPlan = nil
        chainProblem = nil
        guard chainMode, chain.blocker(in: model.nodes) == nil, let client = model.client else { return }
        planning = true
        defer { planning = false }
        try? await Task.sleep(for: .milliseconds(250)) // debounce quick edits
        guard !Task.isCancelled else { return }
        do {
            chainPlan = try await client.planChain(hops: chain.hops)
        } catch {
            if !Task.isCancelled { chainProblem = error.localizedDescription }
        }
    }

    private func fill(from text: String) async {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        let lower = t.lowercased()
        let looksLikeConfig = t.contains("://") || lower.contains("[interface]")
            || (lower.contains("remote ") && (lower.contains("<ca>") || lower.contains("client")))
        guard looksLikeConfig, let client = model.client else { return }
        do {
            let body = try await client.parseLink(t)
            guard let p = body.profile else { return }
            form = ServerForm(profile: p, name: body.name)
            show("Filled from the pasted text.", error: false)
        } catch {
            show(error.localizedDescription, error: true)
        }
    }

    private func test() {
        guard let client = model.client else { return }
        if chainMode {
            if let blocker = chain.blocker(in: model.nodes) { show(blocker, error: true); return }
            busy = true
            show("Testing every hop…", error: false)
            Task {
                defer { busy = false }
                do {
                    let ms = try await client.testChain(hops: chain.hops)
                    show("Works · \(Format.latencyLong(ms))", error: false)
                } catch {
                    show(error.localizedDescription, error: true)
                }
            }
            return
        }
        do {
            let (name, profile) = try customMode ? custom.profile() : form.profile()
            busy = true
            show("Testing through \(model.engineBadge(customMode ? custom.engine : form.engine))…", error: false)
            Task {
                defer { busy = false }
                do {
                    let ms = try await client.testServer(name: name, profile: profile, overrides: overrides)
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
        if chainMode {
            if let blocker = chain.blocker(in: model.nodes) { show(blocker, error: true); return }
            busy = true
            Task {
                defer { busy = false }
                do {
                    let node: Node
                    if let id = editingID {
                        node = try await client.updateChain(id, name: chain.name, hops: chain.hops)
                    } else {
                        node = try await client.createChain(name: chain.name, hops: chain.hops)
                    }
                    await model.refreshState()
                    model.selectedNodeID = node.id
                    dismiss()
                } catch {
                    show(error.localizedDescription, error: true)
                }
            }
            return
        }
        do {
            let (name, profile) = try customMode ? custom.profile() : form.profile()
            busy = true
            Task {
                defer { busy = false }
                do {
                    let node: Node
                    if let id = editingID {
                        node = try await client.updateNode(id, name: name, profile: profile, overrides: overrides)
                    } else {
                        node = try await client.createNode(name: name, profile: profile, overrides: overrides)
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
