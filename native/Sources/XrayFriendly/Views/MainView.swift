import SwiftUI
import XrayFriendlyCore

extension Node {
    /// Sort key for the Latency column (measured first, then n/a, untested, timeout).
    var latencySort: Int { Format.latencySortKey(latencyMs) }
}

struct MainView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    @State private var searchPresented = false

    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            Sidebar()
                .navigationSplitViewColumnWidth(min: 200, ideal: 220, max: 280)
        } detail: {
            Group {
                if let err = model.startupError {
                    ContentUnavailableView("Backend not available", systemImage: "exclamationmark.triangle", description: Text(err))
                } else if !model.ready {
                    ProgressView("Starting…")
                } else {
                    switch model.sidebar {
                    case .servers: ServersView()
                    case .subscriptions: SubscriptionsView()
                    case .routing: ScrollView { RoutingForm().padding(24) }.navigationTitle("Routing")
                    case .activity: ActivityView()
                    case .engines: ScrollView { EnginesPane().padding(24) }.navigationTitle("Engines")
                    }
                }
            }
        }
        .tint(Palette.accent)
        .searchable(text: $model.search, isPresented: $searchPresented, placement: .toolbar, prompt: "Search")
        .onChange(of: model.focusSearch) { _, on in
            if on { searchPresented = true; model.focusSearch = false }
        }
        .sheet(isPresented: $model.showImport) { ImportSheet(initialText: model.importPrefill) }
        .sheet(item: $model.qrNode) { QRSheet(node: $0) }
        .sheet(item: $model.configPreview) { ConfigSheet(preview: $0) }
        .alert("Something went wrong", isPresented: Binding(get: { model.errorMessage != nil }, set: { if !$0 { model.errorMessage = nil } })) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(model.errorMessage ?? "")
        }
        .task(id: model.ready) {
            if model.needsOnboarding && !UserDefaults.standard.bool(forKey: "onboardingDone") {
                openWindow(id: "onboarding")
            }
        }
    }
}

// MARK: sidebar

struct Sidebar: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        List(selection: $model.sidebar) {
            Section("Proxy") {
                row(.servers, "Servers", "globe", count: model.nodes.count)
                row(.subscriptions, "Subscriptions", "dot.radiowaves.up.forward", count: model.subscriptions.count)
                row(.routing, "Routing", "arrow.triangle.branch", count: nil)
                row(.activity, "Activity", "waveform.path.ecg", count: nil)
            }
            Section("Engine") {
                Label("Engines", systemImage: "cpu")
                    .badge(Text(model.engines.map { $0.name == "xray" ? "Xray" : $0.displayName }.joined(separator: " · ")))
                    .tag(SidebarItem.engines)
            }
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .bottom) { SystemProxyCard().padding(10) }
    }

    @ViewBuilder
    private func row(_ item: SidebarItem, _ title: String, _ icon: String, count: Int?) -> some View {
        if let count, count > 0 {
            Label(title, systemImage: icon).badge(count).tag(item)
        } else {
            Label(title, systemImage: icon).tag(item)
        }
    }
}

struct SystemProxyCard: View {
    @Environment(AppModel.self) private var model

    private var on: Bool { model.status.systemProxyOn }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text("System Proxy").font(.system(size: 12, weight: .semibold))
                Spacer()
                Toggle("System proxy", isOn: Binding(get: { on }, set: { model.setSystemProxy($0) }))
                    .toggleStyle(.switch).controlSize(.mini).labelsHidden().tint(Palette.green)
            }
            Text(caption)
                .font(.system(size: 11))
                .foregroundStyle(Palette.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.horizontal, 12).padding(.vertical, 10)
        .background(RoundedRectangle(cornerRadius: 10).fill(Palette.card))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Palette.cardBorder))
    }

    private var caption: String {
        if on {
            let services = model.status.systemProxyServices.joined(separator: ", ")
            return "On for \(services.isEmpty ? "this Mac" : services). Apps use the proxy automatically."
        }
        return model.settings.autoSystemProxy ? "Off. Turns on when you connect." : "Off."
    }
}

// MARK: servers

struct ServersView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        @Bindable var model = model
        VStack(spacing: 16) {
            ConnectionCard()
            ProtocolChips()
            ServerTable()
        }
        .padding(.top, 16).padding(.horizontal, 20)
        .navigationTitle("Servers")
        .navigationSubtitle(Format.serverSummary(model.nodes))
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Menu {
                    Button("TCP quick test") { model.testLatency("tcp") }
                    Button("Real test") { model.testLatency("real") }
                } label: {
                    Label(model.testing ? "Testing…" : "Test Latency", systemImage: "bolt")
                } primaryAction: {
                    model.testLatency()
                }
                .help("Test latency (⌘T)")
                .disabled(model.testing || model.nodes.isEmpty)

                Menu {
                    Button("Add Servers…") { model.openImport() }
                    Button("New Server…") { openWindow(id: "server", value: EditorTarget.new) }
                    Button("New Proxy Chain…") { openWindow(id: "server", value: EditorTarget.newChain) }
                } label: {
                    Label("Add servers", systemImage: "plus")
                } primaryAction: {
                    model.openImport()
                }
                .help("Add servers (⌘N)")
                .accessibilityLabel("Add servers")

                Button { model.showInspector.toggle() } label: { Label("Server details", systemImage: "sidebar.trailing") }
                    .help("Show or hide server details")
            }
        }
        .inspector(isPresented: $model.showInspector) {
            Inspector().inspectorColumnWidth(min: 250, ideal: 276, max: 360)
        }
    }
}

struct ConnectionCard: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let connected = model.connected
        let node = model.activeNode ?? model.selectedNode
        HStack(spacing: 16) {
            RoundedRectangle(cornerRadius: 12)
                .fill(connected ? Palette.green : Palette.idleShield)
                .frame(width: 44, height: 44)
                .overlay(BrandMark(fallback: connected ? "checkmark.shield" : "shield", size: 28))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(connected ? "Connected" : "Not Connected").font(.system(size: 17, weight: .bold))
                    if connected {
                        Text(verbatim: "\(model.status.activeNode) · \(Format.latency(model.status.activeLatencyMs))")
                            .font(.system(size: 12, weight: .semibold)).foregroundStyle(Palette.greenText)
                    }
                }
                TimelineView(.periodic(from: .now, by: 1)) { ctx in
                    Text(subtitle(node: node, now: ctx.date))
                        .font(.system(size: 12)).foregroundStyle(Palette.secondary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 8)
            if connected, model.traffic.available { TrafficGauge(traffic: model.traffic) }
            Toggle("Auto-select fastest", isOn: Binding(get: { model.settings.autoPick }, set: { model.setAutoPick($0) }))
                .toggleStyle(.checkbox)
                .font(.system(size: 12))
            Button(connected ? "Disconnect" : "Connect") { model.toggleConnection() }
                .buttonStyle(.borderedProminent)
                .tint(connected ? Color(nsColor: .controlColor) : Palette.accent)
                .foregroundStyle(connected ? Color.primary : Color.white)
                .controlSize(.large)
                .frame(minWidth: 112)
                .disabled(model.connecting || (!connected && node == nil))
                .accessibilityValue(connected ? "Connected" : "Not connected")
        }
        .padding(.vertical, 16).padding(.horizontal, 18)
        .background(RoundedRectangle(cornerRadius: 12).fill(connected ? Palette.connectedCard : Palette.idleCard))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(connected ? Palette.connectedBorder : Palette.separator))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Connection")
    }

    private func subtitle(node: Node?, now: Date) -> String {
        if model.connected {
            var uptime = model.status.uptimeSec
            if let start = model.status.startedAt, start > .distantPast { uptime = Int(now.timeIntervalSince(start)) }
            let proto = [model.status.protocol, model.status.transport].compactMap { $0 }.joined(separator: " · ")
            return "\(proto)  ·  Up \(Format.uptime(uptime))  ·  \(Format.routingDescription(model.status.routingMode))"
        }
        guard let node else { return "Add a server to get started." }
        return "Your traffic is going out directly. Connect to route it through \(node.displayName)."
    }
}

/// Live speed, totals and a short history of the running connection.
struct TrafficGauge: View {
    let traffic: Traffic

    var body: some View {
        HStack(spacing: 10) {
            Sparkline(samples: traffic.history)
                .frame(width: 64, height: 26)
                .accessibilityHidden(true)
            VStack(alignment: .trailing, spacing: 2) {
                Text(verbatim: "↓ \(Format.rate(traffic.downBps))").foregroundStyle(Palette.greenText)
                Text(verbatim: "↑ \(Format.rate(traffic.upBps))").foregroundStyle(Palette.secondary)
            }
            .font(.system(size: 11, weight: .semibold)).monospacedDigit()
            VStack(alignment: .trailing, spacing: 2) {
                Text(verbatim: Format.bytes(traffic.downTotal))
                Text(verbatim: Format.bytes(traffic.upTotal))
            }
            .font(.system(size: 11)).monospacedDigit().foregroundStyle(Palette.tertiary)
        }
        .help("Download and upload speed, and the totals since you connected")
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Traffic")
        .accessibilityValue("Download \(Format.rate(traffic.downBps)), upload \(Format.rate(traffic.upBps)). Total \(Format.bytes(traffic.downTotal)) down, \(Format.bytes(traffic.upTotal)) up")
    }
}

/// Download speed over the last minute.
struct Sparkline: View {
    let samples: [TrafficSample]

    var body: some View {
        Canvas { ctx, size in
            let vals = samples.map { Double($0.down) }
            guard vals.count > 1, let top = vals.max(), top > 0 else { return }
            var path = Path()
            for (i, v) in vals.enumerated() {
                let x = size.width * CGFloat(i) / CGFloat(max(1, 59))
                let y = size.height - size.height * CGFloat(v / top)
                i == 0 ? path.move(to: CGPoint(x: x, y: y)) : path.addLine(to: CGPoint(x: x, y: y))
            }
            ctx.stroke(path, with: .color(Palette.green), lineWidth: 1.5)
        }
    }
}

struct ProtocolChips: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let chips = [("All", model.nodes.count)] + model.presentProtocols.map { ($0.name, $0.count) }
        FlowLayout(spacing: 6) {
                ForEach(chips, id: \.0) { name, count in
                    let on = model.protocolFilter == name
                    Button { model.protocolFilter = name } label: {
                        HStack(spacing: 5) {
                            Text(name).font(.system(size: 12, weight: .medium))
                            Text(verbatim: "\(count)").font(.system(size: 11)).foregroundStyle(on ? Color.white.opacity(0.85) : Palette.secondary)
                        }
                        .padding(.horizontal, 10).frame(height: 24)
                        .foregroundStyle(on ? Color.white : Color.primary)
                        .background(Capsule().fill(on ? Palette.accent : Palette.card))
                        .overlay(Capsule().stroke(on ? Palette.accent : Palette.cardBorder))
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("\(name), \(count) servers")
                    .accessibilityAddTraits(on ? .isSelected : [])
                }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Filter by protocol")
        .padding(.bottom, -6)
    }
}

struct ServerTable: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    @State private var sortOrder = [KeyPathComparator(\Node.latencySort)]
    @State private var pendingDelete: [Node.ID] = []

    var body: some View {
        @Bindable var model = model
        let groups = model.groups(sortedBy: sortOrder)
        Table(of: Node.self, selection: $model.selectedNodeIDs, sortOrder: $sortOrder) {
            TableColumn("") { n in
                Circle().fill(isActive(n) ? Palette.green : .clear).frame(width: 8, height: 8)
                    .accessibilityLabel("Connected")
                    .accessibilityHidden(!isActive(n))
            }
            .width(24)
            TableColumn("Name", value: \.displayName) { n in
                HStack(spacing: 8) {
                    if n.isChain {
                        Image(systemName: "link").font(.system(size: 11, weight: .semibold)).foregroundStyle(Palette.accentText)
                            .accessibilityLabel("Chain")
                    }
                    if let cc = n.countryCode {
                        Text(cc).font(.system(size: 10, weight: .bold)).tracking(0.3)
                            .foregroundStyle(Palette.tertiary)
                            .padding(.horizontal, 4).padding(.vertical, 2)
                            .background(RoundedRectangle(cornerRadius: 4).fill(Palette.badge))
                    }
                    Text(n.displayName).fontWeight(isActive(n) ? .semibold : .regular).lineLimit(1).truncationMode(.tail)
                    if isActive(n) {
                        Text("Active").font(.system(size: 11, weight: .semibold)).foregroundStyle(Palette.greenText)
                    }
                    if n.engine == nil, let why = n.engineReason {
                        Image(systemName: "exclamationmark.triangle").foregroundStyle(Palette.warn).help(why)
                            .accessibilityLabel("Cannot run: \(why)")
                    }
                }
            }
            TableColumn("Protocol", value: \.protocolName) { Text($0.protocolName).foregroundStyle(Palette.tertiary) }
                .width(92)
            TableColumn("Transport", value: \.transport) { Text($0.transport).foregroundStyle(Palette.tertiary) }
                .width(96)
            TableColumn("Latency", value: \.latencySort) { n in
                let c = Palette.latency(n.latencyMs)
                HStack {
                    Spacer()
                    Text(Format.latency(n.latencyMs))
                        .font(.system(size: 12, weight: .semibold)).monospacedDigit()
                        .foregroundStyle(c.fg)
                        .padding(.horizontal, 7).padding(.vertical, 2)
                        .background(RoundedRectangle(cornerRadius: 5).fill(c.bg))
                        .accessibilityLabel(Format.latencyLong(n.latencyMs))
                }
            }
            .width(84)
        } rows: {
            ForEach(groups) { g in
                Section {
                    ForEach(g.nodes) { TableRow($0) }
                } header: {
                    HStack(spacing: 8) {
                        Text(g.title).font(.system(size: 12, weight: .bold))
                        Text(g.meta).font(.system(size: 11)).foregroundStyle(Palette.secondary)
                    }
                }
            }
        }
        .contextMenu(forSelectionType: Node.ID.self) { ids in
            if ids.count > 1 {
                Button("Delete \(ids.count) Servers…", role: .destructive) { pendingDelete = Array(ids) }
            } else if let id = ids.first, let n = model.nodes.first(where: { $0.id == id }) {
                Button("Connect") { model.connect(id) }
                Button("Test") { model.testLatency() }
                Divider()
                Button("Copy Link") { model.copyLink(n) }.disabled(!n.hasLink)
                Button("Show QR") { model.qrNode = n }.disabled(!n.hasLink)
                Button("View Config…") { model.showConfig(of: n) }
                Button(n.isChain ? "Edit Chain…" : "Edit…") { openWindow(id: "server", value: EditorTarget.edit(id)) }
                Divider()
                Button("Delete", role: .destructive) { model.delete([id]) }
            }
        } primaryAction: { ids in
            if ids.count == 1, let id = ids.first { model.connect(id) } // double-click / Return
        }
        .onDeleteCommand {
            let ids = Array(model.selectedNodeIDs)
            if ids.count == 1 { model.delete(ids) } else if ids.count > 1 { pendingDelete = ids }
        }
        .confirmationDialog("Delete \(pendingDelete.count) servers?", isPresented: Binding(
            get: { !pendingDelete.isEmpty }, set: { if !$0 { pendingDelete = [] } }), titleVisibility: .visible) {
            Button("Delete \(pendingDelete.count) Servers", role: .destructive) {
                model.delete(pendingDelete)
                pendingDelete = []
            }
        } message: {
            Text("This removes them from your list. Chains that use them will stop working.")
        }
        .overlay {
            if model.nodes.isEmpty {
                ContentUnavailableView {
                    Label("No servers yet", systemImage: "globe")
                } description: {
                    Text("Paste a share link, a subscription URL, an OpenVPN or WireGuard config file, or a Clash or sing-box config.")
                } actions: {
                    Button("Add Servers…") { model.openImport() }.buttonStyle(.borderedProminent)
                }
            } else if groups.isEmpty {
                ContentUnavailableView.search(text: model.search)
            }
        }
        .accessibilityLabel("Servers")
    }

    private func isActive(_ n: Node) -> Bool { model.connected && n.id == model.status.activeNodeId }
}

// MARK: inspector

struct Inspector: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let n = model.selectedNode {
                let active = model.connected && n.id == model.status.activeNodeId
                VStack(alignment: .leading, spacing: 4) {
                    Text([n.countryCode, model.source(of: n)].compactMap { $0 }.joined(separator: " · "))
                        .font(.system(size: 11, weight: .bold)).tracking(0.3).foregroundStyle(Palette.tertiary)
                    Text(n.displayName).font(.system(size: 17, weight: .bold)).lineLimit(2)
                    Text(Format.latencyLong(n.latencyMs)).font(.system(size: 12, weight: .semibold)).foregroundStyle(Palette.latency(n.latencyMs).fg)
                }
                if n.isChain {
                    ChainRouteCard(node: n)
                } else {
                    Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 9) {
                        detail("Address", n.server, mono: true)
                        detail("Port", String(n.port))
                        detail("Protocol", n.protocolName)
                        detail("Transport", n.transport)
                        detail("Security", n.security)
                        detail("SNI", n.sni)
                        detail("Engine", n.engine.map { model.engineBadge($0) } ?? "None — \(n.engineReason ?? "unsupported")")
                    }
                    .font(.system(size: 12))
                    .padding(12)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(RoundedRectangle(cornerRadius: 10).fill(Palette.card))
                    .overlay(RoundedRectangle(cornerRadius: 10).stroke(Palette.separator))
                }

                VStack(spacing: 8) {
                    Button {
                        active ? model.disconnect() : model.connect(n.id)
                    } label: {
                        Text(active ? "Disconnect" : "Connect to This Server").fontWeight(.semibold).frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent).controlSize(.large)
                    .disabled(n.engine == nil || model.connecting)
                    HStack(spacing: 8) {
                        Button { model.copyLink(n) } label: { Label("Copy Link", systemImage: "doc.on.doc").frame(maxWidth: .infinity) }
                            .disabled(!n.hasLink)
                        Button { model.qrNode = n } label: { Label("QR Code", systemImage: "qrcode").frame(maxWidth: .infinity) }
                            .disabled(!n.hasLink)
                    }
                    .controlSize(.regular)
                    HStack(spacing: 14) {
                        Button(n.isChain ? "Edit Chain…" : "Edit Server…") { openWindow(id: "server", value: EditorTarget.edit(n.id)) }
                        Button("View Config…") { model.showConfig(of: n) }
                    }
                    .buttonStyle(.link).font(.system(size: 12))
                }
            } else {
                ContentUnavailableView("No server selected", systemImage: "globe")
            }
            Spacer()
            Divider()
            VStack(alignment: .leading, spacing: 6) {
                Text("Local proxies").font(.system(size: 11, weight: .semibold)).foregroundStyle(Palette.secondary)
                if let p = model.socksPort { portRow("SOCKS5", p) }
                if let p = model.httpPort { portRow("HTTP", p) }
                Button("Copy terminal export command") { model.copyExportCommand() }
                    .buttonStyle(.link).font(.system(size: 12))
            }
        }
        .padding(18)
        .frame(maxHeight: .infinity, alignment: .top)
        .background(Palette.inspector)
        .accessibilityLabel("Server details")
    }

    @ViewBuilder
    private func detail(_ label: String, _ value: String, mono: Bool = false) -> some View {
        GridRow {
            Text(label).foregroundStyle(Palette.secondary).frame(width: 70, alignment: .leading)
            Text(value).font(mono ? .system(size: 11, design: .monospaced) : .system(size: 12))
                .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
        }
    }

    private func portRow(_ name: String, _ port: Int) -> some View {
        HStack {
            Text(name).font(.system(size: 12))
            Spacer()
            Text(verbatim: "127.0.0.1:\(port)").font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
        }
    }
}

/// The generated engine configuration of a server, read-only.
struct ConfigSheet: View {
    let preview: ConfigPreview
    @Environment(\.dismiss) private var dismiss
    @State private var index = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Config for \(preview.title)").font(.headline)
            if preview.configs.count > 1 {
                Picker("Process", selection: $index) {
                    ForEach(preview.engines.indices, id: \.self) { Text("\($0 + 1). \(preview.engines[$0])").tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden()
            } else if let e = preview.engines.first {
                Text("Runs on \(e)").font(.system(size: 12)).foregroundStyle(Palette.secondary)
            }
            ScrollView {
                Text(preview.configs.indices.contains(index) ? preview.configs[index] : "")
                    .font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(10)
            }
            .background(RoundedRectangle(cornerRadius: 8).fill(Color(nsColor: .textBackgroundColor)))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(Palette.cardBorder))
            Text("This is read-only and shows the server's credentials. Ports of the traffic counters change on every connection.")
                .font(.system(size: 11)).foregroundStyle(Palette.secondary)
            HStack {
                Button("Copy") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(preview.configs.indices.contains(index) ? preview.configs[index] : "", forType: .string)
                }
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(20).frame(width: 620, height: 520)
    }
}

struct QRSheet: View {
    let node: Node
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 14) {
            Text(node.displayName).font(.headline)
            if let link = node.rawLink, let img = QR.image(for: link) {
                Image(nsImage: img).interpolation(.none).resizable().frame(width: 280, height: 280)
                    .accessibilityLabel("QR code for \(node.displayName)")
            }
            Text("Scan with another device to add this server. The code contains the server's credentials.")
                .font(.system(size: 11)).foregroundStyle(Palette.secondary).multilineTextAlignment(.center).frame(width: 300)
            Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
        }
        .padding(24)
    }
}

/// Lays children out in rows, wrapping like the mockup's flex-wrap chip row.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let rows = arrange(proposal.width ?? .infinity, subviews)
        return CGSize(width: rows.map(\.width).max() ?? 0, height: rows.reduce(0) { $0 + $1.height } + spacing * CGFloat(max(0, rows.count - 1)))
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var y = bounds.minY
        for row in arrange(bounds.width, subviews) {
            var x = bounds.minX
            for i in row.items {
                let size = subviews[i].sizeThatFits(.unspecified)
                subviews[i].place(at: CGPoint(x: x, y: y), proposal: ProposedViewSize(size))
                x += size.width + spacing
            }
            y += row.height + spacing
        }
    }

    private struct Row { var items: [Int] = []; var width: CGFloat = 0; var height: CGFloat = 0 }

    private func arrange(_ maxWidth: CGFloat, _ subviews: Subviews) -> [Row] {
        var rows = [Row()]
        for (i, v) in subviews.enumerated() {
            let size = v.sizeThatFits(.unspecified)
            if !rows[rows.count - 1].items.isEmpty && rows[rows.count - 1].width + spacing + size.width > maxWidth {
                rows.append(Row())
            }
            var r = rows[rows.count - 1]
            r.width += (r.items.isEmpty ? 0 : spacing) + size.width
            r.height = max(r.height, size.height)
            r.items.append(i)
            rows[rows.count - 1] = r
        }
        return rows
    }
}

/// The inspector's description of a chain: its servers in the order traffic takes.
struct ChainRouteCard: View {
    let node: Node
    @Environment(AppModel.self) private var model

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Route").font(.system(size: 11, weight: .semibold)).foregroundStyle(Palette.secondary)
            let hops = node.hopList
            ForEach(Array(hops.enumerated()), id: \.offset) { i, h in
                HStack(spacing: 8) {
                    Text(verbatim: "\(i + 1)").font(.system(size: 10, weight: .bold)).foregroundStyle(.white)
                        .frame(width: 18, height: 18).background(Circle().fill(h.missing ? Palette.error : Palette.accent))
                        .accessibilityHidden(true)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(h.missing ? "Missing server" : h.name).font(.system(size: 12, weight: .medium))
                            .foregroundStyle(h.missing ? Palette.error : Color.primary).lineLimit(1)
                        Text([h.protocolName.isEmpty ? nil : h.protocolName, h.transport, i == 0 ? "entry" : (i == hops.count - 1 ? "exit" : nil)]
                            .compactMap { $0 }.joined(separator: " · "))
                            .font(.system(size: 11)).foregroundStyle(Palette.secondary).lineLimit(1)
                    }
                }
                .accessibilityElement(children: .combine)
                .accessibilityLabel("Hop \(i + 1), \(h.missing ? "missing server" : h.name)")
            }
            Divider()
            HStack {
                Text("Engine").font(.system(size: 12)).foregroundStyle(Palette.secondary)
                Spacer()
                Text(node.engineName ?? "None").font(.system(size: 12))
            }
            if let err = node.error, !err.isEmpty {
                Label(err, systemImage: "exclamationmark.triangle").font(.system(size: 11)).foregroundStyle(Palette.error)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let why = node.engineReason, node.engine == nil {
                Label(why, systemImage: "exclamationmark.triangle").font(.system(size: 11)).foregroundStyle(Palette.warn)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10).fill(Palette.card))
        .overlay(RoundedRectangle(cornerRadius: 10).stroke(Palette.separator))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Chain route")
    }
}

/// The app's shield-and-key logo (white on transparent), shipped as Logo.png in the bundle.
struct BrandMark: View {
    let fallback: String
    let size: CGFloat
    private static let image: NSImage? = Bundle.main.url(forResource: "Logo", withExtension: "png").flatMap { NSImage(contentsOf: $0) }

    var body: some View {
        if let img = Self.image {
            Image(nsImage: img).resizable().interpolation(.high).scaledToFit().frame(width: size, height: size)
        } else {
            Image(systemName: fallback).font(.system(size: size * 0.7, weight: .semibold)).foregroundStyle(.white)
        }
    }
}
