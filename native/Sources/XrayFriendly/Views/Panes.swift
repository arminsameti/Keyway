import SwiftUI
import XrayFriendlyCore

// MARK: shared building blocks (the Settings › Engines card style)

struct CardSection<Content: View>: View {
    let title: String
    var caption: String?
    var footnote: String?
    @ViewBuilder var content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title).font(.system(size: 13, weight: .bold)).accessibilityAddTraits(.isHeader)
            if let caption {
                Text(caption).font(.system(size: 12)).foregroundStyle(Palette.secondary).fixedSize(horizontal: false, vertical: true)
            }
            VStack(spacing: 0) { content }
                .background(RoundedRectangle(cornerRadius: 10).fill(Palette.card))
                .overlay(RoundedRectangle(cornerRadius: 10).stroke(Palette.cardBorder))
            if let footnote {
                Text(footnote).font(.system(size: 11)).foregroundStyle(Palette.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

struct CardRow<Trailing: View>: View {
    let label: String
    var first = false
    @ViewBuilder var trailing: Trailing

    var body: some View {
        VStack(spacing: 0) {
            if !first { Divider().padding(.leading, 14) }
            HStack(spacing: 12) {
                Text(label).frame(maxWidth: .infinity, alignment: .leading)
                trailing
            }
            .padding(.horizontal, 14).frame(minHeight: 40)
        }
    }
}

/// Binds a settings field and saves on every change.
@MainActor
func settingBinding<T>(_ model: AppModel, _ key: WritableKeyPath<AppSettings, T>) -> Binding<T> {
    Binding(get: { model.settings[keyPath: key] }, set: { v in
        var s = model.settings
        s[keyPath: key] = v
        model.save(s)
    })
}

// MARK: subscriptions

struct SubscriptionsView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        List {
            ForEach(model.subscriptions) { sub in
                HStack(alignment: .top, spacing: 12) {
                    Image(systemName: "dot.radiowaves.up.forward").foregroundStyle(Palette.accentText).frame(width: 18)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(sub.name).font(.system(size: 13, weight: .semibold))
                        Text(URL(string: sub.url)?.host ?? sub.url).font(.system(size: 11, design: .monospaced)).foregroundStyle(Palette.secondary)
                        Text([Format.plural(sub.nodeCount, "server"), Format.updated(sub.updatedAt), Format.formatName(sub.format)]
                            .compactMap { $0 }.joined(separator: " · "))
                            .font(.system(size: 11)).foregroundStyle(Palette.secondary)
                        if let err = sub.lastError, !err.isEmpty {
                            Label(err, systemImage: "exclamationmark.triangle").font(.system(size: 11)).foregroundStyle(Palette.warn)
                        }
                    }
                    Spacer()
                    Button("Refresh") { model.refreshSubscription(sub.id) }
                    Button(role: .destructive) { model.deleteSubscription(sub.id) } label: { Image(systemName: "trash") }
                        .help("Remove this subscription and its servers")
                        .accessibilityLabel("Remove \(sub.name)")
                }
                .padding(.vertical, 6)
            }
        }
        .overlay {
            if model.subscriptions.isEmpty {
                ContentUnavailableView {
                    Label("No subscriptions", systemImage: "dot.radiowaves.up.forward")
                } description: {
                    Text("A subscription URL from your provider keeps your server list up to date.")
                } actions: {
                    Button("Add Subscription…") { model.openImport() }.buttonStyle(.borderedProminent)
                }
            }
        }
        .navigationTitle("Subscriptions")
        .navigationSubtitle(Format.plural(model.subscriptions.count, "subscription"))
        .toolbar {
            ToolbarItemGroup {
                Button { model.refreshAllSubscriptions() } label: { Label("Refresh All", systemImage: "arrow.clockwise") }
                    .disabled(model.subscriptions.isEmpty)
                Button { model.openImport() } label: { Label("Add", systemImage: "plus") }
                    .accessibilityLabel("Add subscription")
            }
        }
    }
}

// MARK: routing

struct RoutingForm: View {
    @Environment(AppModel.self) private var model
    @State private var direct = ""
    @State private var proxy = ""
    @State private var blocked = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            CardSection(title: "Routing mode", caption: "Decides which traffic goes through the proxy.") {
                CardRow(label: "Route traffic", first: true) {
                    Picker("Route traffic", selection: routingModeBinding) {
                        Text("Bypass private & local sites").tag("bypass-private")
                        Text("Everything through the proxy").tag("global")
                        Text("Custom rules").tag("custom")
                        Text("Rule sets (advanced)").tag("rules")
                    }
                    .labelsHidden().fixedSize()
                }
                CardRow(label: "Block ads and trackers") {
                    Toggle("Block ads and trackers", isOn: settingBinding(model, \.blockAds)).labelsHidden()
                }
                CardRow(label: "Detect the site name in traffic (sniffing)") {
                    Toggle("Sniffing", isOn: settingBinding(model, \.sniffing)).labelsHidden()
                }
            }
            if model.settings.routingMode == "rules" {
                RuleSetEditor()
            } else {
            CardSection(title: "Sites", footnote: "One entry per line or comma separated: geosite:cn, geoip:ir, domain:example.org, full:www.example.org, keyword:bank, or an IP range such as 10.0.0.0/8.") {
                editor("Go direct", $direct, first: true)
                if model.settings.routingMode == "custom" { editor("Always through the proxy", $proxy) }
                editor("Blocked", $blocked)
            }
            HStack {
                Spacer()
                Button("Revert") { load() }.disabled(!dirty)
                Button("Save Rules") {
                    var s = model.settings
                    s.directSites = direct; s.proxySites = proxy; s.blockedSites = blocked
                    model.save(s)
                }
                .buttonStyle(.borderedProminent).disabled(!dirty)
            }
            }
        }
        .frame(maxWidth: 680)
        .onAppear(perform: load)
    }

    /// Switching to rule sets creates a starter set when there is none, so the mode is never invalid.
    private var routingModeBinding: Binding<String> {
        Binding(get: { model.settings.routingMode }, set: { mode in
            var s = model.settings
            s.routingMode = mode
            if mode == "rules", !s.ruleSets.contains(where: { $0.id == s.activeRuleSet }) {
                if s.ruleSets.isEmpty { s.ruleSets = [RuleEditing.template()] }
                s.activeRuleSet = s.ruleSets[0].id
            }
            model.save(s)
        })
    }

    private var dirty: Bool {
        direct != model.settings.directSites || proxy != model.settings.proxySites || blocked != model.settings.blockedSites
    }

    private func load() {
        direct = model.settings.directSites
        proxy = model.settings.proxySites
        blocked = model.settings.blockedSites
    }

    private func editor(_ label: String, _ text: Binding<String>, first: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            if !first { Divider() }
            Text(label).font(.system(size: 12, weight: .semibold)).padding(.top, 8)
            TextEditor(text: text)
                .font(.system(size: 11, design: .monospaced))
                .frame(height: 64)
                .scrollContentBackground(.hidden)
                .accessibilityLabel(label)
        }
        .padding(.horizontal, 14).padding(.bottom, 10)
    }
}

// MARK: activity

struct ActivityView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 2) {
                    ForEach(Array(model.logs.enumerated()), id: \.offset) { i, line in
                        Text(line).font(.system(size: 11, design: .monospaced)).textSelection(.enabled).id(i)
                    }
                }
                .padding(16)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .onChange(of: model.logs.count) { _, n in if n > 0 { proxy.scrollTo(n - 1, anchor: .bottom) } }
        }
        .overlay {
            if model.logs.isEmpty {
                ContentUnavailableView("No activity yet", systemImage: "waveform.path.ecg",
                                       description: Text("Engine messages appear here while you are connected."))
            }
        }
        .navigationTitle("Activity")
        .navigationSubtitle(model.status.running ? "Engine running" : "Engine stopped")
        .toolbar {
            ToolbarItemGroup {
                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(model.logs.joined(separator: "\n"), forType: .string)
                } label: { Label("Copy", systemImage: "doc.on.doc") }
                Button { model.clearLogs() } label: { Label("Clear", systemImage: "trash") }
            }
        }
        .task {
            while !Task.isCancelled {
                await model.pollLogs()
                try? await Task.sleep(for: .seconds(1))
            }
        }
    }
}

// MARK: engines (Settings › Engines)

struct EnginesPane: View {
    @Environment(AppModel.self) private var model
    @State private var socks = ""
    @State private var http = ""
    @State private var lanUser = ""
    @State private var lanPass = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            CardSection(title: "Proxy engines",
                        caption: "Each server runs on the engine that supports its protocol. Downloads come from the official GitHub releases and are checked against their SHA-256 checksums.") {
                ForEach(Array(model.engines.enumerated()), id: \.element.id) { i, e in
                    if i > 0 { Divider().padding(.leading, 64) }
                    EngineCard(engine: e)
                }
            }
            CardSection(title: "Behavior") {
                CardRow(label: "When both engines support a protocol", first: true) {
                    Picker("Engine preference", selection: settingBinding(model, \.enginePreference)) {
                        Text("Prefer Xray core").tag("xray")
                        Text("Prefer sing-box").tag("sing-box")
                    }.labelsHidden().fixedSize()
                }
                CardRow(label: "Download an engine when a new server needs it") {
                    Toggle("Download engines automatically", isOn: settingBinding(model, \.autoDownloadEngines)).labelsHidden().toggleStyle(.checkbox)
                }
                CardRow(label: "Check for engine updates") {
                    Picker("Update checks", selection: settingBinding(model, \.engineUpdateCheck)) {
                        Text("Never").tag("never"); Text("Daily").tag("daily"); Text("Weekly").tag("weekly")
                    }.labelsHidden().fixedSize()
                }
                CardRow(label: "Latency test method") {
                    Picker("Latency test method", selection: settingBinding(model, \.latencyMethod)) {
                        Text("Real request (accurate, works for UDP)").tag("real")
                        Text("TCP connect (fast, not for UDP)").tag("tcp")
                    }.labelsHidden().fixedSize()
                }
            }
            CardSection(title: "Local proxy ports",
                        footnote: "Turning this on requires a username and password, so the proxy is never open to everyone.") {
                CardRow(label: "SOCKS5", first: true) { portField("SOCKS5 port", $socks, proto: "socks") }
                CardRow(label: "HTTP") { portField("HTTP port", $http, proto: "http") }
                CardRow(label: "Allow devices on my network to connect") {
                    Toggle("Allow LAN", isOn: Binding(get: { model.settings.allowLan }, set: setLAN)).labelsHidden().toggleStyle(.checkbox)
                }
                if model.settings.allowLan || !lanUser.isEmpty {
                    CardRow(label: "Username") { TextField("Username", text: $lanUser).frame(width: 160).labelsHidden() }
                    CardRow(label: "Password") {
                        SecureField("Password", text: $lanPass).frame(width: 160).labelsHidden()
                        Button("Apply") { applyCredentials(allowLan: true) }.disabled(lanUser.isEmpty || lanPass.isEmpty)
                    }
                }
            }
        }
        .frame(maxWidth: 680)
        .onAppear(perform: load)
        .onChange(of: model.settings) { _, _ in load() }
    }

    private func load() {
        socks = model.socksPort.map(String.init) ?? ""
        http = model.httpPort.map(String.init) ?? ""
        if let ib = model.settings.inbounds.first(where: { ($0.username ?? "").isEmpty == false }) {
            lanUser = ib.username ?? ""
            lanPass = ib.password ?? ""
        }
    }

    private func portField(_ label: String, _ text: Binding<String>, proto: String) -> some View {
        TextField(label, text: text)
            .multilineTextAlignment(.trailing).monospacedDigit()
            .frame(width: 72).labelsHidden()
            .accessibilityLabel(label)
            .onSubmit {
                guard let p = Int(text.wrappedValue), (1...65535).contains(p) else { load(); return }
                var s = model.settings
                if let i = s.inbounds.firstIndex(where: { $0.protocol == proto && $0.enabled }) { s.inbounds[i].port = p }
                model.save(s)
            }
    }

    private func setLAN(_ on: Bool) {
        if on && (lanUser.isEmpty || lanPass.isEmpty) {
            lanUser = lanUser.isEmpty ? "xf" : lanUser // reveal the credential fields first
            return
        }
        applyCredentials(allowLan: on)
    }

    private func applyCredentials(allowLan: Bool) {
        var s = model.settings
        s.allowLan = allowLan
        for i in s.inbounds.indices { s.inbounds[i].username = lanUser; s.inbounds[i].password = lanPass }
        model.save(s)
    }
}

struct EngineCard: View {
    let engine: EngineInfo
    @Environment(AppModel.self) private var model
    @State private var releases: [Release] = []

    var body: some View {
        let job = model.job(for: engine.name)
        let installing = job?.state == "running"
        HStack(alignment: .top, spacing: 14) {
            let badge = Palette.engineBadge(engine.name)
            RoundedRectangle(cornerRadius: 9).fill(badge.bg).frame(width: 36, height: 36)
                .overlay(Text(engine.name == "xray" ? "X" : "sb").font(.system(size: 13, weight: .heavy)).foregroundStyle(badge.fg))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Text(engine.displayName).fontWeight(.bold)
                    Text(engine.active.isEmpty ? "Not installed" : "\(engine.active.dropFirst()) installed")
                        .font(.system(size: 12)).foregroundStyle(Palette.tertiary)
                }
                Text(engine.protocols.joined(separator: " · ")).font(.system(size: 12)).foregroundStyle(Palette.secondary)
                if installing, let job {
                    ProgressView(value: job.fraction ?? 0).frame(maxWidth: 260)
                        .accessibilityLabel("\(engine.displayName) download")
                } else if let job, job.state == "failed" {
                    Text(job.error ?? "Download failed").font(.system(size: 12, weight: .semibold)).foregroundStyle(Palette.error)
                } else {
                    stateLine
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 6) {
                if engine.active.isEmpty {
                    Button("Download") { model.download(engine: engine.name) }.buttonStyle(.borderedProminent).disabled(installing)
                } else if engine.updateAvailable {
                    Button("Update") { model.download(engine: engine.name, version: engine.latest ?? "") }
                        .buttonStyle(.borderedProminent).disabled(installing)
                } else {
                    Button("Check Now") { model.checkEngine(engine.name) }
                }
                Menu("Other versions…") {
                    if releases.isEmpty { Text("Loading…") }
                    ForEach(releases, id: \.tag) { r in
                        Button(r.tag + (r.installed ? " (installed)" : "") + (r.tag == engine.active ? " (active)" : "")) {
                            if r.installed { model.useEngine(engine.name, version: r.tag) } else { model.download(engine: engine.name, version: r.tag) }
                        }
                    }
                }
                .fixedSize()
                .accessibilityLabel("\(engine.displayName) version")
                .onHover { inside in if inside && releases.isEmpty { loadReleases() } }
            }
            .controlSize(.small)
        }
        .padding(14)
    }

    @ViewBuilder private var stateLine: some View {
        if engine.active.isEmpty {
            Text("Not installed").font(.system(size: 12, weight: .semibold)).foregroundStyle(Palette.secondary)
        } else if engine.updateAvailable, let latest = engine.latest {
            Text("Version \(latest.dropFirst()) is available").font(.system(size: 12, weight: .semibold)).foregroundStyle(Palette.warn)
        } else if let err = engine.checkError, !err.isEmpty {
            Text("Update check failed").font(.system(size: 12, weight: .semibold)).foregroundStyle(Palette.warn).help(err)
        } else if let c = engine.checkedAt, c > Date(timeIntervalSince1970: 0) {
            Text("Up to date").font(.system(size: 12, weight: .semibold)).foregroundStyle(Palette.greenText)
        } else {
            Text("Not checked yet").font(.system(size: 12)).foregroundStyle(Palette.secondary)
        }
    }

    private func loadReleases() {
        guard let client = model.client else { return }
        Task { releases = (try? await client.releases(engine.name)) ?? [] }
    }
}
