import AppKit
import CoreImage
import Observation
import ServiceManagement
import SwiftUI
import XrayFriendlyCore

enum SidebarItem: Hashable {
    case servers, subscriptions, routing, activity, engines
}

/// A server group in the table: one subscription or "Added Manually".
struct ServerGroup: Identifiable {
    let id: String
    let title: String
    let meta: String
    let nodes: [Node]
}

/// The single source of UI state. It owns the backend connection and polls it.
@MainActor @Observable
final class AppModel {
    // backend
    let backend = Backend()
    private(set) var client: APIClient?
    private(set) var ready = false
    var startupError: String?

    // data from the backend
    private(set) var status = Status()
    private(set) var nodes: [Node] = []
    private(set) var subscriptions: [Subscription] = []
    private(set) var settings = AppSettings()
    private(set) var engines: [EngineInfo] = []
    private(set) var jobs: [Job] = []
    private(set) var activeNodeId = ""
    private(set) var sysProxyServices: [String] = []

    // UI state
    var sidebar: SidebarItem = .servers
    var selectedNodeID: Node.ID?
    var protocolFilter = "All"
    var search = ""
    var showImport = false
    var importPrefill = ""
    var showInspector = true
    var focusSearch = false // set by ⌘F; MainView focuses the search field
    var qrNode: Node?
    var errorMessage: String?
    var testing = false
    var connecting = false
    var lastTestMode = "real"

    // activity log
    private(set) var logs: [String] = []
    private var logNext = 0

    private var pollTask: Task<Void, Never>?

    // MARK: lifecycle

    /// Snapshot rendering ("--snapshot <dir>") must never start a backend.
    static let isSnapshotRun = CommandLine.arguments.contains("--snapshot")

    func start() {
        guard pollTask == nil, !Self.isSnapshotRun else { return }
        backend.onCrash = { [weak self] msg in self?.errorMessage = msg }
        backend.resolvePort()
        pollTask = Task { [weak self] in
            guard let self else { return }
            await self.connectBackend()
            var tick = 0
            while !Task.isCancelled {
                await self.refreshStatus()
                if tick % 3 == 0 || self.jobs.contains(where: { $0.state == "running" }) { await self.refreshState() }
                tick += 1
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    func shutdown() {
        pollTask?.cancel()
        backend.stopIfOwned()
    }

    private func makeClient() -> APIClient? {
        guard let token = backend.token else { return nil }
        return APIClient(port: backend.port, token: token)
    }

    /// Uses a running backend or starts the bundled one, then loads everything.
    private func connectBackend() async {
        if let c = makeClient(), (try? await c.status()) != nil {
            client = c
        } else {
            guard backend.launch() else {
                startupError = "The xray-friendly backend was not found next to the app."
                return
            }
            for _ in 0..<60 {
                try? await Task.sleep(for: .milliseconds(250))
                backend.resolvePort()
                if let c = makeClient(), (try? await c.status()) != nil { client = c; break }
            }
        }
        guard client != nil else {
            startupError = "The backend did not start. Is another program using port \(backend.port)?"
            return
        }
        ready = true
        await refreshState()
        await refreshStatus()
    }

    func refreshStatus() async {
        guard let client else { return }
        do {
            status = try await client.status()
            backend.markHealthy()
        } catch {
            // The backend restarts itself; a new launch writes a new token.
            if let c = makeClient(), c.port != client.port || backend.token != nil { self.client = c }
        }
    }

    func refreshState() async {
        guard let client else { return }
        if let st = try? await client.state() {
            nodes = st.nodes
            subscriptions = st.subscriptions
            settings = st.settings
            engines = st.engines
            activeNodeId = st.activeNodeId
            sysProxyServices = st.systemProxyServices
            if selectedNodeID == nil || !nodes.contains(where: { $0.id == selectedNodeID }) {
                selectedNodeID = nodes.first { $0.id == activeNodeId }?.id ?? nodes.first?.id
            }
        }
        if let js = try? await client.jobs() { jobs = js }
    }

    /// Runs an action, shows its error, then refreshes.
    func perform(_ action: @escaping (APIClient) async throws -> Void) {
        guard let client else { return }
        Task {
            do { try await action(client) } catch { errorMessage = error.localizedDescription }
            await refreshState()
            await refreshStatus()
        }
    }

    // MARK: derived

    var connected: Bool { status.running }
    var activeNode: Node? { nodes.first { $0.id == (connected ? status.activeNodeId : activeNodeId) } }
    var selectedNode: Node? { nodes.first { $0.id == selectedNodeID } }
    var needsOnboarding: Bool { ready && (engines.allSatisfy { $0.installed.isEmpty } || nodes.isEmpty) }
    var socksPort: Int? { settings.port(of: "socks") }
    var httpPort: Int? { settings.port(of: "http") }

    var presentProtocols: [(name: String, count: Int)] {
        var counts: [String: Int] = [:]
        var order: [String] = []
        for n in nodes {
            if counts[n.protocolName] == nil { order.append(n.protocolName) }
            counts[n.protocolName, default: 0] += 1
        }
        return order.map { ($0, counts[$0]!) }
    }

    var filteredNodes: [Node] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        return nodes.filter { n in
            (protocolFilter == "All" || n.protocolName == protocolFilter) &&
                (q.isEmpty || n.displayName.lowercased().contains(q) || n.server.lowercased().contains(q) ||
                    n.protocolName.lowercased().contains(q) || (n.countryCode?.lowercased() == q))
        }
    }

    func groups(sortedBy order: [KeyPathComparator<Node>]) -> [ServerGroup] {
        let rows = filteredNodes
        var out: [ServerGroup] = []
        for sub in subscriptions {
            let g = rows.filter { $0.source == sub.id }.sorted(using: order)
            if g.isEmpty { continue }
            let meta = [Format.updated(sub.updatedAt), Format.formatName(sub.format)].compactMap { $0 }.joined(separator: " · ")
            out.append(ServerGroup(id: sub.id, title: sub.name, meta: meta, nodes: g))
        }
        let known = Set(subscriptions.map(\.id))
        let manual = rows.filter { ($0.source ?? "").isEmpty || !known.contains($0.source ?? "") }.sorted(using: order)
        if !manual.isEmpty { out.append(ServerGroup(id: "manual", title: "Added Manually", meta: "", nodes: manual)) }
        return out
    }

    func source(of n: Node) -> String {
        subscriptions.first { $0.id == n.source }?.name ?? "Added manually"
    }

    func engineBadge(_ name: String?) -> String {
        guard let name, let e = engines.first(where: { $0.name == name }) else { return name ?? "—" }
        return Format.engineBadge(displayName: e.displayName, active: e.active)
    }

    /// Fastest five measured servers, for the menu bar.
    var topServers: [Node] {
        let measured = nodes.filter { $0.latencyMs >= 0 }.sorted { $0.latencyMs < $1.latencyMs }
        return Array((measured.isEmpty ? nodes : measured).prefix(5))
    }

    // MARK: actions

    func connect(_ id: Node.ID? = nil) {
        connecting = true
        perform { [weak self] c in
            defer { Task { @MainActor in self?.connecting = false } }
            if let id { try await c.setActive(id) }
            try await c.connect()
        }
    }

    func disconnect() { perform { try await $0.disconnect() } }

    func toggleConnection() {
        if connected { disconnect() } else { connect(selectedNodeID ?? activeNodeId) }
    }

    func testLatency(_ mode: String? = nil) {
        let m = mode ?? (settings.latencyMethod == "tcp" ? "tcp" : "real")
        lastTestMode = m
        testing = true
        perform { [weak self] c in
            defer { Task { @MainActor in self?.testing = false } }
            _ = try await c.latency(mode: m)
        }
    }

    func pickFastest() {
        testing = true
        perform { [weak self] c in
            defer { Task { @MainActor in self?.testing = false } }
            _ = try await c.pickFastest(reconnect: true)
        }
    }

    func setAutoPick(_ on: Bool) {
        var s = settings
        s.autoPick = on
        save(s)
    }

    func setSystemProxy(_ on: Bool) { perform { try await $0.setSystemProxy(on) } }

    func save(_ s: AppSettings) {
        settings = s
        perform { try await $0.saveSettings(s) }
    }

    func delete(_ ids: [Node.ID]) { perform { try await $0.delete(ids) } }

    func copyLink(_ n: Node) {
        guard let link = n.rawLink, !link.isEmpty else {
            errorMessage = "This server has no share link (its protocol has no link format)."
            return
        }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(link, forType: .string)
    }

    func copyExportCommand() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(Format.exportCommand(socks: socksPort, http: httpPort), forType: .string)
    }

    /// Opens the Add Servers sheet, optionally with text to preview.
    func openImport(text: String = "") {
        importPrefill = text
        showImport = true
    }

    func addFromClipboard() {
        openImport(text: NSPasteboard.general.string(forType: .string) ?? "")
    }

    func refreshSubscription(_ id: String) { perform { try await $0.refreshSubscription(id) } }
    func refreshAllSubscriptions() { perform { try await $0.refreshAllSubscriptions() } }
    func deleteSubscription(_ id: String) { perform { try await $0.deleteSubscription(id) } }

    // MARK: engines

    func download(engine: String, version: String = "") {
        perform { [weak self] c in
            let job = try await c.startDownload(engine: engine, version: version)
            await MainActor.run { self?.upsert(job) }
        }
    }

    private func upsert(_ job: Job) {
        jobs.removeAll { $0.id == job.id }
        jobs.append(job)
    }

    func job(for engine: String) -> Job? {
        jobs.filter { $0.engine == engine }.max { (Int($0.id) ?? 0) < (Int($1.id) ?? 0) }
    }

    func checkEngine(_ name: String) { perform { try await $0.checkEngine(name) } }
    func useEngine(_ name: String, version: String) { perform { try await $0.useEngine(name, version: version) } }

    // MARK: activity log

    func pollLogs() async {
        guard let client, let body = try? await client.logs(since: logNext) else { return }
        if body.next < logNext { logs.removeAll() } // backend restarted
        logs.append(contentsOf: body.logs)
        if logs.count > 2000 { logs.removeFirst(logs.count - 2000) }
        logNext = body.next
    }

    func clearLogs() { logs.removeAll() }

    // MARK: login item

    var opensAtLogin: Bool { SMAppService.mainApp.status == .enabled }

    func setOpensAtLogin(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            errorMessage = "Open at login: \(error.localizedDescription)"
        }
    }
}

// MARK: QR codes

enum QR {
    /// Renders text as a QR code image (CoreImage, no network).
    static func image(for text: String, size: CGFloat = 280) -> NSImage? {
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(Data(text.utf8), forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let out = filter.outputImage else { return nil }
        let scale = size / out.extent.width
        let scaled = out.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let rep = NSCIImageRep(ciImage: scaled)
        let img = NSImage(size: rep.size)
        img.addRepresentation(rep)
        return img
    }

    /// Reads QR codes found in an image.
    static func decode(_ image: CGImage) -> [String] {
        let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        let features = detector?.features(in: CIImage(cgImage: image)) ?? []
        return features.compactMap { ($0 as? CIQRCodeFeature)?.messageString }
    }
}

// MARK: activation policy

/// The app lives in the menu bar; while a window is open it becomes a regular
/// app (Dock icon, Command-Tab), and goes back once the last window closes.
enum Activation {
    static func bringForward() {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    static func install() {
        NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: nil, queue: .main) { _ in
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) {
                let open = NSApp.windows.contains { $0.isVisible && $0.styleMask.contains(.titled) && !($0 is NSPanel) }
                if !open { NSApp.setActivationPolicy(.accessory) }
            }
        }
        NotificationCenter.default.addObserver(forName: NSWindow.didBecomeKeyNotification, object: nil, queue: .main) { note in
            guard let w = note.object as? NSWindow, w.styleMask.contains(.titled), !(w is NSPanel) else { return }
            if NSApp.activationPolicy() != .regular { NSApp.setActivationPolicy(.regular) }
        }
    }
}

// MARK: sample data

extension AppModel {
    /// The mockups' sample data (design/screens/*.dc.html), for snapshot rendering.
    func loadSample(connected: Bool = true) {
        func n(_ id: String, _ cc: String, _ name: String, _ proto: String, _ pname: String, _ tr: String, _ ms: Int, _ host: String,
               _ port: Int, _ sec: String, _ sni: String, sub: Bool, engine: String = "xray") -> Node {
            Node(id: id, name: name, protocol: proto, server: host, port: port, rawLink: "\(proto)://x", source: sub ? "s1" : nil,
                 latencyMs: ms, displayName: name, countryCode: cc, protocolName: pname, transport: tr, security: sec, sni: sni,
                 udp: ["hysteria2", "tuic", "wireguard"].contains(proto), engine: engine,
                 engineName: engine == "xray" ? "Xray core" : "sing-box", hasLink: true)
        }
        nodes = [
            n("fra1", "DE", "Frankfurt 01", "vless", "VLESS", "Reality", 48, "fra1.example.net", 443, "Reality · Vision", "www.example.com", sub: true),
            n("ams2", "NL", "Amsterdam 02", "vless", "VLESS", "XHTTP", 62, "ams2.example.net", 443, "TLS", "ams2.example.net", sub: true),
            n("hel1", "FI", "Helsinki", "trojan", "Trojan", "TCP", 71, "hel.example.net", 443, "TLS", "hel.example.net", sub: true),
            n("ist1", "TR", "Istanbul", "shadowsocks", "Shadowsocks", "TCP", 118, "203.0.113.24", 8388, "2022-blake3", "—", sub: true),
            n("tyo3", "JP", "Tokyo 03", "vmess", "VMess", "WebSocket", 186, "tyo3.example.net", 8443, "TLS", "cdn.example.net", sub: true),
            n("sgp1", "SG", "Singapore", "hysteria2", "Hysteria2", "QUIC", -3, "sgp.example.net", 443, "TLS", "sgp.example.net", sub: true),
            n("sgp2", "SG", "Singapore TUIC", "tuic", "TUIC", "QUIC", 54, "sgp.example.net", 8443, "TLS · BBR", "sgp.example.net", sub: true, engine: "sing-box"),
            n("home", "CA", "Home server", "vless", "VLESS", "gRPC", 24, "home.example.org", 2053, "TLS", "home.example.org", sub: false),
            n("wg1", "CA", "Home WireGuard", "wireguard", "WireGuard", "UDP", 31, "wg.example.org", 51820, "Curve25519 keys", "—", sub: false),
            n("old1", "US", "Old test node", "socks", "SOCKS", "TCP", -2, "198.51.100.7", 1080, "None", "—", sub: false),
        ]
        subscriptions = [Subscription(id: "s1", name: "My Subscription", url: "https://sub.example.net/api/v1/client/token",
                                      updatedAt: Date().addingTimeInterval(-7200), nodeCount: 7, format: "clash")]
        var s = AppSettings()
        s.inbounds = [Inbound(tag: "socks-in", protocol: "socks", port: 10808, listen: "127.0.0.1", udp: true, enabled: true),
                      Inbound(tag: "http-in", protocol: "http", port: 10809, listen: "127.0.0.1", udp: false, enabled: true)]
        s.autoPick = true
        s.autoSystemProxy = true
        settings = s
        engines = [
            EngineInfo(name: "xray", displayName: "Xray core", installed: ["v25.10.15"], active: "v25.10.15", version: "Xray 25.10.15",
                       latest: "v25.11.2", updateAvailable: true, checkedAt: Date(), checkError: nil,
                       protocols: ["VLESS", "VMess", "Trojan", "Shadowsocks", "Hysteria2", "WireGuard", "SOCKS", "HTTP"]),
            EngineInfo(name: "sing-box", displayName: "sing-box", installed: ["v1.12.0"], active: "v1.12.0", version: "sing-box version 1.12.0",
                       latest: "v1.12.0", updateAvailable: false, checkedAt: Date(), checkError: nil,
                       protocols: ["TUIC", "Hysteria", "AnyTLS", "ShadowTLS", "NaiveProxy", "SSH"]),
        ]
        activeNodeId = "fra1"
        selectedNodeID = "fra1"
        var st = Status()
        st.running = connected
        st.activeNode = "Frankfurt 01"
        st.activeNodeId = "fra1"
        st.activeCountryCode = "DE"
        st.activeLatencyMs = 48
        st.protocol = "VLESS"
        st.transport = "Reality"
        st.engine = "xray"
        st.uptimeSec = 872
        st.startedAt = connected ? Date().addingTimeInterval(-872) : nil
        st.systemProxyOn = connected
        st.systemProxyServices = connected ? ["Wi-Fi"] : []
        status = st
        ready = true
    }

    /// The onboarding mockup's state: Xray installed, sing-box downloading, no servers yet.
    func loadSampleOnboarding() {
        loadSample(connected: false)
        nodes = []
        engines[1].installed = []
        engines[1].active = ""
        jobs = [Job(id: "1", engine: "sing-box", version: nil, state: "running", done: 64, total: 100, error: nil)]
    }
}
