import AppKit
import SwiftUI
import KeywayCore

/// Renders every screen offscreen to PNG ("Keyway --snapshot <dir>").
/// Uses AppKit's own drawing, so it needs no Screen Recording permission.
@MainActor
enum Snapshots {
    static func renderAll(to dir: String) {
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let sampleImport: ImportPreview = {
            var p = ImportPreview()
            func item(_ line: Int, _ status: String, _ name: String, _ proto: String?, _ tr: String?, engine: String? = "xray", reason: String? = nil) -> PreviewItem {
                PreviewItem(line: line, status: status, scheme: nil, name: name, countryCode: nil, protocol: proto, transport: tr,
                            engine: engine, engineName: nil, engineInstalled: true, duplicate: false, reason: reason)
            }
            p.items = [item(1, "ready", "Frankfurt 01", "VLESS", "Reality"), item(2, "ready", "Helsinki", "Trojan", "TCP"),
                       item(3, "ready", "Singapore", "TUIC v5", "QUIC", engine: "sing-box"), item(4, "ready", "Home WG", "WireGuard", "UDP"),
                       item(5, "subscription", "sub.example.net", nil, nil, engine: nil),
                       item(6, "skipped", "Line 6 · ssr://", nil, nil, engine: nil, reason: "ShadowsocksR is retired — skipped")]
            p.ready = 4; p.subscriptions = 1; p.skipped = 1
            return p
        }()
        let links = """
        vless://5c1e…@fra1.example.net:443?security=reality&sni=www.example.com#Frankfurt%2001
        trojan://••••••@hel.example.net:443?sni=hel.example.net#Helsinki
        tuic://••••••@sgp.example.net:443?congestion_control=bbr#Singapore
        wireguard://••••••@wg.example.org:51820?address=10.7.0.2/32#Home%20WG
        https://sub.example.net/api/v1/client/[YOUR TOKEN]
        ssr://bG9uZy1sZWdhY3ktbGluay4uLg
        """
        for (suffix, appearance) in [("light", NSAppearance.Name.aqua), ("dark", .darkAqua)] {
            let connected = AppModel(); connected.loadSample(connected: true)
            let idle = AppModel(); idle.loadSample(connected: false)
            let onboarding = AppModel(); onboarding.loadSampleOnboarding()
            render(MainView().environment(connected), "main-connected-\(suffix)", CGSize(width: 1240, height: 780), appearance, dir)
            render(MainView().environment(idle), "main-idle-\(suffix)", CGSize(width: 1240, height: 780), appearance, dir)
            let subs = AppModel(); subs.loadSample(connected: true); subs.sidebar = .subscriptions
            render(MainView().environment(subs), "main-subscriptions-\(suffix)", CGSize(width: 1240, height: 780), appearance, dir)
            let grp = AppModel(); grp.loadSample(connected: true); grp.sidebar = .groups
            render(MainView().environment(grp), "main-groups-\(suffix)", CGSize(width: 1240, height: 780), appearance, dir)
            render(GroupEditor(target: .edit(grp.groups[2])).environment(grp), "group-editor-\(suffix)", CGSize(width: 520, height: 560), appearance, dir)
            render(MenuBarView().environment(connected), "menubar-\(suffix)", CGSize(width: 352, height: 600), appearance, dir)
            render(ImportSheet(initialText: links, samplePreview: sampleImport).environment(connected), "import-\(suffix)",
                   CGSize(width: 580, height: 660), appearance, dir)
            render(NewServerView(target: .new, initialProtocol: "tuic").environment(connected), "newserver-\(suffix)",
                   CGSize(width: 760, height: 720), appearance, dir)
            render(NewServerView(target: .new, initialProtocol: "openvpn").environment(connected), "newserver-openvpn-\(suffix)",
                   CGSize(width: 760, height: 720), appearance, dir)
            let chainModel = AppModel(); chainModel.loadSample(connected: true); chainModel.selectChain()
            render(MainView().environment(chainModel), "main-chain-\(suffix)", CGSize(width: 1240, height: 780), appearance, dir)
            let sample = (chain: ChainForm(name: "", hops: ["ovpn1", "fra1", "wg1"]),
                          plan: ChainPlan(engine: "sing-box", engineName: "sing-box", processes: 1, installed: true))
            render(NewServerView(target: .newChain, sampleChain: sample).environment(connected), "newserver-chain-\(suffix)",
                   CGSize(width: 760, height: 720), appearance, dir)
            render(SettingsView(tab: "engines").environment(connected), "settings-engines-\(suffix)", CGSize(width: 760, height: 640), appearance, dir)
            render(SettingsView(tab: "general").environment(connected), "settings-general-\(suffix)", CGSize(width: 760, height: 640), appearance, dir)
            let dnsModel = AppModel(); dnsModel.loadSample(connected: true)
            var dnsSettings = dnsModel.settings
            dnsSettings.dnsMode = "custom"; dnsSettings.dnsDirect = "223.5.5.5"
            dnsSettings.dns = ["https://1.1.1.1/dns-query", "tls://9.9.9.9"]
            dnsModel.save(dnsSettings) // no backend in a snapshot: this only sets the sample
            render(SettingsView(tab: "dns").environment(dnsModel), "settings-dns-\(suffix)", CGSize(width: 760, height: 640), appearance, dir)
            render(OnboardingView().environment(onboarding), "onboarding-\(suffix)", CGSize(width: 720, height: 640), appearance, dir)
        }
    }

    private static func render<V: View>(_ view: V, _ name: String, _ size: CGSize, _ appearance: NSAppearance.Name, _ dir: String) {
        let window = NSWindow(contentRect: CGRect(origin: CGPoint(x: -10000, y: -10000), size: size),
                              styleMask: [.titled, .fullSizeContentView], backing: .buffered, defer: false)
        window.appearance = NSAppearance(named: appearance)
        // cacheDisplay draws the view, not the window, so paint the window background here.
        let host = NSHostingView(rootView: view.frame(width: size.width, height: size.height)
            .background(Color(nsColor: .windowBackgroundColor)))
        host.frame = CGRect(origin: .zero, size: size)
        window.contentView = host
        window.orderFrontRegardless()
        for _ in 0..<6 { RunLoop.main.run(until: Date().addingTimeInterval(0.15)); host.layoutSubtreeIfNeeded() }
        guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return }
        host.cacheDisplay(in: host.bounds, to: rep)
        if let png = rep.representation(using: .png, properties: [:]) {
            try? png.write(to: URL(fileURLWithPath: dir).appendingPathComponent(name + ".png"))
        }
        window.orderOut(nil)
    }
}
