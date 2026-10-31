import SwiftUI
import UniformTypeIdentifiers
import XrayFriendlyCore

/// First run (design/screens/Onboarding.dc.html): get an engine, add servers, connect.
struct OnboardingView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openWindow) private var openWindow
    @State private var openAtLogin = true
    @State private var picking = false
    @State private var connecting = false
    @State private var started = false

    private var xray: EngineInfo? { model.engines.first { $0.name == "xray" } }
    private var singBox: EngineInfo? { model.engines.first { $0.name == "sing-box" } }
    private var engineReady: Bool { model.engines.contains { !$0.installed.isEmpty } }
    private var hasServers: Bool { !model.nodes.isEmpty }

    var body: some View {
        VStack(spacing: 0) {
            RoundedRectangle(cornerRadius: 17).fill(Palette.accent).frame(width: 72, height: 72)
                .overlay(BrandMark(fallback: "checkmark.shield", size: 46))
                .shadow(color: .black.opacity(0.16), radius: 9, y: 6)
                .accessibilityHidden(true)
            Text("Welcome to Xray Friendly").font(.system(size: 24, weight: .bold)).padding(.top, 18).padding(.bottom, 6)
            Text("Three quick steps and you’re online. You can change anything later in Settings.")
                .font(.system(size: 13)).foregroundStyle(Palette.secondary).multilineTextAlignment(.center).frame(maxWidth: 440)
                .padding(.bottom, 26)

            VStack(spacing: 10) {
                step(1, done: engineReady, current: !engineReady) { engineStep }
                step(2, done: hasServers, current: engineReady && !hasServers) { serversStep }
                step(3, done: model.connected, current: engineReady && hasServers && !model.connected) { connectStep }
            }

            Spacer(minLength: 16)
            HStack {
                Toggle("Open at login and keep in the menu bar", isOn: $openAtLogin).toggleStyle(.checkbox).font(.system(size: 12))
                Spacer()
                Button("Skip for Now") { finish() }.buttonStyle(.link)
            }
        }
        .padding(.top, 44).padding(.horizontal, 72).padding(.bottom, 28)
        .frame(width: 720, height: 640)
        .tint(Palette.accent)
        .fileImporter(isPresented: $picking, allowedContentTypes: [.item]) { result in
            if case .success(let url) = result, let text = readText(url) { openImport(text) }
        }
        .task(id: model.ready) { startDownloads() }
    }

    // MARK: steps

    private func step<Content: View>(_ n: Int, done: Bool, current: Bool, @ViewBuilder content: () -> Content) -> some View {
        HStack(alignment: .top, spacing: 14) {
            ZStack {
                Circle().fill(done ? Palette.green : current ? Palette.accent : Palette.separator).frame(width: 24, height: 24)
                if done {
                    Image(systemName: "checkmark").font(.system(size: 11, weight: .bold)).foregroundStyle(.white)
                } else {
                    Text(verbatim: "\(n)").font(.system(size: 12, weight: .bold)).foregroundStyle(current ? Color.white : Palette.tertiary)
                }
            }
            .accessibilityLabel(done ? "Step \(n) done" : "Step \(n)")
            VStack(alignment: .leading, spacing: 6) { content() }
            Spacer(minLength: 0)
        }
        .padding(.vertical, 14).padding(.horizontal, 16)
        .background(RoundedRectangle(cornerRadius: 12).fill(done ? Palette.idleCard : Palette.card))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(current ? Palette.accent : Palette.separator, lineWidth: current ? 2 : 1))
    }

    @ViewBuilder private var engineStep: some View {
        Text("Get the proxy engine").fontWeight(.bold)
        if let x = xray, !x.installed.isEmpty {
            Text("Xray core \(x.active.dropFirst()) installed and verified.").font(.system(size: 12)).foregroundStyle(Palette.tertiary)
        } else {
            progressRow(engine: "xray", label: "Xray core")
        }
        if let sb = singBox, sb.installed.isEmpty, model.job(for: "sing-box") != nil {
            progressRow(engine: "sing-box", label: "sing-box for TUIC, Naive & more")
        }
    }

    private func progressRow(engine: String, label: String) -> some View {
        let job = model.job(for: engine)
        let pct = Int((job?.fraction ?? 0) * 100)
        return HStack(spacing: 10) {
            if job?.state == "failed" {
                Text(job?.error ?? "Download failed").font(.system(size: 11)).foregroundStyle(Palette.error).lineLimit(2)
                Button("Retry") { model.download(engine: engine) }.controlSize(.small)
            } else {
                ProgressView(value: job?.fraction ?? 0).accessibilityLabel("\(label) download")
                Text(job == nil ? "\(label) · waiting" : "\(label) · \(pct)%")
                    .font(.system(size: 11)).foregroundStyle(Palette.tertiary).fixedSize()
            }
        }
    }

    @ViewBuilder private var serversStep: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text("Add your servers").fontWeight(.bold)
            Text(hasServers ? Format.plural(model.nodes.count, "server") + " added."
                            : "Your provider gives you a link, a subscription URL, a QR code or a config file.")
                .font(.system(size: 12)).foregroundStyle(Palette.tertiary).fixedSize(horizontal: false, vertical: true)
        }
        if !hasServers {
            HStack(spacing: 8) {
                Button("Paste from Clipboard") { openImport(NSPasteboard.general.string(forType: .string) ?? "") }
                    .buttonStyle(.borderedProminent)
                Button("Scan QR Code on Screen") {
                    Task {
                        do {
                            let codes = try await ScreenQR.scan()
                            if codes.isEmpty { model.errorMessage = "No QR code is visible on screen." } else { openImport(codes.joined(separator: "\n")) }
                        } catch { model.errorMessage = error.localizedDescription }
                    }
                }
                Button("Open File…") { picking = true }
            }
            .padding(.top, 4)
        }
    }

    @ViewBuilder private var connectStep: some View {
        Text("Connect").fontWeight(.bold).foregroundStyle(engineReady && hasServers ? Color.primary : Palette.tertiary)
        Text("We’ll pick the fastest server and set the macOS system proxy, so Safari and most apps work without setup.")
            .font(.system(size: 12)).foregroundStyle(Palette.secondary).fixedSize(horizontal: false, vertical: true)
        if engineReady && hasServers && !model.connected {
            Button(connecting ? "Connecting…" : "Connect") { connect() }
                .buttonStyle(.borderedProminent).disabled(connecting).padding(.top, 4)
        }
    }

    // MARK: actions

    /// Step 1 runs on its own: Xray first, sing-box next to it (as in the design).
    private func startDownloads() {
        guard model.ready, !started else { return }
        started = true
        if xray?.installed.isEmpty ?? false { model.download(engine: "xray") }
        if model.settings.autoDownloadEngines, singBox?.installed.isEmpty ?? false { model.download(engine: "sing-box") }
    }

    private func openImport(_ text: String) {
        openWindow(id: "main")
        model.openImport(text: text)
    }

    private func connect() {
        guard let client = model.client else { return }
        connecting = true
        Task {
            defer { connecting = false }
            do {
                _ = try await client.pickFastest(reconnect: false)
                try await client.connect()
                try await client.setSystemProxy(true)
                await model.refreshState()
                await model.refreshStatus()
                finish()
            } catch {
                model.errorMessage = error.localizedDescription
            }
        }
    }

    private func finish() {
        if openAtLogin && !model.opensAtLogin { model.setOpensAtLogin(true) }
        UserDefaults.standard.set(true, forKey: "onboardingDone")
        openWindow(id: "main")
        dismiss()
    }

    private func readText(_ url: URL) -> String? {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        if let type = UTType(filenameExtension: url.pathExtension), type.conforms(to: .image),
           let img = NSImage(contentsOf: url), let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) {
            return QR.decode(cg).joined(separator: "\n")
        }
        guard let data = try? Data(contentsOf: url), data.count <= 1 << 20 else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
