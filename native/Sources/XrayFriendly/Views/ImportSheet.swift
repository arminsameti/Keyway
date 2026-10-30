import AppKit
import SwiftUI
import UniformTypeIdentifiers
import XrayFriendlyCore

/// The Add Servers sheet (design/screens/Import.dc.html).
struct ImportSheet: View {
    enum Method: String, CaseIterable, Identifiable {
        case paste = "Paste Links", subscription = "Subscription URL", file = "File or QR Image"
        var id: String { rawValue }
    }

    let initialText: String
    /// Shown instead of a live preview (snapshot rendering).
    var samplePreview: ImportPreview?
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openWindow) private var openWindow

    @State private var method: Method = .paste
    @State private var text = ""
    @State private var subURL = ""
    @State private var fileText = ""
    @State private var fileName = ""
    @State private var preview = ImportPreview()
    @State private var previewError: String?
    @State private var adding = false
    @State private var picking = false

    private var currentText: String {
        switch method {
        case .paste: return text
        case .subscription: return subURL
        case .file: return fileText
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Add Servers").font(.system(size: 15, weight: .bold))
                    Text(intro).font(.system(size: 12)).foregroundStyle(Palette.secondary)
                }
                Picker("Import method", selection: $method) {
                    ForEach(Method.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden()
                input
            }
            .padding([.horizontal, .top], 22)

            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .firstTextBaseline) {
                    Text("Found").font(.system(size: 12, weight: .semibold))
                    Spacer()
                    Text(Format.previewSummary(preview)).font(.system(size: 11)).foregroundStyle(Palette.secondary)
                }
                previewList
                Text("Recognizes VLESS, VMess, Trojan, Shadowsocks, SOCKS, HTTP(S), Hysteria, Hysteria2, TUIC, WireGuard, OpenVPN, AnyTLS, ShadowTLS, NaiveProxy and SSH links, plus Clash YAML and sing-box JSON.")
                    .font(.system(size: 11)).foregroundStyle(Palette.secondary).fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 2)
            }
            .padding(.horizontal, 22).padding(.top, 14)

            HStack(spacing: 8) {
                Button("Enter Manually…") { dismiss(); openWindow(id: "server", value: EditorTarget.new) }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(Format.addButton(servers: preview.ready, subscriptions: preview.subscriptions)) { add() }
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.defaultAction)
                    .disabled(adding || preview.ready + preview.subscriptions == 0)
            }
            .padding(22)
        }
        .frame(width: 580)
        .tint(Palette.accent)
        .onAppear {
            if let samplePreview { preview = samplePreview }
            text = initialText
            if initialText.lowercased().hasPrefix("http"), !initialText.contains("\n") { method = .subscription; subURL = initialText }
        }
        .task(id: currentText + method.rawValue) {
            try? await Task.sleep(for: .milliseconds(350)) // debounce typing
            await runPreview()
        }
        .fileImporter(isPresented: $picking, allowedContentTypes: [.item]) { result in
            if case .success(let url) = result { load(url) }
        }
    }

    private var intro: String {
        switch method {
        case .paste: return "Paste share links, one per line, or a whole WireGuard .conf or OpenVPN .ovpn. An https:// link is added as a subscription that refreshes on its own."
        case .subscription: return "Your provider's subscription URL. Its server list is fetched now and refreshed on its own."
        case .file: return "An OpenVPN .ovpn, WireGuard .conf, Clash YAML, sing-box JSON or text file, or a screenshot of a QR code."
        }
    }

    @ViewBuilder private var input: some View {
        switch method {
        case .paste:
            VStack(alignment: .leading, spacing: 6) {
                Text("Links").font(.system(size: 12, weight: .semibold))
                TextEditor(text: $text)
                    .font(.system(size: 11, design: .monospaced))
                    .frame(height: 120)
                    .padding(4)
                    .overlay(RoundedRectangle(cornerRadius: 7).stroke(Palette.cardBorder))
                    .accessibilityLabel("Share links")
            }
        case .subscription:
            VStack(alignment: .leading, spacing: 6) {
                Text("URL").font(.system(size: 12, weight: .semibold))
                TextField("https://", text: $subURL)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12, design: .monospaced))
                    .accessibilityLabel("Subscription URL")
            }
        case .file:
            HStack(spacing: 10) {
                Button("Choose File…") { picking = true }
                Button("Scan QR Code on Screen") { Task { await scanScreen() } }
                Text(fileName.isEmpty ? "No file chosen" : fileName).font(.system(size: 12)).foregroundStyle(Palette.secondary).lineLimit(1)
            }
            .frame(height: 40)
        }
    }

    private var previewList: some View {
        ScrollView {
            VStack(spacing: 0) {
                if let previewError {
                    row(icon: "exclamationmark.triangle", color: Palette.error, name: previewError, detail: "", label: "Error")
                } else if preview.items.isEmpty {
                    Text("Nothing found yet").font(.system(size: 12)).foregroundStyle(Palette.secondary).frame(maxWidth: .infinity, minHeight: 32)
                }
                ForEach(Array(preview.items.enumerated()), id: \.offset) { i, item in
                    if i > 0 || previewError != nil { Divider() }
                    switch item.status {
                    case "ready":
                        row(icon: "checkmark", color: Palette.greenText, name: item.name, detail: readyDetail(item), label: "Ready")
                    case "subscription":
                        row(icon: "dot.radiowaves.up.forward", color: Palette.accentText, name: item.name,
                            detail: "Subscription · base64, Clash or sing-box", label: "Subscription")
                    default:
                        row(icon: "exclamationmark.triangle", color: Palette.warn, name: item.name, detail: item.reason ?? "Skipped",
                            label: "Skipped", dimName: true, detailColor: Palette.warn)
                    }
                }
            }
            .padding(4)
        }
        .frame(maxHeight: 200)
        .fixedSize(horizontal: false, vertical: true)
        .overlay(RoundedRectangle(cornerRadius: 9).stroke(Palette.separator))
    }

    private func readyDetail(_ i: PreviewItem) -> String {
        var parts = [i.protocol, i.transport].compactMap { $0 }
        if i.engine == "sing-box" { parts.append("uses sing-box") }
        if i.duplicate { parts.append("already added") }
        return parts.joined(separator: " · ")
    }

    private func row(icon: String, color: Color, name: String, detail: String, label: String,
                     dimName: Bool = false, detailColor: Color = Palette.tertiary) -> some View {
        HStack(spacing: 10) {
            Image(systemName: icon).font(.system(size: 12, weight: .semibold)).foregroundStyle(color).frame(width: 14)
                .accessibilityLabel(label)
            Text(name).foregroundStyle(dimName ? Palette.tertiary : Color.primary).lineLimit(1)
            Spacer()
            Text(detail).font(.system(size: 12)).foregroundStyle(detailColor).lineLimit(1)
        }
        .padding(.horizontal, 8).frame(minHeight: 32)
    }

    // MARK: actions

    private func runPreview() async {
        guard let client = model.client else { return }
        let t = currentText
        guard !t.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { preview = ImportPreview(); previewError = nil; return }
        do {
            preview = try await client.preview(t)
            previewError = nil
        } catch {
            previewError = error.localizedDescription
        }
    }

    private func add() {
        guard let client = model.client else { return }
        adding = true
        let t = currentText
        Task {
            defer { adding = false }
            do {
                let res = try await client.importText(t)
                await model.refreshState()
                if res.added == 0, let first = res.errors.first { model.errorMessage = first } else { dismiss() }
            } catch {
                model.errorMessage = error.localizedDescription
            }
        }
    }

    private func load(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        fileName = url.lastPathComponent
        if let type = UTType(filenameExtension: url.pathExtension), type.conforms(to: .image) {
            guard let img = NSImage(contentsOf: url), let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) else {
                previewError = "The image could not be read."
                return
            }
            let codes = QR.decode(cg)
            if codes.isEmpty { previewError = "No QR code found in \(fileName)." } else { fileText = codes.joined(separator: "\n") }
            return
        }
        guard let data = try? Data(contentsOf: url), data.count <= 1 << 20, let s = String(data: data, encoding: .utf8) else {
            previewError = "\(fileName) is not a text file under 1 MB."
            return
        }
        fileText = s
    }

    private func scanScreen() async {
        fileName = "Screen"
        do {
            let codes = try await ScreenQR.scan()
            if codes.isEmpty { previewError = "No QR code is visible on screen." } else { fileText = codes.joined(separator: "\n"); previewError = nil }
        } catch {
            previewError = error.localizedDescription
        }
    }
}
