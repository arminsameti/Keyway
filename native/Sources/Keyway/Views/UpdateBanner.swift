import SwiftUI
import KeywayCore

/// Download, progress, or Show in Finder for the newest release: shared by the
/// main-window banner and Settings › General › Updates.
struct UpdateActions: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let update = model.appUpdate
        if let d = update.download, d.state == "running" {
            if let f = d.fraction {
                ProgressView(value: f).frame(width: 90)
            } else {
                ProgressView().controlSize(.small)
            }
        } else if let d = update.download, d.state == "done", let path = d.path {
            Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)]) }
        } else {
            Button("Download") { model.downloadUpdate() }
        }
    }
}

/// A slim bar across the top of the main window while a newer Keyway is out.
/// "Later" hides it until the next release.
struct UpdateBanner: View {
    @Environment(AppModel.self) private var model
    @AppStorage("dismissedUpdateVersion") private var dismissed = ""

    var body: some View {
        let update = model.appUpdate
        if UpdateNotice.showsBanner(update, dismissed: dismissed), let v = UpdateNotice.announced(update) {
            HStack(spacing: 10) {
                Image(systemName: "arrow.down.circle.fill").foregroundStyle(Palette.accent)
                    .accessibilityHidden(true)
                Text(message(v)).font(.system(size: 12, weight: .medium))
                    .lineLimit(1).truncationMode(.tail)
                Spacer(minLength: 8)
                if let u = update.notesUrl.flatMap(URL.init(string:)) {
                    Link("Release Notes", destination: u).font(.system(size: 12))
                }
                UpdateActions().controlSize(.small)
                Button("Later") { dismissed = v }
                    .buttonStyle(.borderless).font(.system(size: 12))
                    .help("Hide until the next release")
            }
            .padding(.horizontal, 14).padding(.vertical, 8)
            .background(RoundedRectangle(cornerRadius: 10).fill(Palette.card))
            .overlay(RoundedRectangle(cornerRadius: 10).stroke(Palette.cardBorder))
            .padding(.horizontal, 20).padding(.top, 10)
            .accessibilityElement(children: .contain)
        }
    }

    private func message(_ v: String) -> String {
        let version = v.hasPrefix("v") ? String(v.dropFirst()) : v
        if let d = model.appUpdate.download {
            switch d.state {
            case "done": return "Keyway \(version) is downloaded. Open the disk image and drag Keyway to Applications."
            case "failed": return "Keyway \(version) could not be downloaded: \(d.error ?? "unknown error")"
            default: return "Downloading Keyway \(version)…"
            }
        }
        return "Keyway \(version) is available"
    }
}
