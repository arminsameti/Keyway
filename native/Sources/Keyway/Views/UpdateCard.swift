import SwiftUI
import KeywayCore

/// Settings › General › Updates: tells the user about a newer Keyway release and
/// downloads its disk image (checked against the release's SHA-256 sums). It
/// never installs: the user opens the image themselves.
struct UpdateCard: View {
    @Environment(AppModel.self) private var model

    private var update: AppUpdate { model.appUpdate }

    var body: some View {
        CardSection(title: "Updates",
                    footnote: "Keyway asks GitHub for the newest release number once a day. Nothing that identifies you or your Mac is sent. The download goes to your Downloads folder and is checked against the release's SHA-256 checksums; Keyway never replaces itself.") {
            CardRow(label: status, first: true) {
                Button("Check Now") { model.checkForUpdate() }
            }
            if update.available { availableRow }
            CardRow(label: "Check for updates daily") {
                Toggle("Check for updates daily", isOn: Binding(
                    get: { model.settings.appUpdateCheck != "never" },
                    set: { on in
                        var s = model.settings
                        s.appUpdateCheck = on ? "daily" : "never"
                        model.save(s)
                    })).labelsHidden().toggleStyle(.checkbox)
            }
        }
    }

    private var status: String {
        let me = update.current.isEmpty ? "Keyway" : "Keyway \(update.current.trimmingCharacters(in: CharacterSet(charactersIn: "v")))"
        if update.available { return me }
        if let e = update.error, !e.isEmpty { return "\(me): could not check for updates" }
        return update.checkedAt == nil || update.latest == nil ? me : "\(me) is up to date"
    }

    @ViewBuilder
    private var availableRow: some View {
        CardRow(label: "Keyway \(update.latest ?? "") is available") {
            if let u = update.notesUrl.flatMap(URL.init(string:)) {
                Link("Release Notes", destination: u).font(.system(size: 12))
            }
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
        if let d = update.download, d.state == "failed", let e = d.error {
            Text(e).font(.system(size: 11)).foregroundStyle(Palette.error)
                .padding(.horizontal, 14).padding(.bottom, 8).frame(maxWidth: .infinity, alignment: .leading)
        } else if let d = update.download, d.state == "done" {
            Text("Downloaded and verified. Open the disk image and drag Keyway to Applications to update.")
                .font(.system(size: 11)).foregroundStyle(Palette.secondary)
                .padding(.horizontal, 14).padding(.bottom, 8).frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
