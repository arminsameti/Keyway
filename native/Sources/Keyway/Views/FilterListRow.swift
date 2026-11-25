import SwiftUI
import KeywayCore

/// One row of the filter-list picker: checkbox, name, description and download state.
struct FilterListRow: View {
    let name: String
    var detail = ""
    var problematic = false
    var languages: [String] = []
    var homepage = ""
    let chosen: Bool
    /// The download state of this list, once the backend knows the list.
    var view: FilterListView?
    var disabled = false
    let onToggle: (Bool) -> Void
    var onRemove: (() -> Void)?

    private var downloading: Bool { chosen && !(view?.hasStatus ?? false) }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Toggle(name, isOn: Binding(get: { chosen }, set: onToggle))
                .labelsHidden().toggleStyle(.checkbox).disabled(disabled).padding(.top, 2)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 8) {
                    Text(name).font(.system(size: 13, weight: .medium))
                    if problematic {
                        Label("May break some sites", systemImage: "exclamationmark.triangle.fill")
                            .font(.system(size: 11)).foregroundStyle(.orange)
                    }
                    if !languages.isEmpty {
                        Text(languages.joined(separator: ", ")).font(.system(size: 11)).foregroundStyle(Palette.secondary)
                    }
                }
                if !detail.isEmpty {
                    Text(detail).font(.system(size: 12)).foregroundStyle(Palette.secondary)
                        .lineLimit(2).fixedSize(horizontal: false, vertical: true)
                }
                if downloading {
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Downloading…").font(.system(size: 11)).foregroundStyle(Palette.secondary)
                    }
                } else if chosen, let view, let line = FilterSelection.statusLine(view) {
                    Text(line).font(.system(size: 11))
                        .foregroundStyle((view.status.lastError ?? "").isEmpty ? Palette.secondary : Color.red)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            if let url = URL(string: homepage), url.scheme == "https" {
                Link("Homepage", destination: url).font(.system(size: 11))
            }
            if let onRemove {
                Button(role: .destructive, action: onRemove) { Image(systemName: "trash") }
                    .buttonStyle(.borderless).help("Remove this list").disabled(disabled)
            }
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
        .accessibilityElement(children: .contain)
    }
}
