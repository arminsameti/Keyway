import SwiftUI
import KeywayCore

/// Domains no filter list may block. One per line; a name also covers its subdomains.
struct AllowedSitesSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""

    private var dirty: Bool { text != model.settings.allowedSites }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Allowed sites").font(.system(size: 15, weight: .bold)).accessibilityAddTraits(.isHeader)
            Text("Filter lists never block these sites or their subdomains. One domain per line.")
                .font(.system(size: 12)).foregroundStyle(Palette.secondary)
            TextEditor(text: $text)
                .font(.system(size: 12, design: .monospaced))
                .frame(minHeight: 140)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Palette.cardBorder))
                .accessibilityLabel("Allowed sites")
            if !model.filterView.widened.isEmpty {
                VStack(alignment: .leading, spacing: 3) {
                    ForEach(model.filterView.widened, id: \.self) { w in
                        Label("Allowing \(w.allowed) also unblocks \(w.unblocked)", systemImage: "info.circle")
                            .font(.system(size: 11)).foregroundStyle(Palette.secondary)
                    }
                }
            }
            HStack {
                Spacer()
                Button("Revert") { text = model.settings.allowedSites }.disabled(!dirty)
                Button("Save") {
                    var s = model.settings
                    s.allowedSites = text
                    model.saveFilters(s)
                }
                .disabled(!dirty || model.filterSaving)
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
        .frame(width: 480, height: 400)
        .onAppear { text = model.settings.allowedSites }
        .task { await model.refreshFilterView() }
        // the backend tidies the list (lowercase, one per line); show what it kept
        .onChange(of: model.filterSaving) { _, saving in if !saving { text = model.settings.allowedSites } }
    }
}
