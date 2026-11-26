import SwiftUI
import KeywayCore

/// Domains no filter list may block. One per line; a name also covers its subdomains.
struct AllowedSitesSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var saveError: String?

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
            if let saveError {
                Text(saveError).font(.system(size: 11)).foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("Revert") { text = model.settings.allowedSites }.disabled(!dirty)
                Button("Save") { Task { _ = await save() } }
                    .disabled(!dirty || model.filterSaving)
                // Done keeps unsaved edits: it saves first and stays open if that fails.
                Button("Done") {
                    Task {
                        if !dirty { dismiss(); return }
                        if await save() { dismiss() }
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(model.filterSaving)
            }
        }
        .padding(16)
        .frame(width: 480, height: 400)
        .onAppear { text = model.settings.allowedSites }
        .task { await model.refreshFilterView() }
        // the backend tidies the list (lowercase, one per line); show what it kept
        .onChange(of: model.filterSaving) { _, saving in if !saving { text = model.settings.allowedSites } }
    }

    /// Saves the text as the allowlist; false (with the error shown) when the backend refused it.
    private func save() async -> Bool {
        var s = model.settings
        s.allowedSites = text
        saveError = await model.saveFiltersNow(s)
        return saveError == nil
    }
}
