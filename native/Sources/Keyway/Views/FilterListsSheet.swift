import SwiftUI
import KeywayCore

/// The picker for ad-block filter lists, modeled on AdGuard Home's: choose lists from
/// AdGuard's catalog or add a URL. A tick saves at once; the row shows a spinner until
/// the backend has downloaded the list.
struct FilterListsSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var search = ""
    @State private var tab = customTab // a catalog group id, or customTab (also the choice before the catalog loads)
    @State private var pickedTab = false // the user chose a tab, so a finished load must not move them
    @State private var customURL = ""
    @State private var previewing = false
    @State private var previewNote = ""
    @State private var previewFailed = false
    @State private var testHost = ""
    @State private var testResult = ""
    @State private var updating = false

    private static let customTab = -1

    private var chosen: [FilterList] { model.settings.filterLists }
    private var enabledCount: Int { chosen.filter(\.enabled).count }
    private var groups: [CatalogGroup] { model.catalog?.groups ?? [] }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            content
            Divider()
            footer
        }
        .frame(width: 680, height: 640)
        .task {
            selectFirstGroup()
            await model.refreshFilterView()
            model.startFilterPolling()
            await model.loadCatalog()
            selectFirstGroup()
        }
        .onDisappear { model.stopFilterPolling() }
    }

    /// Moves from the not-yet-loaded state to the first group, unless the user already picked a tab.
    private func selectFirstGroup() {
        if !pickedTab, let first = groups.first { tab = first.id }
    }

    private func retryCatalog() {
        Task { await model.loadCatalog(); selectFirstGroup() }
    }

    // MARK: header

    private var header: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Filter lists").font(.system(size: 15, weight: .bold)).accessibilityAddTraits(.isHeader)
            TextField("Search lists", text: $search).textFieldStyle(.roundedBorder)
            Picker("Group", selection: Binding(get: { tab }, set: { tab = $0; pickedTab = true })) {
                ForEach(groups) { Text($0.name).tag($0.id) }
                Text("Custom").tag(Self.customTab)
            }
            .pickerStyle(.segmented).labelsHidden()
            .disabled(!search.isEmpty)
        }
        .padding(16)
    }

    // MARK: lists

    @ViewBuilder private var content: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                if let err = model.catalogError, model.catalog == nil {
                    catalogFailure(err)
                    Divider()
                }
                if tab == Self.customTab && search.isEmpty {
                    customTab
                } else {
                    ForEach(catalogRows) { item in
                        row(for: item)
                        Divider().padding(.leading, 14)
                    }
                    if catalogRows.isEmpty { emptyNote }
                }
            }
        }
        .frame(maxHeight: .infinity)
    }

    /// The catalog lists for the search or the group tab. Deprecated lists show only when already chosen.
    private var catalogRows: [CatalogList] {
        guard let cat = model.catalog else { return [] }
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        return cat.lists.filter { item in
            if item.deprecated && !FilterSelection.isChosen(item.key, in: chosen) { return false }
            if !q.isEmpty { return item.name.lowercased().contains(q) || item.description.lowercased().contains(q) }
            return item.group == tab
        }
    }

    private func row(for item: CatalogList) -> some View {
        FilterListRow(
            name: item.name, detail: item.description, problematic: item.problematic,
            languages: item.languages, homepage: item.homepage,
            chosen: FilterSelection.isChosen(item.key, in: chosen),
            view: model.filterView.lists.first { $0.list.catalogKey == item.key },
            disabled: model.filterSaving,
            onToggle: { on in toggle(item, on) })
    }

    @ViewBuilder private var emptyNote: some View {
        if model.catalogLoading {
            HStack { ProgressView().controlSize(.small); Text("Loading AdGuard's list catalog…") }.padding(20)
        } else {
            Text(search.isEmpty ? "No lists in this group." : "No list matches your search.")
                .foregroundStyle(Palette.secondary).padding(20)
        }
    }

    private func catalogFailure(_ err: String) -> some View {
        VStack(spacing: 10) {
            Text("Couldn't load AdGuard's list catalog").font(.system(size: 13, weight: .semibold))
            Text(err).font(.system(size: 11)).foregroundStyle(Palette.secondary).multilineTextAlignment(.center)
            Button("Retry", action: retryCatalog).disabled(model.catalogLoading)
            Text("You can still add a list by URL in the Custom tab.").font(.system(size: 11)).foregroundStyle(Palette.secondary)
        }
        .frame(maxWidth: .infinity).padding(30)
    }

    // MARK: custom tab

    private var customTab: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                TextField("https://…", text: $customURL).textFieldStyle(.roundedBorder)
                    .onSubmit(preview)
                    .onChange(of: customURL) { _, _ in previewNote = "" }
                Button("Preview", action: preview).disabled(customURL.trimmingCharacters(in: .whitespaces).isEmpty || previewing)
                Button("Add", action: addCustom).disabled(customURL.trimmingCharacters(in: .whitespaces).isEmpty || model.filterSaving)
            }
            if previewing { ProgressView().controlSize(.small) }
            if !previewNote.isEmpty {
                Text(previewNote).font(.system(size: 12)).foregroundStyle(previewFailed ? Color.red : Palette.secondary)
                    .textSelection(.enabled)
            }
            Text("Use the https:// address of a hosts file or an AdGuard or Adblock domain list.")
                .font(.system(size: 11)).foregroundStyle(Palette.secondary)
            let custom = FilterSelection.custom(chosen)
            if !custom.isEmpty {
                Divider()
                ForEach(custom) { l in
                    FilterListRow(
                        name: l.name, detail: l.url ?? "", chosen: l.enabled,
                        view: model.filterView.lists.first { $0.id == l.id },
                        disabled: model.filterSaving,
                        onToggle: { on in
                            var s = model.settings
                            s.filterLists = FilterSelection.setting(id: l.id, enabled: on, in: s.filterLists)
                            model.saveFilters(s)
                        },
                        onRemove: {
                            var s = model.settings
                            s.filterLists = FilterSelection.removing(id: l.id, from: s.filterLists)
                            model.saveFilters(s)
                        })
                }
            }
        }
        .padding(14)
    }

    private func preview() {
        let url = customURL.trimmingCharacters(in: .whitespaces)
        guard !url.isEmpty else { return }
        previewing = true
        previewNote = ""
        Task {
            defer { previewing = false }
            switch await model.previewFilter(url: url) {
            case .success(let p):
                previewFailed = false
                previewNote = "Found \(FilterSelection.domains(p.domains)), skipped \(Format.plural(p.skipped, "line"))"
                    + (p.sample.isEmpty ? "" : ". For example: " + p.sample.prefix(3).joined(separator: ", "))
            case .failure(let e):
                previewFailed = true
                previewNote = e.localizedDescription
            }
        }
    }

    private func addCustom() {
        var s = model.settings
        s.filterLists = FilterSelection.adding(url: customURL, to: s.filterLists)
        model.saveFilters(s)
        customURL = ""
        previewNote = ""
    }

    private func toggle(_ item: CatalogList, _ on: Bool) {
        var s = model.settings
        s.filterLists = FilterSelection.setting(item, on: on, in: s.filterLists)
        model.saveFilters(s)
    }

    // MARK: footer

    private var footer: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                TextField("Test a site, e.g. doubleclick.net", text: $testHost).textFieldStyle(.roundedBorder)
                    .onSubmit(runTest)
                Button("Test", action: runTest).disabled(testHost.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            if !testResult.isEmpty {
                Text(testResult).font(.system(size: 12)).textSelection(.enabled)
            }
            if !model.settings.blockAds && enabledCount > 0 {
                note("Block ads and trackers is off, so these lists are not applied.", .orange)
            }
            if model.filterView.warn {
                note("This many domains can slow down connecting and use more memory, most of all on Xray and V2Ray.", .orange)
            }
            if model.filterView.applyOnConnect {
                note("Updated, applies on next connect", Palette.secondary)
            }
            if let e = model.filterView.mergeError, !e.isEmpty { note(e, .red) }
            if let e = model.filterView.placeError, !e.isEmpty { note(e, .red) }
            HStack {
                Text("Selected: \(Format.plural(enabledCount, "list")) · \(FilterSelection.domains(model.filterView.domains))")
                    .font(.system(size: 12, weight: .medium))
                Spacer()
                if updating { ProgressView().controlSize(.small) }
                Button("Update now") {
                    updating = true
                    Task { await model.updateFilterListsNow(); updating = false }
                }
                .disabled(enabledCount == 0 || updating)
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
    }

    private func note(_ text: String, _ color: Color) -> some View {
        Text(text).font(.system(size: 11)).foregroundStyle(color).fixedSize(horizontal: false, vertical: true)
    }

    private func runTest() {
        let host = testHost.trimmingCharacters(in: .whitespaces)
        guard !host.isEmpty else { return }
        let dest = RuleEditing.destination(host)
        Task {
            guard let m = await model.testRoute(host: dest.host, port: dest.port, rules: nil) else { return }
            if let name = m.filterList {
                testResult = "\(dest.host) is blocked by \(name)"
            } else if m.allowedBy == true {
                testResult = "\(dest.host) is allowed by your allowed sites"
            } else if m.outbound == "block" {
                testResult = "\(dest.host) is blocked" + (m.entry.map { " (\($0))" } ?? "")
            } else {
                testResult = "\(dest.host) is not blocked → \(RuleEditing.outboundLabel(m.outbound))"
            }
        }
    }
}
