import SwiftUI
import XrayFriendlyCore

/// Edits the saved rule sets: an ordered list of rules, each sending the entries
/// it matches to the proxy, direct or a block. Changes apply on "Save Rule Set".
struct RuleSetEditor: View {
    @Environment(AppModel.self) private var model
    @State private var sets: [RuleSet] = []
    @State private var activeID = ""
    @State private var loaded = false
    @State private var showImport = false
    @State private var importText = ""
    @State private var importNote = ""
    @State private var testText = ""
    @State private var testResult = ""

    private var index: Int? { sets.firstIndex { $0.id == activeID } }

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            CardSection(title: "Rule set", caption: "Rules run top to bottom and the first match wins. Traffic that matches nothing goes through the proxy.") {
                CardRow(label: "Active set", first: true) {
                    Picker("Active set", selection: $activeID) {
                        ForEach(sets) { Text($0.name).tag($0.id) }
                    }
                    .labelsHidden().fixedSize()
                    Menu {
                        Button("New Set from Template") { add(RuleEditing.template(name: "Rule set \(sets.count + 1)")) }
                        Button("New Empty Set") { add(RuleSet(id: RuleEditing.newID(), name: "Rule set \(sets.count + 1)")) }
                        Button("Duplicate") { if let i = index { add(RuleEditing.duplicate(sets[i])) } }.disabled(index == nil)
                        Divider()
                        Button("Delete Set", role: .destructive) { deleteActive() }.disabled(sets.count < 2)
                    } label: { Label("Manage", systemImage: "ellipsis.circle") }
                        .menuStyle(.borderlessButton).fixedSize()
                }
                if let i = index {
                    CardRow(label: "Name") {
                        TextField("Name", text: $sets[i].name).textFieldStyle(.roundedBorder).frame(width: 220)
                    }
                }
            }
            if let i = index {
                CardSection(title: "Rules", footnote: "Entries, one per line: geosite:cn, geoip:ir, domain:example.org, full:www.example.org, keyword:bank, 10.0.0.0/8, port:80,443 or process:Slack (sing-box only).") {
                    ForEach(Array(sets[i].rules.enumerated()), id: \.element.id) { n, rule in
                        ruleRow(i, n, rule)
                    }
                    if sets[i].rules.isEmpty {
                        Text("No rules yet. Everything goes through the proxy.").foregroundStyle(Palette.secondary).padding(14)
                    }
                    Divider()
                    HStack {
                        Button { sets[i].rules.append(RouteRule(id: RuleEditing.newID(), entries: [], outbound: "direct")) } label: {
                            Label("Add Rule", systemImage: "plus")
                        }
                        Button { importText = ""; importNote = ""; showImport = true } label: {
                            Label("Import Rules…", systemImage: "square.and.arrow.down")
                        }
                        Spacer()
                    }
                    .padding(10)
                }
                CardSection(title: "Test a destination", caption: "See which rule would handle a site. geosite and geoip lists are checked by the engine, not here.") {
                    HStack {
                        TextField("example.com or example.com:443", text: $testText)
                            .textFieldStyle(.roundedBorder).onSubmit { runTest() }
                        Button("Test") { runTest() }.disabled(testText.trimmingCharacters(in: .whitespaces).isEmpty)
                    }
                    .padding(14)
                    if !testResult.isEmpty {
                        Divider()
                        Text(testResult).font(.system(size: 12)).textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading).padding(14)
                    }
                }
            }
            let problems = index.map { RuleEditing.problems(sets[$0]) } ?? []
            ForEach(problems, id: \.self) { Text($0).font(.system(size: 12)).foregroundStyle(Palette.warn) }
            HStack {
                Spacer()
                Button("Revert") { load() }.disabled(!dirty)
                Button("Save Rule Set") { save() }
                    .buttonStyle(.borderedProminent).disabled(!dirty || !problems.isEmpty)
            }
        }
        .onAppear { if !loaded { load() } }
        .sheet(isPresented: $showImport) { importSheet }
    }

    private func ruleRow(_ i: Int, _ n: Int, _ rule: RouteRule) -> some View {
        let entries = Binding(get: { RuleEditing.text(from: sets[i].rules[n].entries) },
                              set: { sets[i].rules[n].entries = RuleEditing.entries(from: $0) })
        return VStack(alignment: .leading, spacing: 6) {
            if n > 0 { Divider() }
            HStack(spacing: 8) {
                Toggle("Rule \(n + 1) enabled", isOn: $sets[i].rules[n].enabled).labelsHidden()
                Text("Rule \(n + 1)").font(.system(size: 12, weight: .semibold))
                if let name = rule.name, !name.isEmpty { Text(name).font(.system(size: 12)).foregroundStyle(Palette.secondary) }
                Spacer()
                Picker("Send to", selection: $sets[i].rules[n].outbound) {
                    Text("Proxy").tag("proxy"); Text("Direct").tag("direct"); Text("Block").tag("block")
                }
                .labelsHidden().fixedSize()
                Button { RuleEditing.move(&sets[i].rules, id: rule.id, by: -1) } label: { Image(systemName: "chevron.up") }
                    .disabled(n == 0).accessibilityLabel("Move rule up")
                Button { RuleEditing.move(&sets[i].rules, id: rule.id, by: 1) } label: { Image(systemName: "chevron.down") }
                    .disabled(n == sets[i].rules.count - 1).accessibilityLabel("Move rule down")
                Button(role: .destructive) { sets[i].rules.removeAll { $0.id == rule.id } } label: { Image(systemName: "trash") }
                    .accessibilityLabel("Delete rule")
            }
            .buttonStyle(.borderless)
            TextEditor(text: entries)
                .font(.system(size: 11, design: .monospaced))
                .frame(height: 56)
                .scrollContentBackground(.hidden)
                .opacity(rule.enabled ? 1 : 0.5)
                .accessibilityLabel("Entries of rule \(n + 1)")
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
    }

    private var importSheet: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Import Rules").font(.system(size: 15, weight: .bold))
            Text("Paste Clash rules (DOMAIN-SUFFIX,example.com,DIRECT) or v2rayN / Xray routing JSON. They are added to the end of this set.")
                .font(.system(size: 12)).foregroundStyle(Palette.secondary)
            TextEditor(text: $importText).font(.system(size: 11, design: .monospaced)).frame(height: 180)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(Palette.cardBorder))
            if !importNote.isEmpty { Text(importNote).font(.system(size: 12)).foregroundStyle(Palette.secondary) }
            HStack {
                Spacer()
                Button("Cancel") { showImport = false }
                Button("Import") { runImport() }.buttonStyle(.borderedProminent)
                    .disabled(importText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(20).frame(width: 480)
    }

    // MARK: actions

    private var dirty: Bool { sets != model.settings.ruleSets || activeID != model.settings.activeRuleSet }

    private func load() {
        sets = model.settings.ruleSets
        activeID = model.settings.activeRuleSet
        if index == nil, let first = sets.first { activeID = first.id }
        loaded = true
    }

    private func add(_ set: RuleSet) { sets.append(set); activeID = set.id }

    private func deleteActive() {
        sets.removeAll { $0.id == activeID }
        activeID = sets.first?.id ?? ""
    }

    private func save() {
        var s = model.settings
        s.ruleSets = sets
        s.activeRuleSet = activeID
        model.save(s)
    }

    private func runImport() {
        Task {
            guard let got = await model.importRules(importText), let i = index else { return }
            sets[i].rules.append(contentsOf: got.rules.map { var r = $0; r.id = RuleEditing.newID(); return r })
            if got.skipped.isEmpty {
                showImport = false
            } else {
                importNote = "Added \(got.rules.count) rules. Skipped \(got.skipped.count): \(got.skipped.prefix(3).joined(separator: "; "))"
                importText = ""
            }
        }
    }

    private func runTest() {
        guard let i = index else { return }
        let dest = RuleEditing.destination(testText)
        Task {
            guard let m = await model.testRoute(host: dest.host, port: dest.port, rules: sets[i].rules) else { return }
            var text = "→ \(RuleEditing.outboundLabel(m.outbound))"
            if let id = m.ruleId, let n = sets[i].rules.firstIndex(where: { $0.id == id }) {
                text += " by rule \(n + 1)" + (m.entry.map { " (\($0))" } ?? "")
            } else {
                text += " (no rule matched)"
            }
            if let u = m.unknown, !u.isEmpty {
                text += "\nNot checked here: " + u.prefix(4).joined(separator: ", ") + (u.count > 4 ? ", …" : "")
            }
            testResult = text
        }
    }
}
