import SwiftUI
import KeywayCore

/// Server groups: a set of servers used as one. Choose a group as the active
/// server like any other; the group decides which of its servers carries traffic.
struct GroupsView: View {
    @Environment(AppModel.self) private var model
    @State private var editing: GroupTarget?

    var body: some View {
        List {
            ForEach(model.groups) { g in
                GroupRow(group: g, onEdit: { editing = .edit(g) })
            }
        }
        .overlay {
            if model.groups.isEmpty {
                ContentUnavailableView {
                    Label("No groups", systemImage: "square.stack.3d.up")
                } description: {
                    Text("A group uses one server out of several: pick it yourself, take the first that works, or always the fastest. Clash configs bring their groups along.")
                } actions: {
                    Button("New Group…") { editing = .new }.buttonStyle(.borderedProminent).disabled(model.nodes.isEmpty)
                }
            }
        }
        .navigationTitle("Groups")
        .navigationSubtitle(Format.plural(model.groups.count, "group"))
        .toolbar {
            ToolbarItem {
                Button { editing = .new } label: { Label("New Group", systemImage: "plus") }
                    .disabled(model.nodes.isEmpty)
                    .accessibilityLabel("New group")
            }
        }
        .sheet(item: $editing) { GroupEditor(target: $0) }
    }
}

enum GroupTarget: Identifiable {
    case new
    case edit(ProxyGroup)
    var id: String { if case .edit(let g) = self { return g.id } else { return "new" } }
}

private struct GroupRow: View {
    @Environment(AppModel.self) private var model
    let group: ProxyGroup
    let onEdit: () -> Void

    private var active: Bool { model.activeGroupId == group.id }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon).foregroundStyle(active ? Palette.green : Palette.accentText).frame(width: 18)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(group.name).font(.system(size: 13, weight: .semibold))
                    if active {
                        Text(model.connected ? "In use" : "Selected").font(.system(size: 10, weight: .bold)).foregroundStyle(Palette.greenText)
                            .padding(.horizontal, 5).padding(.vertical, 1).background(RoundedRectangle(cornerRadius: 4).fill(Palette.badge))
                    }
                }
                Text([Format.strategyName(group.strategy), Format.plural(group.memberCount, "server"), origin].compactMap { $0 }.joined(separator: " · "))
                    .font(.system(size: 11)).foregroundStyle(Palette.secondary)
                currentLine
            }
            Spacer()
            actions
        }
        .padding(.vertical, 6)
        .accessibilityElement(children: .contain)
    }

    private var icon: String {
        switch group.strategy {
        case "fallback": return "arrow.triangle.turn.up.right.circle"
        case "url-test": return "bolt.circle"
        default: return "hand.point.up.left"
        }
    }

    private var origin: String? {
        if group.followsSubscription { return "All of \(group.sourceName ?? "a subscription")" }
        if group.imported { return "From \(group.sourceName ?? "a subscription")" }
        return nil
    }

    @ViewBuilder private var currentLine: some View {
        if group.strategy == "select" {
            Menu {
                ForEach(group.members, id: \.self) { id in
                    if let n = model.nodes.first(where: { $0.id == id }) {
                        Button { model.selectMember(of: group, id) } label: {
                            Text("\(group.current == id ? "✓ " : "")\(n.displayName)  \(Format.latency(n.latencyMs))")
                        }
                    }
                }
            } label: {
                Text("Server: \(group.currentName ?? "none")").font(.system(size: 12))
            }
            .menuStyle(.borderlessButton).fixedSize()
            .accessibilityLabel("Server of \(group.name)")
        } else if let name = group.currentName {
            Text("Using \(name) · \(Format.latency(group.currentLatencyMs))").font(.system(size: 12)).foregroundStyle(Palette.secondary)
        }
    }

    @ViewBuilder private var actions: some View {
        if group.isAutomatic {
            Button("Test") { model.testGroup(group.id) }.disabled(model.testing)
                .help("Test the servers and let the group choose")
        }
        Button(model.connected && active ? "Reconnect" : "Use") { model.connectGroup(group.id) }
            .disabled(group.memberCount == 0 || model.connecting)
            .help("Connect through this group")
        if !group.imported {
            Button { onEdit() } label: { Image(systemName: "pencil") }.help("Edit this group").accessibilityLabel("Edit \(group.name)")
            Button(role: .destructive) { model.deleteGroup(group.id) } label: { Image(systemName: "trash") }
                .help("Delete this group (its servers stay)").accessibilityLabel("Delete \(group.name)")
        }
    }
}

/// Creates a group or edits one made by hand (or the name and strategy of one that follows a subscription).
struct GroupEditor: View {
    let target: GroupTarget
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var strategy = "select"
    @State private var members: [String] = []
    @State private var loaded = false

    private var existing: ProxyGroup? { if case .edit(let g) = target { return g } else { return nil } }
    private var followsSubscription: Bool { existing?.followsSubscription == true }
    private var candidates: [Node] { model.nodes.filter { !members.contains($0.id) } }
    private var valid: Bool { !name.trimmingCharacters(in: .whitespaces).isEmpty && (followsSubscription || !members.isEmpty) }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    LabeledContent("Name") {
                        TextField("Name", text: $name, prompt: Text("Shown in the menu bar")).labelsHidden().multilineTextAlignment(.trailing)
                    }
                    Picker("Strategy", selection: $strategy) {
                        Text("Manual").tag("select")
                        Text("Fallback").tag("fallback")
                        Text("Fastest").tag("url-test")
                    }
                } footer: {
                    Text(Format.strategyHelp(strategy)).font(.system(size: 11)).foregroundStyle(Palette.secondary)
                }
                if followsSubscription {
                    Section {
                        Text("This group always holds every server of \(existing?.sourceName ?? "its subscription").")
                            .font(.system(size: 12)).foregroundStyle(Palette.secondary)
                    }
                } else {
                    Section {
                        if members.isEmpty {
                            Text("No servers yet.").font(.system(size: 12)).foregroundStyle(Palette.secondary)
                        }
                        ForEach(Array(members.enumerated()), id: \.offset) { i, id in memberRow(i, id) }
                        addMenu
                    } header: {
                        Text(strategy == "fallback" ? "Servers, in order of preference" : "Servers")
                    } footer: {
                        Text("A group holds single servers or chains. A group cannot be a step inside a chain.")
                            .font(.system(size: 11)).foregroundStyle(Palette.secondary)
                    }
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                Button(existing == nil ? "Create" : "Save") { save() }
                    .keyboardShortcut(.defaultAction).buttonStyle(.borderedProminent).disabled(!valid)
            }
            .padding(12)
        }
        .frame(width: 520, height: 560)
        .onAppear {
            guard !loaded else { return }
            loaded = true
            if let g = existing { name = g.name; strategy = g.strategy; members = g.members }
        }
    }

    @ViewBuilder private func memberRow(_ i: Int, _ id: String) -> some View {
        let node = model.nodes.first { $0.id == id }
        HStack(spacing: 8) {
            if strategy == "fallback" {
                Text(verbatim: "\(i + 1)").font(.system(size: 11, weight: .bold)).foregroundStyle(.white)
                    .frame(width: 20, height: 20).background(Circle().fill(Palette.accent)).accessibilityHidden(true)
            }
            Text(node?.displayName ?? "Missing server").foregroundStyle(node == nil ? Palette.error : Color.primary).lineLimit(1)
            if let node { Text(node.protocolName).font(.system(size: 11)).foregroundStyle(Palette.secondary) }
            Spacer()
            if strategy == "fallback" {
                Button { members.swapAt(i, i - 1) } label: { Image(systemName: "arrow.up") }.disabled(i == 0).accessibilityLabel("Move up")
                Button { members.swapAt(i, i + 1) } label: { Image(systemName: "arrow.down") }
                    .disabled(i == members.count - 1).accessibilityLabel("Move down")
            }
            Button(role: .destructive) { members.remove(at: i) } label: { Image(systemName: "minus.circle") }
                .accessibilityLabel("Remove \(node?.displayName ?? "server") from the group")
        }
        .buttonStyle(.borderless)
    }

    private var addMenu: some View {
        Menu {
            if candidates.isEmpty { Text("No more servers") }
            ForEach(candidates) { n in
                Button("\(n.countryCode.map { $0 + "  " } ?? "")\(n.displayName) — \(n.protocolName)") { members.append(n.id) }
            }
        } label: {
            Label("Add Server", systemImage: "plus")
        }
        .menuStyle(.borderlessButton).fixedSize().disabled(candidates.isEmpty)
        .accessibilityLabel("Add a server to the group")
    }

    private func save() {
        let input = GroupInput(name: name.trimmingCharacters(in: .whitespaces), strategy: strategy, members: followsSubscription ? nil : members)
        if let g = existing { model.updateGroup(g.id, input) } else { model.createGroup(input) }
        dismiss()
    }
}
