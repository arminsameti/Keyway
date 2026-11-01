import SwiftUI
import KeywayCore

/// The body of the New Server window while "Proxy Chain" is selected: pick
/// existing servers and put them in order. Traffic goes through them top to
/// bottom, so the first is the entry and the last is where it leaves.
struct ChainEditor: View {
    @Binding var chain: ChainForm
    let plan: ChainPlan?
    let problem: String?
    let planning: Bool
    @Environment(AppModel.self) private var model

    private var nodes: [Node] { model.nodes }
    private var candidates: [Node] { chain.candidates(from: nodes) }

    var body: some View {
        Form {
            Section {
                LabeledContent("Name") {
                    TextField("Name", text: $chain.name, prompt: Text(chain.hops.count >= 2 ? chain.defaultName(in: nodes) : "Shown in the server list"))
                        .labelsHidden().multilineTextAlignment(.trailing)
                }
            } header: {
                Text("Chain")
            }

            Section {
                if chain.hops.isEmpty {
                    Text("No servers yet. Add the servers in the order traffic should travel.")
                        .font(.system(size: 12)).foregroundStyle(Palette.secondary)
                }
                ForEach(Array(chain.hops.enumerated()), id: \.offset) { i, id in
                    hopRow(i, node: nodes.first { $0.id == id })
                }
                addMenu
            } header: {
                Text("Servers, in order")
            } footer: {
                VStack(alignment: .leading, spacing: 6) {
                    status
                    Text("Traffic goes through the servers from top to bottom; the last one connects to the internet. A hop that uses UDP (WireGuard, Hysteria, TUIC, OpenVPN over UDP) needs the server before it to carry UDP.")
                        .font(.system(size: 11)).foregroundStyle(Palette.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
    }

    // MARK: rows

    @ViewBuilder
    private func hopRow(_ i: Int, node: Node?) -> some View {
        let last = chain.hops.count - 1
        HStack(spacing: 10) {
            Text(verbatim: "\(i + 1)")
                .font(.system(size: 11, weight: .bold)).foregroundStyle(.white)
                .frame(width: 20, height: 20).background(Circle().fill(Palette.accent))
                .accessibilityHidden(true)
            if let node {
                if let cc = node.countryCode {
                    Text(cc).font(.system(size: 10, weight: .bold)).foregroundStyle(Palette.tertiary)
                        .padding(.horizontal, 4).padding(.vertical, 2)
                        .background(RoundedRectangle(cornerRadius: 4).fill(Palette.badge))
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text(node.displayName).lineLimit(1)
                    Text("\(node.protocolName) · \(node.transport) · \(role(i, last: last))")
                        .font(.system(size: 11)).foregroundStyle(Palette.secondary).lineLimit(1)
                }
            } else {
                Text("Missing server").foregroundStyle(Palette.error)
                Text(role(i, last: last)).font(.system(size: 11)).foregroundStyle(Palette.secondary)
            }
            Spacer(minLength: 6)
            Button { chain.move(at: i, by: -1) } label: { Image(systemName: "arrow.up") }
                .disabled(i == 0).help("Move towards the entry").accessibilityLabel("Move up")
            Button { chain.move(at: i, by: 1) } label: { Image(systemName: "arrow.down") }
                .disabled(i == last).help("Move towards the exit").accessibilityLabel("Move down")
            Button(role: .destructive) { chain.remove(at: i) } label: { Image(systemName: "minus.circle") }
                .help("Remove from the chain").accessibilityLabel("Remove \(node?.displayName ?? "server") from the chain")
        }
        .buttonStyle(.borderless)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Hop \(i + 1), \(node?.displayName ?? "missing server"), \(role(i, last: last))")
    }

    private func role(_ i: Int, last: Int) -> String {
        switch i {
        case 0: return "entry"
        case last: return "exit"
        default: return "hop \(i + 1)"
        }
    }

    private var addMenu: some View {
        Menu {
            if candidates.isEmpty { Text("Add servers first") }
            ForEach(candidates) { n in
                Button("\(n.countryCode.map { $0 + "  " } ?? "")\(n.displayName) — \(n.protocolName)") { chain.add(n.id) }
            }
        } label: {
            Label("Add Server", systemImage: "plus")
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
        .disabled(!chain.canAddMore || candidates.isEmpty)
        .accessibilityLabel("Add a server to the chain")
    }

    // MARK: verdict

    @ViewBuilder private var status: some View {
        if let blocker = chain.blocker(in: nodes) {
            Label(blocker, systemImage: "info.circle").font(.system(size: 12)).foregroundStyle(Palette.secondary)
        } else if let problem {
            Label(problem, systemImage: "exclamationmark.triangle").font(.system(size: 12, weight: .semibold)).foregroundStyle(Palette.error)
                .fixedSize(horizontal: false, vertical: true)
        } else if let plan {
            Label(planText(plan), systemImage: "checkmark.circle").font(.system(size: 12, weight: .semibold)).foregroundStyle(Palette.greenText)
        } else if planning {
            Label("Checking…", systemImage: "hourglass").font(.system(size: 12)).foregroundStyle(Palette.secondary)
        }
    }

    private func planText(_ p: ChainPlan) -> String {
        var s = "Valid. Runs on \(p.engineName)"
        if p.processes > 1 { s += " (\(p.processes) processes joined by a private local connection)" }
        if !p.installed { s += ". The missing engine is downloaded when you connect." }
        return s
    }
}
