import Foundation

/// The chain editor's state: an ordered list of existing servers, entry first.
/// Only trivial checks live here; the real rules (UDP between hops, engine
/// support) come from the backend's plan (`APIClient.planChain`), so the editor
/// can never disagree with what saving does.
public struct ChainForm: Equatable, Sendable {
    public static let maxHops = 16

    public var name = ""
    public var hops: [String] = [] // node IDs

    public init(name: String = "", hops: [String] = []) { self.name = name; self.hops = hops }

    public var canAddMore: Bool { hops.count < Self.maxHops }

    public mutating func add(_ id: String) {
        guard canAddMore else { return }
        hops.append(id)
    }

    public mutating func remove(at index: Int) {
        guard hops.indices.contains(index) else { return }
        hops.remove(at: index)
    }

    /// Moves a hop one place towards the entry (-1) or the exit (+1).
    public mutating func move(at index: Int, by delta: Int) {
        let to = index + delta
        guard hops.indices.contains(index), hops.indices.contains(to) else { return }
        hops.swapAt(index, to)
    }

    public mutating func move(fromOffsets: IndexSet, toOffset: Int) {
        let moving = fromOffsets.map { hops[$0] }
        let before = fromOffsets.filter { $0 < toOffset }.count
        for i in fromOffsets.sorted(by: >) { hops.remove(at: i) }
        hops.insert(contentsOf: moving, at: toOffset - before)
    }

    /// Servers that can still be added: single servers only, never a chain.
    public func candidates(from nodes: [Node]) -> [Node] {
        nodes.filter { !$0.isChain }
    }

    /// The hop nodes in order; nil entries are servers that no longer exist.
    public func resolved(in nodes: [Node]) -> [Node?] {
        hops.map { id in nodes.first { $0.id == id } }
    }

    /// Why the chain cannot be saved yet, or nil when the backend should decide.
    public func blocker(in nodes: [Node]) -> String? {
        if hops.count < 2 { return "Add at least two servers." }
        for (i, n) in resolved(in: nodes).enumerated() {
            guard let n else { return "Server \(i + 1) is no longer in your list." }
            if n.isChain { return "“\(n.displayName)” is a chain; a chain can only contain single servers." }
        }
        return nil
    }

    /// "Office VPN → Frankfurt → Home WG", used as the default name.
    public func defaultName(in nodes: [Node]) -> String {
        let names = resolved(in: nodes).compactMap { $0?.displayName }
        guard let first = names.first, let last = names.last else { return "Chain" }
        return "\(first) → \(last)"
    }
}
