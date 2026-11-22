import Foundation

/// Rearranging the server list by drag and drop, and adding servers to groups.
/// Pure functions, so the rules can be tested without the UI.
public enum Reorder {
    /// Where dragged servers land: right before one server or right after one.
    public struct Placement: Equatable, Sendable {
        public let ids: [String]
        public let before: String?
        public let after: String?
    }

    /// Plans a drop. `displayed` is the section's server IDs in the order shown;
    /// `moving` is what was dragged; `insertAt` is the gap the drop landed in
    /// (0 = above the first row, `displayed.count` = below the last).
    ///
    /// Only servers of this section move: a drop never carries a server into
    /// another section, since a server's section is where it came from. The
    /// anchor is the nearest row that is not itself being moved, so dropping a
    /// block next to one of its own members still does what the user pointed at.
    /// Returns nil when nothing can move.
    public static func placement(displayed: [String], moving: [String], insertAt: Int) -> Placement? {
        let here = Set(displayed)
        let drag = Set(moving.filter { here.contains($0) })
        guard !drag.isEmpty else { return nil }
        let ids = displayed.filter { drag.contains($0) } // keep the order they have on screen
        let gap = min(max(insertAt, 0), displayed.count)
        if let next = displayed[gap...].first(where: { !drag.contains($0) }) {
            return Placement(ids: ids, before: next, after: nil)
        }
        if let prev = displayed[..<gap].last(where: { !drag.contains($0) }) {
            return Placement(ids: ids, before: nil, after: prev)
        }
        return nil // every row of the section is being moved
    }

    /// A group's members with `adding` appended; servers it already has keep their place.
    public static func members(_ existing: [String], adding: [String]) -> [String] {
        var seen = Set(existing)
        var out = existing
        for id in adding where seen.insert(id).inserted { out.append(id) }
        return out
    }

    /// The text a drag carries. Prefixed so other text dropped on the list is ignored.
    static let dragPrefix = "keyway-servers:"
    public static func dragPayload(_ ids: [String]) -> String { dragPrefix + ids.joined(separator: ",") }
    public static func ids(fromDragPayload s: String) -> [String] {
        guard s.hasPrefix(dragPrefix) else { return [] }
        return s.dropFirst(dragPrefix.count).split(separator: ",").map(String.init)
    }
}
