import Foundation

/// Pure helpers behind the routing rule editor.
public enum RuleEditing {
    public static func newID() -> String { UUID().uuidString.lowercased().prefix(8).description }

    /// "a, b\nc" -> ["a", "b", "c"].
    public static func entries(from text: String) -> [String] {
        text.split(whereSeparator: { $0 == "\n" || $0 == "," || $0 == "\r" || $0 == "\r\n" })
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    public static func text(from entries: [String]) -> String { entries.joined(separator: "\n") }

    /// A sensible first rule set: block ads, send local and Chinese traffic direct.
    public static func template(name: String = "Bypass LAN & China") -> RuleSet {
        RuleSet(id: newID(), name: name, rules: [
            RouteRule(id: newID(), name: "Ads and trackers", entries: ["geosite:category-ads-all"], outbound: "block"),
            RouteRule(id: newID(), name: "Local network", entries: ["geoip:private", "geosite:private"], outbound: "direct"),
            RouteRule(id: newID(), name: "China", entries: ["geosite:cn", "geoip:cn"], outbound: "direct"),
        ])
    }

    public static func move(_ rules: inout [RouteRule], id: String, by offset: Int) {
        guard let i = rules.firstIndex(where: { $0.id == id }) else { return }
        let j = i + offset
        guard rules.indices.contains(j) else { return }
        rules.swapAt(i, j)
    }

    public static func duplicate(_ set: RuleSet) -> RuleSet {
        var copy = set
        copy.id = newID()
        copy.name = set.name + " copy"
        copy.rules = set.rules.map { var r = $0; r.id = newID(); return r }
        return copy
    }

    /// What would make the backend refuse the set; shown before saving.
    public static func problems(_ set: RuleSet) -> [String] {
        var out: [String] = []
        for (i, r) in set.rules.enumerated() where r.enabled && r.entries.isEmpty {
            out.append("Rule \(i + 1) is on but has no entries.")
        }
        return out
    }

    /// "example.com:8443" / "example.com" / "1.2.3.4" -> host and port (0 = any).
    public static func destination(_ text: String) -> (host: String, port: Int) {
        var t = text.trimmingCharacters(in: .whitespaces)
        for prefix in ["https://", "http://"] where t.lowercased().hasPrefix(prefix) { t = String(t.dropFirst(prefix.count)) }
        if let slash = t.firstIndex(of: "/") { t = String(t[..<slash]) }
        if let colon = t.lastIndex(of: ":"), t.filter({ $0 == ":" }).count == 1, let port = Int(t[t.index(after: colon)...]) {
            return (String(t[..<colon]), port)
        }
        return (t, 0)
    }

    public static func outboundLabel(_ outbound: String) -> String {
        switch outbound {
        case "direct": return "Direct"
        case "block": return "Block"
        default: return "Proxy"
        }
    }
}
