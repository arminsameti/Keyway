import Foundation

/// Latency label classes from the design: <100 Fast, <200 OK, else Slow;
/// -2 Timeout; -3 n/a (UDP protocol in TCP mode); -1 never measured.
public enum LatencyClass: Equatable, Sendable {
    case fast, ok, slow, timeout, notApplicable, unknown

    public init(ms: Int) {
        switch ms {
        case -2: self = .timeout
        case -3: self = .notApplicable
        case ..<0: self = .unknown
        case ..<100: self = .fast
        case ..<200: self = .ok
        default: self = .slow
        }
    }
}

public enum Format {
    /// Table cell text: "48 ms", "Timeout", "n/a", "—".
    public static func latency(_ ms: Int) -> String {
        switch LatencyClass(ms: ms) {
        case .timeout: return "Timeout"
        case .notApplicable: return "n/a"
        case .unknown: return "—"
        default: return "\(ms) ms"
        }
    }

    /// Inspector text: "48 ms · Fast", "Unreachable", "UDP — use Real test".
    public static func latencyLong(_ ms: Int) -> String {
        switch LatencyClass(ms: ms) {
        case .fast: return "\(ms) ms · Fast"
        case .ok: return "\(ms) ms · OK"
        case .slow: return "\(ms) ms · Slow"
        case .timeout: return "Unreachable"
        case .notApplicable: return "UDP — use Real test"
        case .unknown: return "Not tested yet"
        }
    }

    /// Sort key: measured first by speed, then n/a, unknown, timeout.
    public static func latencySortKey(_ ms: Int) -> Int {
        switch ms {
        case 0...: return ms
        case -3: return 1_000_000
        case -1: return 2_000_000
        default: return 3_000_000
        }
    }

    public static func plural(_ n: Int, _ one: String, _ many: String? = nil) -> String {
        "\(n) \(n == 1 ? one : (many ?? one + "s"))"
    }

    /// "10 servers · 8 protocols · 2 sources".
    public static func serverSummary(_ nodes: [Node]) -> String {
        let protos = Set(nodes.map(\.protocol)).count
        let sources = Set(nodes.map { $0.source ?? "" }).count
        return [plural(nodes.count, "server"), plural(protos, "protocol"), plural(sources, "source")].joined(separator: " · ")
    }

    /// Primary button of the Add Servers sheet: "Add 4 Servers & 1 Subscription".
    public static func addButton(servers: Int, subscriptions: Int) -> String {
        let s = servers == 1 ? "1 Server" : "\(servers) Servers"
        let u = subscriptions == 1 ? "1 Subscription" : "\(subscriptions) Subscriptions"
        switch (servers, subscriptions) {
        case (0, 0): return "Add"
        case (_, 0): return "Add \(s)"
        case (0, _): return "Add \(u)"
        default: return "Add \(s) & \(u)"
        }
    }

    /// "4 servers · 1 subscription · 1 skipped".
    public static func previewSummary(_ p: ImportPreview) -> String {
        var parts: [String] = []
        if p.ready > 0 { parts.append(plural(p.ready, "server")) }
        if p.subscriptions > 0 { parts.append(plural(p.subscriptions, "subscription")) }
        if p.skipped > 0 { parts.append("\(p.skipped) skipped") }
        return parts.joined(separator: " · ")
    }

    /// "1.2 MB", "340 KB", "12 B".
    public static func bytes(_ n: Int64) -> String {
        let units = ["B", "KB", "MB", "GB", "TB"]
        var v = Double(max(0, n)), i = 0
        while v >= 1000, i < units.count - 1 { v /= 1000; i += 1 }
        return i == 0 ? "\(Int(v)) B" : String(format: v < 10 ? "%.1f %@" : "%.0f %@", v, units[i])
    }

    /// "1.2 MB/s".
    public static func rate(_ bps: Int64) -> String { bytes(bps) + "/s" }

    /// "00:14:32".
    public static func uptime(_ seconds: Int) -> String {
        let s = max(0, seconds)
        return String(format: "%02d:%02d:%02d", s / 3600, (s / 60) % 60, s % 60)
    }

    /// "Updated 2 hours ago".
    public static func updated(_ date: Date?, now: Date = Date()) -> String {
        guard let date, date > Date(timeIntervalSince1970: 0) else { return "Never updated" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return "Updated " + f.localizedString(for: date, relativeTo: now)
    }

    /// "12.3 GB of 100 GB used", or "12.3 GB used" when the provider gave no limit.
    public static func usageLine(_ u: SubUsage) -> String {
        u.total > 0 ? "\(bytes(u.used)) of \(bytes(u.total)) used" : "\(bytes(u.used)) used"
    }

    /// Share of the quota used, 0...1; nil without a limit.
    public static func usageFraction(_ u: SubUsage) -> Double? {
        u.total > 0 ? min(1, max(0, Double(u.used) / Double(u.total))) : nil
    }

    /// "Expires in 12 days", "Expires today", "Expired 3 days ago"; nil when the plan has no expiry.
    public static func expiry(_ date: Date?, now: Date = Date(), calendar: Calendar = .current) -> String? {
        guard let date else { return nil }
        let days = calendar.dateComponents([.day], from: calendar.startOfDay(for: now), to: calendar.startOfDay(for: date)).day ?? 0
        switch days {
        case 0: return date < now ? "Expired today" : "Expires today"
        case 1...: return "Expires in \(plural(days, "day"))"
        default: return "Expired \(plural(-days, "day")) ago"
        }
    }

    /// How a group picks its server, for lists.
    public static func strategyName(_ s: String) -> String {
        switch s {
        case "fallback": return "Fallback"
        case "url-test": return "Fastest"
        default: return "Manual"
        }
    }

    public static func strategyHelp(_ s: String) -> String {
        switch s {
        case "fallback": return "Uses the first server in the list that works, and moves on to the next when it stops answering."
        case "url-test": return "Tests the servers regularly and uses the fastest, staying put unless another is clearly faster."
        default: return "You choose which server the group uses."
        }
    }

    public static func formatName(_ format: String?) -> String? {
        switch format {
        case "clash": return "Clash format"
        case "sing-box": return "sing-box format"
        case "base64": return "base64"
        case "links": return "Plain links"
        case "wireguard": return "WireGuard config"
        default: return nil
        }
    }

    public static func routingDescription(_ mode: String) -> String {
        switch mode {
        case "global": return "Everything through the proxy"
        case "custom": return "Custom routing rules"
        case "rules": return "Your rule set"
        default: return "Bypassing private & local sites"
        }
    }

    /// The shell line that points terminal tools at the local proxies.
    public static func exportCommand(socks: Int?, http: Int?) -> String {
        var parts: [String] = []
        if let http { parts.append("export http_proxy=http://127.0.0.1:\(http) https_proxy=http://127.0.0.1:\(http)") }
        if let socks { parts.append("export all_proxy=socks5://127.0.0.1:\(socks)") }
        return parts.joined(separator: "; ")
    }

    /// Short engine version for badges: "Xray core 26.3", "sing-box 1.14".
    public static func engineBadge(displayName: String, active: String) -> String {
        let v = active.hasPrefix("v") ? String(active.dropFirst()) : active
        let short = v.split(separator: ".").prefix(2).joined(separator: ".")
        return short.isEmpty ? displayName : "\(displayName) \(short)"
    }
}
