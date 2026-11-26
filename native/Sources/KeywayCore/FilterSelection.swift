import Foundation

/// Edits of the chosen filter lists, and the summary lines the UI shows. New
/// lists carry an empty id; the backend assigns it when it saves.
public enum FilterSelection {
    public static func isChosen(_ key: String, in lists: [FilterList]) -> Bool {
        lists.contains { $0.catalogKey == key && $0.enabled }
    }

    /// Ticks or unticks a catalog list. Unticking drops it, so unused entries do not pile up.
    public static func setting(_ item: CatalogList, on: Bool, in lists: [FilterList]) -> [FilterList] {
        var out = lists.filter { $0.catalogKey != item.key }
        if on { out.append(FilterList(catalogKey: item.key, name: item.name)) }
        return out
    }

    /// A custom list from a URL typed by the user; it is named after the host.
    public static func adding(url: String, to lists: [FilterList]) -> [FilterList] {
        let u = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !u.isEmpty, !lists.contains(where: { $0.url == u }) else { return lists }
        let name = URL(string: u)?.host ?? u
        return lists + [FilterList(name: name, url: u)]
    }

    public static func setting(id: String, enabled: Bool, in lists: [FilterList]) -> [FilterList] {
        lists.map { var l = $0; if l.id == id { l.enabled = enabled }; return l }
    }

    public static func removing(id: String, from lists: [FilterList]) -> [FilterList] {
        lists.filter { $0.id != id }
    }

    /// The list a catalog key or a URL stands for, independent of the backend id.
    private static func identity(_ l: FilterList) -> String {
        if let k = l.catalogKey, !k.isEmpty { return "catalog:" + k }
        return "url:" + (l.url ?? "")
    }

    /// The settings the user last asked for, laid over what the backend holds now:
    /// the server's settings with the wanted lists and allowlist. Lists match by
    /// catalog key or URL, so a list added by the save that just finished keeps
    /// its new id instead of being added again; one the backend no longer knows
    /// goes back in without an id and gets a fresh one.
    public static func reapplying(_ wanted: AppSettings, onto server: AppSettings) -> AppSettings {
        let known = Dictionary(server.filterLists.map { (identity($0), $0) }, uniquingKeysWith: { a, _ in a })
        var out = server
        out.filterLists = wanted.filterLists.map { w in
            if var s = known[identity(w)] {
                s.enabled = w.enabled
                return s
            }
            var fresh = w
            fresh.id = ""
            return fresh
        }
        out.allowedSites = wanted.allowedSites
        return out
    }

    /// Lists to show in the Custom tab: the ones that came from a URL.
    public static func custom(_ lists: [FilterList]) -> [FilterList] {
        lists.filter { ($0.catalogKey ?? "").isEmpty }
    }

    /// "3 lists · 412,880 domains · Updated 2 hours ago", for the Routing pane.
    public static func summary(settings: AppSettings, view: FilterView, now: Date = Date()) -> String {
        let chosen = settings.filterLists.filter(\.enabled)
        if chosen.isEmpty { return "No lists chosen" }
        var parts = [Format.plural(chosen.count, "list")]
        let ready = chosen.compactMap { c in view.lists.first { $0.id == c.id && $0.hasStatus } }
        if ready.count < chosen.count && view.domains == 0 {
            parts.append("downloading…")
        } else {
            parts.append(domains(view.domains))
            if let last = ready.map(\.status.updatedAt).filter({ $0 != .distantPast }).max() {
                parts.append(Format.updated(last, now: now))
            }
        }
        return parts.joined(separator: " · ")
    }

    /// The line under a row: size and age of the copy, or why the last download failed.
    public static func statusLine(_ v: FilterListView, now: Date = Date()) -> String? {
        let s = v.status
        let hasCopy = s.updatedAt != .distantPast
        if let err = s.lastError, !err.isEmpty {
            return hasCopy ? "Couldn't update: \(err). Using the copy from \(age(s.updatedAt, now: now))." : "Couldn't download: \(err)"
        }
        guard hasCopy else { return nil }
        return "\(domains(s.domains)) · \(Format.updated(s.updatedAt, now: now))"
    }

    /// "412,880 domains".
    public static func domains(_ n: Int) -> String { "\(n.formatted()) \(n == 1 ? "domain" : "domains")" }

    private static func age(_ d: Date, now: Date) -> String {
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .full
        return f.localizedString(for: d, relativeTo: now)
    }
}
