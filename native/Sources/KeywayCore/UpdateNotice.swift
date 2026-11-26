import Foundation

/// When to tell the user about a newer Keyway: the main-window banner and the
/// one-time system notification. Pure, so it is unit-tested.
public enum UpdateNotice {
    /// The version an announcement is about, or nil when there is nothing to announce.
    public static func announced(_ u: AppUpdate) -> String? {
        guard u.available, let v = u.latest, !v.isEmpty else { return nil }
        return v
    }

    /// The banner shows until the user hides it for this version ("Later").
    public static func showsBanner(_ u: AppUpdate, dismissed: String?) -> Bool {
        guard let v = announced(u) else { return false }
        return v != dismissed
    }

    /// One notification per version, and none once the user is already downloading it.
    public static func shouldNotify(_ u: AppUpdate, notified: String?) -> Bool {
        guard let v = announced(u) else { return false }
        return v != notified && u.download == nil
    }
}
