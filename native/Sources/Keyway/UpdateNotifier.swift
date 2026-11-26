import AppKit
import KeywayCore
import UserNotifications

/// Posts one macOS notification per new Keyway version. Clicking it opens the
/// main window, where the update banner offers the download. While Keyway is
/// the active app the notification goes quietly to Notification Center, since
/// the banner is already on screen.
@MainActor
final class UpdateNotifier: NSObject, UNUserNotificationCenterDelegate {
    static let shared = UpdateNotifier()

    /// Opens the main window; set by MainView (the window may be closed when the notification is clicked).
    var openMain: (() -> Void)?

    private static let notifiedKey = "notifiedUpdateVersion"
    private var center: UNUserNotificationCenter?

    private override init() {
        super.init()
        // UNUserNotificationCenter needs a real app bundle; `swift run` and the test runner have none.
        if Bundle.main.bundleIdentifier != nil, Bundle.main.bundleURL.pathExtension == "app" {
            center = UNUserNotificationCenter.current()
            center?.delegate = self
        }
    }

    func notifyIfNeeded(_ u: AppUpdate) {
        let defaults = UserDefaults.standard
        guard UpdateNotice.shouldNotify(u, notified: defaults.string(forKey: Self.notifiedKey)),
              let version = UpdateNotice.announced(u) else { return }
        // Remember it before asking, so a declined permission never re-prompts for the same release.
        defaults.set(version, forKey: Self.notifiedKey)
        guard let center else { return }
        let content = UNMutableNotificationContent()
        content.title = "Keyway \(Self.display(version)) is available"
        content.body = "Open Keyway to download the update."
        content.sound = .default
        let request = UNNotificationRequest(identifier: "keyway-update-\(version)", content: content, trigger: nil)
        Task {
            guard (try? await center.requestAuthorization(options: [.alert, .sound])) == true else { return }
            try? await center.add(request)
        }
    }

    private static func display(_ v: String) -> String { v.hasPrefix("v") ? String(v.dropFirst()) : v }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
                                            withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        // Keyway is in front: the banner in the main window already says it.
        completionHandler([.list])
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
                                            withCompletionHandler completionHandler: @escaping () -> Void) {
        Task { @MainActor in
            self.openMain?()
            Activation.bringForward()
            completionHandler()
        }
    }
}
