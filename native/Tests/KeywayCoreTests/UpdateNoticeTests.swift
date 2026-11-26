import XCTest
@testable import KeywayCore

final class UpdateNoticeTests: XCTestCase {
    private func update(available: Bool, latest: String?, downloading: Bool = false) -> AppUpdate {
        var u = AppUpdate()
        u.current = "v0.1.0"
        u.available = available
        u.latest = latest
        if downloading { u.download = AppDownload(version: latest ?? "", state: "running", done: 0, total: -1) }
        return u
    }

    func testNothingToAnnounceWhenUpToDate() {
        let u = update(available: false, latest: "v0.1.0")
        XCTAssertNil(UpdateNotice.announced(u))
        XCTAssertFalse(UpdateNotice.showsBanner(u, dismissed: nil))
        XCTAssertFalse(UpdateNotice.shouldNotify(u, notified: nil))
    }

    func testBannerShowsUntilDismissedForThatVersion() {
        let u = update(available: true, latest: "v0.2.0")
        XCTAssertTrue(UpdateNotice.showsBanner(u, dismissed: nil))
        XCTAssertFalse(UpdateNotice.showsBanner(u, dismissed: "v0.2.0"))
        // a newer release brings it back
        XCTAssertTrue(UpdateNotice.showsBanner(update(available: true, latest: "v0.3.0"), dismissed: "v0.2.0"))
    }

    func testNotifiesOncePerVersion() {
        let u = update(available: true, latest: "v0.2.0")
        XCTAssertTrue(UpdateNotice.shouldNotify(u, notified: nil))
        XCTAssertFalse(UpdateNotice.shouldNotify(u, notified: "v0.2.0"))
        XCTAssertTrue(UpdateNotice.shouldNotify(update(available: true, latest: "v0.3.0"), notified: "v0.2.0"))
    }

    func testNoNotificationWhileDownloading() {
        XCTAssertFalse(UpdateNotice.shouldNotify(update(available: true, latest: "v0.2.0", downloading: true), notified: nil))
    }

    func testEmptyLatestIsNotAnnounced() {
        XCTAssertNil(UpdateNotice.announced(update(available: true, latest: "")))
    }
}
