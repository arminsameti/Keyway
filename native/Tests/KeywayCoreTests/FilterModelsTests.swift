import XCTest
@testable import KeywayCore

/// The fixtures are the real Go encoder's output (service.FilterView and filters.Catalog),
/// so these tests fail when the backend's JSON shape and the Swift models drift apart.
final class FilterModelsTests: XCTestCase {
    private func fixture(_ name: String) throws -> Data {
        let url = try XCTUnwrap(Bundle.module.url(forResource: name, withExtension: "json", subdirectory: "Fixtures"))
        return try Data(contentsOf: url)
    }

    func testDecodesTheFiltersView() throws {
        let v = try APIClient.decoder.decode(FilterView.self, from: try fixture("filters-view"))
        XCTAssertEqual(v.lists.count, 3)
        let a = v.lists[0]
        XCTAssertEqual(a.list.id, "a1")
        XCTAssertEqual(a.list.catalogKey, "adguard_dns_filter")
        XCTAssertTrue(a.list.enabled)
        XCTAssertEqual(a.status.domains, 94000)
        XCTAssertEqual(a.status.skipped, 12)
        XCTAssertTrue(a.applyOnConnect)
        XCTAssertTrue(a.hasStatus)
        let b = v.lists[1]
        XCTAssertEqual(b.list.url, "https://example.org/my.txt")
        XCTAssertEqual(b.list.updateHours, 12)
        XCTAssertEqual(b.status.lastError, "download failed: 404")
        XCTAssertTrue(b.hasStatus, "an error is a status")
        XCTAssertFalse(v.lists[2].hasStatus, "no download yet")
        XCTAssertTrue(v.needsPolling, "the third list is enabled and has no status yet")
        var settled = v
        settled.lists[2].list.enabled = false
        XCTAssertFalse(settled.needsPolling)
        XCTAssertEqual(v.domains, 94000)
        XCTAssertTrue(v.warn)
        XCTAssertTrue(v.applyOnConnect)
        XCTAssertEqual(v.placeError, "could not place the lists")
        XCTAssertEqual(v.widened, [Widened(allowed: "cdn.x.com", unblocked: "x.com")])
    }

    func testDecodesAnEmptyFiltersView() throws {
        // Go encodes nil slices as null
        let json = #"{"lists":null,"domains":0,"warn":false,"widened":null,"applyOnConnect":false}"#
        let v = try APIClient.decoder.decode(FilterView.self, from: Data(json.utf8))
        XCTAssertTrue(v.lists.isEmpty)
        XCTAssertTrue(v.widened.isEmpty)
    }

    func testDecodesTheCatalog() throws {
        let c = try APIClient.decoder.decode(Catalog.self, from: try fixture("filter-catalog"))
        XCTAssertEqual(c.groups.map(\.name), ["General", "Other", "Regional", "Security"])
        let dns = try XCTUnwrap(c.lists.first { $0.key == "adguard_dns_filter" })
        XCTAssertEqual(dns.group, 1)
        XCTAssertFalse(dns.problematic)
        XCTAssertTrue(dns.languages.isEmpty)
        XCTAssertTrue(dns.downloadURL.hasPrefix("https://"))
        XCTAssertTrue(c.lists.contains { $0.problematic })
        XCTAssertTrue(c.lists.contains { !$0.languages.isEmpty })
        XCTAssertGreaterThan(c.fetchedAt, .distantPast)
    }

    func testSettingsSaveKeepsFilterListsAndAllowedSites() throws {
        var s = AppSettings()
        s.filterLists = [FilterList(id: "", catalogKey: "adguard_dns_filter", name: "AdGuard DNS filter", url: "", enabled: true)]
        s.allowedSites = "cdn.x.com\nexample.org"
        let obj = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(s)) as? [String: Any])
        let lists = try XCTUnwrap(obj["filterLists"] as? [[String: Any]])
        XCTAssertEqual(lists.count, 1)
        XCTAssertEqual(lists[0]["catalogKey"] as? String, "adguard_dns_filter")
        XCTAssertEqual(lists[0]["id"] as? String, "", "a new list is sent with an empty id; the backend assigns it")
        XCTAssertEqual(obj["allowedSites"] as? String, "cdn.x.com\nexample.org")
        // and a decode of what the backend sends gives the same values back
        let back = try JSONDecoder().decode(AppSettings.self, from: JSONSerialization.data(withJSONObject: obj))
        XCTAssertEqual(back, s)
    }

    func testDecodesTheSettingsResult() throws {
        let json = #"{"ok":true,"reconnectRequired":true,"restartRequired":false,"sniffingTurnedOn":true,"warning":"w"}"#
        let r = try JSONDecoder().decode(SettingsResult.self, from: Data(json.utf8))
        XCTAssertTrue(r.sniffingTurnedOn)
        XCTAssertEqual(r.warning, "w")
        let plain = try JSONDecoder().decode(SettingsResult.self, from: Data(#"{"ok":true}"#.utf8))
        XCTAssertFalse(plain.sniffingTurnedOn)
        XCTAssertNil(plain.warning)
    }
}

final class FilterSelectionTests: XCTestCase {
    private func item(_ key: String) throws -> CatalogList {
        let json = #"{"Key":"\#(key)","Name":"Name \#(key)"}"#
        return try JSONDecoder().decode(CatalogList.self, from: Data(json.utf8))
    }

    func testTickingAddsAListWithoutAnIdAndUntickingDropsIt() throws {
        let a = try item("a")
        let on = FilterSelection.setting(a, on: true, in: [])
        XCTAssertEqual(on, [FilterList(id: "", catalogKey: "a", name: "Name a")])
        XCTAssertTrue(FilterSelection.isChosen("a", in: on))
        XCTAssertEqual(FilterSelection.setting(a, on: false, in: on), [])
    }

    func testTickingKeepsTheListsAlreadyChosen() throws {
        let kept = FilterList(id: "x1", catalogKey: "b", name: "B")
        let out = FilterSelection.setting(try item("a"), on: true, in: [kept])
        XCTAssertEqual(out.first, kept, "an existing list keeps its backend id")
        XCTAssertEqual(out.count, 2)
    }

    func testCustomListsAreNamedAfterTheHostAndNotAddedTwice() {
        let once = FilterSelection.adding(url: " https://lists.example.org/ads.txt ", to: [])
        XCTAssertEqual(once.first?.name, "lists.example.org")
        XCTAssertEqual(once.first?.url, "https://lists.example.org/ads.txt")
        XCTAssertEqual(FilterSelection.adding(url: "https://lists.example.org/ads.txt", to: once), once)
        XCTAssertEqual(FilterSelection.custom(once).count, 1)
    }

    func testReapplyingKeepsTheNewIdsAndTheLatestSelection() {
        // tick 1 (a) is saved and got id "n1"; tick 2 (b, a custom url) was queued meanwhile
        var server = AppSettings()
        server.filterLists = [FilterList(id: "n1", catalogKey: "a", name: "A")]
        var wanted = AppSettings()
        wanted.allowedSites = "ok.com"
        wanted.filterLists = [
            FilterList(id: "", catalogKey: "a", name: "A"),
            FilterList(id: "", catalogKey: "b", name: "B"),
            FilterList(id: "", name: "x", url: "https://x.example/l.txt", enabled: false),
        ]
        let out = FilterSelection.reapplying(wanted, onto: server)
        XCTAssertEqual(out.filterLists.map(\.id), ["n1", "", ""], "a is not added twice")
        XCTAssertEqual(out.filterLists.map { $0.catalogKey ?? $0.url ?? "" }, ["a", "b", "https://x.example/l.txt"])
        XCTAssertEqual(out.filterLists.map(\.enabled), [true, true, false])
        XCTAssertEqual(out.allowedSites, "ok.com")
    }

    func testReapplyingDropsWhatTheUserRemovedAndResetsUnknownIds() {
        var server = AppSettings()
        server.blockAds = false
        server.filterLists = [FilterList(id: "n1", catalogKey: "a", name: "A"), FilterList(id: "n2", catalogKey: "b", name: "B")]
        var wanted = AppSettings()
        wanted.filterLists = [FilterList(id: "gone", catalogKey: "c", name: "C"), FilterList(id: "n2", catalogKey: "b", name: "B", enabled: false)]
        let out = FilterSelection.reapplying(wanted, onto: server)
        XCTAssertEqual(out.filterLists.map(\.id), ["", "n2"])
        XCTAssertEqual(out.filterLists.map(\.enabled), [true, false])
        XCTAssertFalse(out.blockAds, "everything else is the server's")
    }

    func testStatusLines() throws {
        let now = Date()
        var v = FilterListView(list: FilterList(id: "1", name: "n"))
        XCTAssertNil(FilterSelection.statusLine(v, now: now))
        v.status.lastError = "HTTP 404"
        XCTAssertEqual(FilterSelection.statusLine(v, now: now), "Couldn't download: HTTP 404")
        v.status.updatedAt = now.addingTimeInterval(-3 * 86400)
        v.status.domains = 1200
        XCTAssertTrue(try XCTUnwrap(FilterSelection.statusLine(v, now: now)).hasPrefix("Couldn't update: HTTP 404. Using the copy from 3 days ago"))
        v.status.lastError = nil
        XCTAssertTrue(try XCTUnwrap(FilterSelection.statusLine(v, now: now)).hasPrefix("\(1200.formatted()) domains"))
    }

    func testSummary() {
        var s = AppSettings()
        XCTAssertEqual(FilterSelection.summary(settings: s, view: FilterView()), "No lists chosen")
        s.filterLists = [FilterList(id: "1", name: "n")]
        XCTAssertEqual(FilterSelection.summary(settings: s, view: FilterView()), "1 list · downloading…")
    }
}
