import XCTest
@testable import KeywayCore

final class ReorderTests: XCTestCase {
    private let rows = ["a", "b", "c", "d", "e"]

    func testDropLandsBeforeTheRowBelowTheGap() {
        let p = Reorder.placement(displayed: rows, moving: ["d"], insertAt: 1)
        XCTAssertEqual(p, Reorder.Placement(ids: ["d"], before: "b", after: nil))
    }

    func testDropBelowTheLastRowGoesAfterIt() {
        let p = Reorder.placement(displayed: rows, moving: ["a"], insertAt: 5)
        XCTAssertEqual(p, Reorder.Placement(ids: ["a"], before: nil, after: "e"))
    }

    func testAnchorSkipsRowsThatAreBeingMoved() {
        // dropping the block {b, c} into the gap right above c: c moves too, so the anchor is d
        let p = Reorder.placement(displayed: rows, moving: ["c", "b"], insertAt: 2)
        XCTAssertEqual(p, Reorder.Placement(ids: ["b", "c"], before: "d", after: nil))
        // and at the end, the anchor is the last row that stays
        let q = Reorder.placement(displayed: rows, moving: ["d", "e"], insertAt: 5)
        XCTAssertEqual(q, Reorder.Placement(ids: ["d", "e"], before: nil, after: "c"))
    }

    func testMovedServersKeepTheirOnScreenOrder() {
        let p = Reorder.placement(displayed: rows, moving: ["d", "b"], insertAt: 0)
        XCTAssertEqual(p?.ids, ["b", "d"])
    }

    func testServersOfOtherSectionsAreIgnored() {
        let p = Reorder.placement(displayed: rows, moving: ["x", "c"], insertAt: 0)
        XCTAssertEqual(p, Reorder.Placement(ids: ["c"], before: "a", after: nil))
        XCTAssertNil(Reorder.placement(displayed: rows, moving: ["x", "y"], insertAt: 0))
    }

    func testNothingToDoWhenEveryRowMoves() {
        XCTAssertNil(Reorder.placement(displayed: rows, moving: rows, insertAt: 2))
    }

    func testOutOfRangeGapIsClamped() {
        XCTAssertEqual(Reorder.placement(displayed: rows, moving: ["a"], insertAt: 99)?.after, "e")
        XCTAssertEqual(Reorder.placement(displayed: rows, moving: ["e"], insertAt: -4)?.before, "a")
    }

    func testGroupMembersAppendWithoutDuplicates() {
        XCTAssertEqual(Reorder.members(["a", "b"], adding: ["c", "a", "d", "c"]), ["a", "b", "c", "d"])
        XCTAssertEqual(Reorder.members([], adding: ["x"]), ["x"])
    }

    func testDragPayloadRoundTripsAndIgnoresOtherText() {
        let ids = ["1f27", "a6ec", "eb89"]
        XCTAssertEqual(Reorder.ids(fromDragPayload: Reorder.dragPayload(ids)), ids)
        XCTAssertEqual(Reorder.ids(fromDragPayload: "https://example.com"), [])
        XCTAssertEqual(Reorder.ids(fromDragPayload: Reorder.dragPayload([])), [])
    }
}
