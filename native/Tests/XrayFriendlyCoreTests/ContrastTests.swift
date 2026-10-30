import XCTest
@testable import XrayFriendlyCore

/// Acceptance: text contrast ≥ 4.5:1 in light and dark mode, for every
/// text/background pair the UI draws (DESIGN_HANDOFF.md checklist).
final class ContrastTests: XCTestCase {
    typealias C = DesignColors
    static let white = ColorPair(0xFFFFFF, 0xFFFFFF)

    /// (name, text, background)
    static let pairs: [(String, ColorPair, ColorPair)] = [
        ("secondary on window", C.secondary, C.systemWindow),
        ("secondary on content", C.secondary, C.systemContent),
        ("secondary on card", C.secondary, C.card),
        ("secondary on idle card", C.secondary, C.idleCard),
        ("secondary on connected card", C.secondary, C.connectedCard),
        ("secondary on inspector", C.secondary, C.inspector),
        ("tertiary on card", C.tertiary, C.card),
        ("tertiary on window", C.tertiary, C.systemWindow),
        ("tertiary on badge", C.tertiary, C.badge),
        ("green text on connected card", C.greenText, C.connectedCard),
        ("green text on content", C.greenText, C.systemContent),
        ("green text on window", C.greenText, C.systemWindow),
        ("green text on inspector", C.greenText, C.inspector),
        ("fast latency", C.greenText, C.latencyFastFill),
        ("ok latency", C.warn, C.latencyOKFill),
        ("slow latency", C.error, C.latencySlowFill),
        ("n/a latency", C.latencyNAText, C.latencyNAFill),
        ("warning on window", C.warn, C.systemWindow),
        ("warning on card", C.warn, C.card),
        ("error on card", C.error, C.card),
        ("accent text on content", C.accentText, C.systemContent),
        ("accent text on window", C.accentText, C.systemWindow),
        ("accent text on inspector", C.accentText, C.inspector),
        ("white on accent", white, C.accent),
        ("Xray badge", C.xrayBadgeText, C.xrayBadgeFill),
        ("sing-box badge", C.singBoxBadgeText, C.singBoxBadgeFill),
    ]

    func testTextContrast() {
        for (name, fg, bg) in Self.pairs {
            let light = DesignColors.contrast(fg.light, bg.light)
            let dark = DesignColors.contrast(fg.dark, bg.dark)
            XCTAssertGreaterThanOrEqual(light, 4.5, "\(name) (light): \(String(format: "%.2f", light)):1")
            XCTAssertGreaterThanOrEqual(dark, 4.5, "\(name) (dark): \(String(format: "%.2f", dark)):1")
        }
    }

    func testContrastFormula() {
        XCTAssertEqual(DesignColors.contrast(0x000000, 0xFFFFFF), 21, accuracy: 0.01)
        XCTAssertEqual(DesignColors.contrast(0x0064D2, 0xFFFFFF), 5.6, accuracy: 0.1) // the spec's reason for #0064D2
    }
}
