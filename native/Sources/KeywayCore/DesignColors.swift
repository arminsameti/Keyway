import Foundation

/// A color with light and dark appearances, as 0xRRGGBB.
public struct ColorPair: Sendable, Equatable {
    public let light: UInt32
    public let dark: UInt32
    public init(_ light: UInt32, _ dark: UInt32) { self.light = light; self.dark = dark }
}

/// The design palette (DESIGN_HANDOFF.md). Light values are the mockup hexes
/// unless a mockup value failed 4.5:1 on a real macOS background (noted).
/// Dark values follow the MenuBar mockup's dark tweak. ContrastTests checks
/// every text/background pair the UI uses.
public enum DesignColors {
    public static let accent = ColorPair(0x0064D2, 0x0064D2)     // fills with white text
    public static let accentText = ColorPair(0x0064D2, 0x6CB0FF) // accent as text
    public static let green = ColorPair(0x28A745, 0x30D158)      // fills, switches
    /// Mockup #1A7F37 is 4.30:1 on macOS's window background (#ECECEC) and
    /// 4.45:1 on the "Fast" fill; #1A7A35 passes both.
    public static let greenText = ColorPair(0x1A7A35, 0x5BDB7A)
    public static let warn = ColorPair(0xA64B00, 0xFFB25C)
    public static let error = ColorPair(0xB3261E, 0xFF8A80)
    /// Mockup #6E6E73 is 4.29:1 on macOS's window background (#ECECEC); #68686D passes.
    public static let secondary = ColorPair(0x68686D, 0xA1A1A8)
    public static let tertiary = ColorPair(0x48484D, 0xC7C7CC)
    public static let separator = ColorPair(0xE5E5EA, 0x3A3A3C)
    public static let cardBorder = ColorPair(0xE2E2E7, 0x3A3A3C)
    public static let card = ColorPair(0xFFFFFF, 0x2A2A2D)
    public static let inspector = ColorPair(0xFAFAFC, 0x232325)
    public static let badge = ColorPair(0xEDEDF0, 0x3A3A3C)
    public static let connectedCard = ColorPair(0xF1F9F3, 0x1C2E21)
    public static let connectedBorder = ColorPair(0xCDE9D5, 0x2E5238)
    public static let idleCard = ColorPair(0xF6F6F8, 0x262628)
    public static let idleShield = ColorPair(0x9A9AA0, 0x6E6E73)
    public static let selection = ColorPair(0xDCE8F8, 0x1D3557)
    public static let xrayBadgeText = ColorPair(0x0057B8, 0x8CBEFF)
    public static let xrayBadgeFill = ColorPair(0xE6F0FC, 0x1A2A40)
    public static let singBoxBadgeText = ColorPair(0x5B36B5, 0xC4B0FF)
    public static let singBoxBadgeFill = ColorPair(0xEFEAFB, 0x2D2445)
    public static let v2rayBadgeText = ColorPair(0x00695C, 0x7FD8C8)
    public static let v2rayBadgeFill = ColorPair(0xE0F4F1, 0x16352F)
    public static let latencyFastFill = ColorPair(0xE4F4E8, 0x1F3A27)
    public static let latencyOKFill = ColorPair(0xFFEFDB, 0x40301A)
    public static let latencySlowFill = ColorPair(0xFDE8E8, 0x46201E)
    public static let latencyNAText = ColorPair(0x5A5A5F, 0xA1A1A8)
    public static let latencyNAFill = ColorPair(0xEFEFF2, 0x2C2C2E)

    /// macOS window backgrounds the palette is drawn on (not settable here).
    public static let systemWindow = ColorPair(0xECECEC, 0x323232)
    public static let systemContent = ColorPair(0xFFFFFF, 0x1E1E1E)

    /// WCAG 2 contrast ratio between two sRGB colors.
    public static func contrast(_ a: UInt32, _ b: UInt32) -> Double {
        func lum(_ c: UInt32) -> Double {
            func ch(_ v: UInt32) -> Double {
                let s = Double(v) / 255
                return s <= 0.03928 ? s / 12.92 : pow((s + 0.055) / 1.055, 2.4)
            }
            return 0.2126 * ch((c >> 16) & 0xFF) + 0.7152 * ch((c >> 8) & 0xFF) + 0.0722 * ch(c & 0xFF)
        }
        let (l1, l2) = (lum(a), lum(b))
        return (max(l1, l2) + 0.05) / (min(l1, l2) + 0.05)
    }
}
