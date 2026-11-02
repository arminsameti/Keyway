import AppKit
import SwiftUI
import KeywayCore

extension Color {
    /// A color with separate light and dark appearances (hex RGB).
    init(light: UInt32, dark: UInt32) {
        self.init(nsColor: NSColor(name: nil) { appearance in
            let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            let v = isDark ? dark : light
            return NSColor(srgbRed: CGFloat((v >> 16) & 0xFF) / 255, green: CGFloat((v >> 8) & 0xFF) / 255,
                           blue: CGFloat(v & 0xFF) / 255, alpha: 1)
        })
    }
}

/// Design palette: values live in KeywayCore.DesignColors, where the
/// contrast of every text/background pair is unit-tested.
enum Palette {
    private typealias D = DesignColors
    private static func c(_ p: ColorPair) -> Color { Color(light: p.light, dark: p.dark) }

    static let accent = c(D.accent)
    static let accentText = c(D.accentText)
    static let green = c(D.green)
    static let greenText = c(D.greenText)
    static let warn = c(D.warn)
    static let error = c(D.error)
    static let secondary = c(D.secondary)
    static let tertiary = c(D.tertiary)
    static let separator = c(D.separator)
    static let cardBorder = c(D.cardBorder)
    static let card = c(D.card)
    static let inspector = c(D.inspector)
    static let badge = c(D.badge)
    static let connectedCard = c(D.connectedCard)
    static let connectedBorder = c(D.connectedBorder)
    static let idleCard = c(D.idleCard)
    static let idleShield = c(D.idleShield)
    static let selection = c(D.selection)
    static let xrayBadge = (fg: c(D.xrayBadgeText), bg: c(D.xrayBadgeFill))
    static let singBoxBadge = (fg: c(D.singBoxBadgeText), bg: c(D.singBoxBadgeFill))
    static let v2rayBadge = (fg: c(D.v2rayBadgeText), bg: c(D.v2rayBadgeFill))

    static func latency(_ ms: Int) -> (fg: Color, bg: Color) {
        switch LatencyClass(ms: ms) {
        case .fast: return (greenText, c(D.latencyFastFill))
        case .ok: return (warn, c(D.latencyOKFill))
        case .slow, .timeout: return (error, c(D.latencySlowFill))
        case .notApplicable, .unknown: return (c(D.latencyNAText), c(D.latencyNAFill))
        }
    }

    static func engineBadge(_ engine: String) -> (fg: Color, bg: Color) {
        switch engine {
        case "sing-box": singBoxBadge
        case "v2ray": v2rayBadge
        default: xrayBadge
        }
    }
}
