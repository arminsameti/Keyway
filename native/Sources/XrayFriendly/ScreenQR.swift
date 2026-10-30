import CoreGraphics
import Foundation
import ScreenCaptureKit

/// Finds QR codes on the screens ("Scan QR Code on Screen"). macOS asks for
/// Screen Recording permission the first time; nothing leaves this Mac.
enum ScreenQR {
    struct PermissionError: LocalizedError {
        var errorDescription: String? {
            "Xray Friendly needs Screen Recording permission to read a QR code on screen. Allow it in System Settings › Privacy & Security › Screen Recording, or open a screenshot of the code instead."
        }
    }

    static func scan() async throws -> [String] {
        let content: SCShareableContent
        do {
            content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
        } catch {
            throw PermissionError()
        }
        var codes: [String] = []
        for display in content.displays {
            let filter = SCContentFilter(display: display, excludingWindows: [])
            let config = SCStreamConfiguration()
            config.width = display.width * 2
            config.height = display.height * 2
            let image = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: config)
            codes += QR.decode(image)
        }
        return Array(NSOrderedSet(array: codes)) as? [String] ?? codes
    }
}
