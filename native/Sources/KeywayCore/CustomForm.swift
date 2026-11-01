import Foundation

/// The "Custom Config" editor: an outbound (or a list of them, or a whole
/// config) written for Xray or sing-box. The app keeps its own inbounds,
/// routing and DNS around it.
public struct CustomForm: Equatable, Sendable {
    public var name = ""
    public var engine = "xray"
    public var config = ""
    public init() {}

    public init(profile: Profile, name: String) {
        self.name = name
        self.engine = profile.custom?.engine ?? "xray"
        self.config = profile.custom?.config ?? ""
    }

    public static let engines = [("xray", "Xray core"), ("sing-box", "sing-box")]

    public static let placeholder = """
    {
      "protocol": "vless",
      "settings": { "vnext": [ … ] },
      "streamSettings": { … }
    }
    """

    public struct FormError: LocalizedError, Equatable { public let message: String; public var errorDescription: String? { message } }

    /// The profile to send; the backend parses the JSON and reports what is wrong.
    public func profile() throws -> (name: String, profile: Profile) {
        let text = config.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { throw FormError(message: "Paste the outbound JSON.") }
        var p = Profile(protocol: "custom")
        p.custom = CustomConfig(engine: engine, config: text)
        return (name.trimmingCharacters(in: .whitespaces), p)
    }
}
