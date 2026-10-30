// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "XrayFriendly",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "XrayFriendly", targets: ["XrayFriendly"])],
    targets: [
        // API client, models, formatting and form definitions: no UI, unit-tested.
        .target(name: "XrayFriendlyCore"),
        .executableTarget(name: "XrayFriendly", dependencies: ["XrayFriendlyCore"]),
        .testTarget(name: "XrayFriendlyCoreTests", dependencies: ["XrayFriendlyCore"]),
    ]
)
