// swift-tools-version:5.10
import PackageDescription

let package = Package(
    name: "Keyway",
    platforms: [.macOS(.v14)],
    products: [.executable(name: "Keyway", targets: ["Keyway"])],
    targets: [
        // API client, models, formatting and form definitions: no UI.
        .target(name: "KeywayCore"),
        .executableTarget(name: "Keyway", dependencies: ["KeywayCore"]),
    ]
)
