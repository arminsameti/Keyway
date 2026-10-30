import AppKit
import SwiftUI
import XrayFriendlyCore

/// What the server editor window edits.
enum EditorTarget: Codable, Hashable {
    case new
    case edit(String) // node ID
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    var model: AppModel?

    func applicationDidFinishLaunching(_ notification: Notification) {
        if let i = CommandLine.arguments.firstIndex(of: "--snapshot"), i + 1 < CommandLine.arguments.count {
            MainActor.assumeIsolated { Snapshots.renderAll(to: CommandLine.arguments[i + 1]) }
            exit(0)
        }
        Activation.install()
    }

    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { model?.shutdown() }
    }

    // Keep running in the menu bar when the last window closes.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
}

@main
struct XrayFriendlyApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @State private var model = AppModel()

    var body: some Scene {
        Window("Xray Friendly", id: "main") {
            MainView()
                .environment(model)
                .onAppear {
                    delegate.model = model
                    model.start()
                    Activation.bringForward()
                }
                .frame(minWidth: 940, minHeight: 600)
        }
        .defaultSize(width: 1240, height: 780)
        .commands { AppCommands(model: model) }

        WindowGroup("Server", id: "server", for: EditorTarget.self) { $target in
            NewServerView(target: target ?? .new)
                .environment(model)
                .onAppear(perform: Activation.bringForward)
        }
        .windowResizability(.contentSize)
        .defaultSize(width: 760, height: 720)

        Window("Welcome to Xray Friendly", id: "onboarding") {
            OnboardingView()
                .environment(model)
                .onAppear(perform: Activation.bringForward)
        }
        .windowResizability(.contentSize)

        MenuBarExtra {
            MenuBarView()
                .environment(model)
                .onAppear { model.start() }
        } label: {
            Image(systemName: model.connected ? "checkmark.shield" : "shield")
                .accessibilityLabel(model.connected ? "Xray Friendly, connected" : "Xray Friendly, not connected")
        }
        .menuBarExtraStyle(.window)

        Settings {
            SettingsView()
                .environment(model)
                .onAppear(perform: Activation.bringForward)
        }
    }
}

/// Menu commands and the keyboard shortcuts from the design.
struct AppCommands: Commands {
    let model: AppModel
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("Add Servers…") { openWindow(id: "main"); model.openImport() }
                .keyboardShortcut("n")
            Button("New Server…") { openWindow(id: "server", value: EditorTarget.new) }
                .keyboardShortcut("n", modifiers: [.command, .option])
            Button("Add Servers from Clipboard") { openWindow(id: "main"); model.addFromClipboard() }
                .keyboardShortcut("v", modifiers: [.command, .shift])
        }
        CommandMenu("Server") {
            Button("Test Latency") { model.testLatency() }
                .keyboardShortcut("t")
            Button("TCP Quick Test") { model.testLatency("tcp") }
            Button("Real Test") { model.testLatency("real") }
            Divider()
            Button(model.connected ? "Disconnect" : "Connect") { model.toggleConnection() }
                .keyboardShortcut("k")
            Button("Pick Fastest Now") { model.pickFastest() }
        }
        CommandGroup(after: .textEditing) {
            Button("Find Servers") { openWindow(id: "main"); model.sidebar = .servers; model.focusSearch = true }
                .keyboardShortcut("f")
        }
        CommandGroup(after: .windowArrangement) {
            Button("Open Xray Friendly") { openWindow(id: "main"); Activation.bringForward() }
                .keyboardShortcut("o")
        }
    }
}
