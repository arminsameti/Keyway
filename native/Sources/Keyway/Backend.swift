import Foundation

/// Starts the bundled Go backend when none is running and keeps it alive.
/// The backend writes ~/.keyway/api-token and api-port at start.
final class Backend {
    let dataDir = NSHomeDirectory() + "/.keyway"
    private(set) var port = 12345
    private var process: Process?
    private var owned = false
    private var restarts = 0
    var isQuitting = false
    var onCrash: ((String) -> Void)?

    func readFile(_ name: String) -> String? {
        guard let s = try? String(contentsOfFile: dataDir + "/" + name, encoding: .utf8) else { return nil }
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.isEmpty ? nil : t
    }

    var token: String? { readFile("api-token") }

    /// A backend that is already running announces its port; prefer it so a
    /// second instance never overwrites its token file.
    func resolvePort() {
        if let s = readFile("api-port"), let p = Int(s), p > 0 { port = p }
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "-port"), i + 1 < args.count, let p = Int(args[i + 1]) { port = p }
    }

    private func binaryPath() -> String? {
        var candidates: [String] = []
        if let exe = Bundle.main.executablePath {
            candidates.append(((exe as NSString).deletingLastPathComponent as NSString).appendingPathComponent("keywayd"))
        }
        candidates += ["./bin/keywayd", "/opt/homebrew/bin/keywayd", "/usr/local/bin/keywayd"]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    @discardableResult
    func launch() -> Bool {
        guard let bin = binaryPath() else { return false }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["-port", String(port)]
        p.terminationHandler = { [weak self] proc in
            DispatchQueue.main.async { self?.exited(proc) }
        }
        do { try p.run() } catch { return false }
        process = p
        owned = true
        return true
    }

    private func exited(_ proc: Process) {
        guard !isQuitting, owned, proc === process else { return }
        restarts += 1
        if restarts > 3 {
            onCrash?("The backend keeps stopping (exit status \(proc.terminationStatus)). Restart the app to try again.")
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + Double(restarts)) { [weak self] in
            guard let self, !self.isQuitting else { return }
            self.launch()
        }
    }

    func markHealthy() { restarts = 0 }

    /// SIGTERM lets the backend stop the engine and restore the system proxy.
    func stopIfOwned() {
        isQuitting = true
        guard owned, let p = process, p.isRunning else { return }
        p.terminate()
        let deadline = Date().addingTimeInterval(8)
        while p.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.1) }
    }
}
