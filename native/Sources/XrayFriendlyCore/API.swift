import Foundation

/// An error the backend reported ({"ok":false,"error":"..."}) or a transport failure.
public struct APIError: LocalizedError, Equatable, Sendable {
    public let message: String
    public let status: Int
    public init(_ message: String, status: Int = 0) { self.message = message; self.status = status }
    public var errorDescription: String? { message }
}

/// Talks to the local Go backend. Every request carries the per-launch token
/// the backend writes to ~/.xray-friendly/api-token.
public final class APIClient: @unchecked Sendable {
    public let port: Int
    private let token: String
    private let session: URLSession

    public init(port: Int, token: String, session: URLSession = .shared) {
        self.port = port
        self.token = token
        self.session = session
    }

    public static let decoder: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { dec in
            let s = try dec.singleValueContainer().decode(String.self)
            if let date = parseDate(s) { return date }
            throw DecodingError.dataCorrupted(.init(codingPath: dec.codingPath, debugDescription: "bad date \(s)"))
        }
        return d
    }()

    /// Go's RFC 3339 with optional fractional seconds; Go's zero time maps to distantPast.
    public static func parseDate(_ s: String) -> Date? {
        if s.hasPrefix("0001-01-01") { return .distantPast }
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = f.date(from: s) { return d }
        f.formatOptions = [.withInternetDateTime]
        return f.date(from: s)
    }

    // MARK: transport

    public func raw(_ method: String, _ path: String, body: (any Encodable)? = nil, timeout: TimeInterval = 30) async throws -> Data {
        guard let url = URL(string: "http://127.0.0.1:\(port)\(path)") else { throw APIError("bad path") }
        var req = URLRequest(url: url, timeoutInterval: timeout)
        req.httpMethod = method
        req.setValue(token, forHTTPHeaderField: "X-XF-Token")
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try JSONEncoder().encode(AnyEncodable(body))
        }
        let (data, resp) = try await session.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        if code >= 400 {
            let msg = (try? JSONDecoder().decode(ErrorBody.self, from: data))?.error ?? HTTPURLResponse.localizedString(forStatusCode: code)
            throw APIError(msg, status: code)
        }
        return data
    }

    public func get<T: Decodable>(_ path: String, as: T.Type = T.self) async throws -> T {
        try Self.decoder.decode(T.self, from: try await raw("GET", path))
    }

    public func post<T: Decodable>(_ path: String, _ body: (any Encodable)? = nil, as: T.Type = T.self, timeout: TimeInterval = 30) async throws -> T {
        try Self.decoder.decode(T.self, from: try await raw("POST", path, body: body ?? [String: String](), timeout: timeout))
    }

    // MARK: endpoints

    public func status() async throws -> Status { try await get("/api/status") }
    public func importRules(_ text: String) async throws -> ImportedRules { try await post("/api/routing/import", ["text": text]) }

    public func testRoute(host: String, port: Int, rules: [RouteRule]) async throws -> RouteMatch {
        struct Body: Encodable { var host: String; var port: Int; var rules: [RouteRule] }
        struct Reply: Decodable { var match: RouteMatch }
        return try await post("/api/routing/test", Body(host: host, port: port, rules: rules), as: Reply.self).match
    }

    public func nodeConfig(_ id: String) async throws -> ConfigPreview { try await get("/api/nodes/\(id)/config") }

    public func tunHelper() async throws -> TUNHelper { try await get("/api/tun/helper", as: TUNHelperBody.self).helper }
    public func setTunHelper(install: Bool) async throws -> TUNHelper {
        try await post("/api/tun/helper", ["action": install ? "install" : "uninstall"], as: TUNHelperBody.self, timeout: 200).helper
    }

    public func traffic() async throws -> Traffic { try await get("/api/traffic") }
    public func state() async throws -> AppSnapshot { try await get("/api/state") }
    public func settings() async throws -> AppSettings { try await get("/api/settings") }
    public func engines() async throws -> [EngineInfo] { try await get("/api/engines", as: EnginesBody.self).engines }
    public func jobs() async throws -> [Job] { try await get("/api/jobs", as: JobsBody.self).jobs }
    public func job(_ id: String) async throws -> Job { try await get("/api/jobs/\(id)", as: JobBody.self).job }

    public func connect() async throws { _ = try await raw("POST", "/api/connect", body: [String: String](), timeout: 130) }
    public func disconnect() async throws { _ = try await raw("POST", "/api/disconnect", body: [String: String]()) }
    public func setActive(_ id: String) async throws { _ = try await raw("POST", "/api/active", body: ["id": id]) }
    public func delete(_ ids: [String]) async throws { _ = try await raw("POST", "/api/nodes/delete", body: ["ids": ids]) }

    public func latency(mode: String) async throws -> [String: Int] {
        try await post("/api/latency", ["mode": mode], as: LatencyBody.self, timeout: 130).latency
    }

    public func pickFastest(reconnect: Bool) async throws -> PickResult {
        try await post("/api/pick-fastest", PickRequest(reconnect: reconnect), timeout: 130)
    }

    public func preview(_ text: String) async throws -> ImportPreview { try await post("/api/import/preview", ["text": text]) }
    public func importText(_ text: String) async throws -> ImportResult { try await post("/api/import", ["text": text], timeout: 60) }

    public func parseLink(_ link: String) async throws -> ProfileBody { try await post("/api/links/parse", ["link": link]) }
    public func nodeProfile(_ id: String) async throws -> ProfileBody { try await get("/api/nodes/\(id)/profile") }
    public func createNode(name: String, profile: Profile, overrides: ServerOverrides? = nil) async throws -> Node {
        try await post("/api/nodes", NodeInput(name: name, profile: profile, overrides: overrides?.cleaned), as: NodeBody.self).node
    }
    public func updateNode(_ id: String, name: String, profile: Profile, overrides: ServerOverrides? = nil) async throws -> Node {
        let data = try await raw("PUT", "/api/nodes/\(id)", body: NodeInput(name: name, profile: profile, overrides: overrides?.cleaned))
        return try Self.decoder.decode(NodeBody.self, from: data).node
    }
    public func testServer(name: String, profile: Profile, overrides: ServerOverrides? = nil) async throws -> Int {
        try await post("/api/nodes/test", NodeInput(name: name, profile: profile, overrides: overrides?.cleaned), as: TestBody.self, timeout: 60).latencyMs
    }

    // chains: other servers, entry first
    public func createChain(name: String, hops: [String]) async throws -> Node {
        try await post("/api/nodes", NodeInput(name: name, chain: hops), as: NodeBody.self).node
    }
    public func updateChain(_ id: String, name: String, hops: [String]) async throws -> Node {
        let data = try await raw("PUT", "/api/nodes/\(id)", body: NodeInput(name: name, chain: hops))
        return try Self.decoder.decode(NodeBody.self, from: data).node
    }
    /// What saving the chain would do: whether it is valid and which engines run it.
    /// Throws the backend's reason when the chain is not valid.
    public func planChain(hops: [String]) async throws -> ChainPlan {
        try await post("/api/chains/plan", ["chain": hops], as: ChainPlanBody.self).plan
    }
    /// A chain sets up a tunnel per hop and is measured twice (a warm-up first).
    public func testChain(hops: [String]) async throws -> Int {
        try await post("/api/nodes/test", NodeInput(name: "", chain: hops), as: TestBody.self, timeout: 180).latencyMs
    }

    public func refreshSubscription(_ id: String) async throws { _ = try await raw("POST", "/api/subscriptions/\(id)/refresh", body: [String: String](), timeout: 90) }
    public func refreshAllSubscriptions() async throws { _ = try await raw("POST", "/api/subscriptions/refresh", body: [String: String](), timeout: 180) }
    public func deleteSubscription(_ id: String) async throws { _ = try await raw("DELETE", "/api/subscriptions/\(id)") }

    public func saveSettings(_ s: AppSettings) async throws { _ = try await raw("POST", "/api/settings", body: s) }
    public func setSystemProxy(_ on: Bool) async throws { _ = try await raw("POST", "/api/sysproxy", body: ["on": on]) }
    public func logs(since: Int) async throws -> LogsBody { try await get("/api/logs?since=\(since)") }

    public func startDownload(engine: String, version: String = "") async throws -> Job {
        try await post("/api/engines/\(engine)/download", DownloadRequest(version: version, async: true), as: JobBody.self).job
    }
    public func checkEngine(_ engine: String) async throws { _ = try await raw("POST", "/api/engines/\(engine)/check", body: [String: String](), timeout: 60) }
    public func useEngine(_ engine: String, version: String) async throws { _ = try await raw("POST", "/api/engines/\(engine)/use", body: ["version": version]) }
    public func releases(_ engine: String) async throws -> [Release] { try await get("/api/engines/\(engine)/releases", as: ReleasesBody.self).releases }
}

// MARK: request/response bodies

struct ErrorBody: Decodable { let error: String }
struct EnginesBody: Decodable { let engines: [EngineInfo] }
struct JobsBody: Decodable { let jobs: [Job] }
struct JobBody: Decodable { let job: Job }
struct LatencyBody: Decodable { let latency: [String: Int] }
struct NodeBody: Decodable { let node: Node }
struct TUNHelperBody: Decodable { let helper: TUNHelper }
struct TestBody: Decodable { let latencyMs: Int }
struct ChainPlanBody: Decodable { let plan: ChainPlan }
struct ReleasesBody: Decodable { let releases: [Release] }
struct PickRequest: Encodable { let reconnect: Bool }
struct DownloadRequest: Encodable { let version: String; let async: Bool }
struct NodeInput: Encodable {
    let name: String
    var profile: Profile?
    var chain: [String]?
    var overrides: ServerOverrides?
}

public struct ChainPlan: Decodable, Equatable, Sendable {
    public let engine: String
    public let engineName: String // every engine, in order: "sing-box + Xray core"
    public let processes: Int
    public let installed: Bool
    public init(engine: String, engineName: String, processes: Int, installed: Bool) {
        self.engine = engine; self.engineName = engineName; self.processes = processes; self.installed = installed
    }
}

public struct PickResult: Decodable, Sendable { public let name: String?; public let latencyMs: Int? }
public struct ImportResult: Decodable, Sendable { public let added: Int; public let errors: [String] }
/// A node in editable form: a server's profile, or a chain's hop IDs.
public struct ProfileBody: Decodable, Sendable {
    public let profile: Profile?
    public let chain: [String]?
    public let overrides: ServerOverrides?
    public let name: String
}
public struct LogsBody: Decodable, Sendable { public let logs: [String]; public let next: Int; public let running: Bool }

struct AnyEncodable: Encodable {
    let value: any Encodable
    init(_ v: any Encodable) { value = v }
    func encode(to encoder: Encoder) throws { try value.encode(to: encoder) }
}
