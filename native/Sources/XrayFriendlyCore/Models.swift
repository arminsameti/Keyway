import Foundation

// Codable mirrors of the backend's JSON (internal/service, internal/models).

public struct Status: Codable, Equatable, Sendable {
    public var running = false
    public var startedAt: Date?
    public var lastExit: String?
    public var activeNode = ""
    public var activeNodeId = ""
    public var activeCountryCode: String?
    public var activeLatencyMs: Int = -1
    public var `protocol`: String?
    public var transport: String?
    public var engine: String?
    public var engineVersion: String?
    public var engineLabel: String? // every engine of the connection, e.g. "sing-box + Xray core"
    public var uptimeSec: Int = 0
    public var routingMode = "bypass-private"
    public var autoPick = false
    public var systemProxyServices: [String] = []
    public var systemProxyOn = false
    public init() {}
}

public struct Node: Codable, Identifiable, Hashable, Sendable {
    public var id: String
    public var name: String
    public var `protocol`: String
    public var server: String
    public var port: Int
    public var rawLink: String?
    public var source: String?
    public var latencyMs: Int
    public var displayName: String
    public var countryCode: String?
    public var protocolName: String
    public var transport: String
    public var security: String
    public var sni: String
    public var udp: Bool
    public var engine: String?
    public var engineName: String?
    public var engineInstalled: Bool
    public var engineReason: String?
    public var hasLink: Bool
    public var error: String?
    public var chain: Bool?
    public var hops: [HopInfo]?
    public var relaysUdp: Bool?
    public var overrides: ServerOverrides?

    public var isChain: Bool { chain ?? false }
    public var hopList: [HopInfo] { hops ?? [] }
    /// Can carry UDP for a following hop of a chain.
    public var canRelayUDP: Bool { relaysUdp ?? false }

    public init(id: String, name: String, protocol: String, server: String, port: Int, rawLink: String? = nil,
                source: String? = nil, latencyMs: Int = -1, displayName: String? = nil, countryCode: String? = nil,
                protocolName: String? = nil, transport: String = "TCP", security: String = "TLS", sni: String = "—",
                udp: Bool = false, engine: String? = "xray", engineName: String? = "Xray core", engineInstalled: Bool = true,
                engineReason: String? = nil, hasLink: Bool = true, error: String? = nil,
                chain: Bool = false, hops: [HopInfo]? = nil, relaysUdp: Bool = false) {
        self.id = id; self.name = name; self.protocol = `protocol`; self.server = server; self.port = port
        self.rawLink = rawLink; self.source = source; self.latencyMs = latencyMs
        self.displayName = displayName ?? name; self.countryCode = countryCode
        self.protocolName = protocolName ?? `protocol`; self.transport = transport; self.security = security
        self.sni = sni; self.udp = udp; self.engine = engine; self.engineName = engineName
        self.engineInstalled = engineInstalled; self.engineReason = engineReason; self.hasLink = hasLink; self.error = error
        self.chain = chain; self.hops = hops; self.relaysUdp = relaysUdp
    }
}

/// One server of a chain, entry first.
public struct HopInfo: Codable, Hashable, Sendable, Identifiable {
    public var id: String
    public var name: String
    public var countryCode: String?
    public var protocolName: String
    public var transport: String?
    public var missing: Bool
    public init(id: String, name: String, countryCode: String? = nil, protocolName: String, transport: String? = nil, missing: Bool = false) {
        self.id = id; self.name = name; self.countryCode = countryCode; self.protocolName = protocolName
        self.transport = transport; self.missing = missing
    }
}

public struct Subscription: Codable, Identifiable, Hashable, Sendable {
    public var id: String
    public var name: String
    public var url: String
    public var updatedAt: Date?
    public var nodeCount: Int
    public var lastError: String?
    public var format: String?
    public init(id: String, name: String, url: String, updatedAt: Date? = nil, nodeCount: Int = 0, lastError: String? = nil, format: String? = nil) {
        self.id = id; self.name = name; self.url = url; self.updatedAt = updatedAt; self.nodeCount = nodeCount
        self.lastError = lastError; self.format = format
    }
}

public struct Inbound: Codable, Hashable, Sendable {
    public var tag: String
    public var `protocol`: String
    public var port: Int
    public var listen: String
    public var udp: Bool
    public var username: String?
    public var password: String?
    public var enabled: Bool
    public init(tag: String, protocol p: String, port: Int, listen: String, udp: Bool, username: String? = nil, password: String? = nil, enabled: Bool) {
        self.tag = tag; self.protocol = p; self.port = port; self.listen = listen; self.udp = udp
        self.username = username; self.password = password; self.enabled = enabled
    }
}

public struct AppSettings: Codable, Equatable, Sendable {
    public var inbounds: [Inbound] = []
    public var routingMode = "bypass-private"
    public var blockAds = true
    public var directSites = ""
    public var proxySites = ""
    public var blockedSites = ""
    public var dns: [String] = []
    public var logLevel = "warning"
    public var mux = false
    public var muxConcurrency = 8
    public var allowLan = false
    public var sniffing = true
    public var apiPort = 12345
    public var autoPick = false
    public var autoPickMin = 10
    public var autoConnect = false
    public var autoSystemProxy = false
    public var subUpdateHours = 24
    public var enginePreference = "xray"
    public var autoDownloadEngines = true
    public var engineUpdateCheck = "weekly"
    public var latencyMethod = "real"
    public var ruleSets: [RuleSet] = []
    public var activeRuleSet = ""
    public init() {}

    /// The first enabled inbound of a protocol ("socks", "http").
    public func port(of proto: String) -> Int? {
        inbounds.first { $0.protocol == proto && $0.enabled }?.port
    }
}

public struct EngineInfo: Codable, Identifiable, Hashable, Sendable {
    public var id: String { name }
    public var name: String
    public var displayName: String
    public var installed: [String]
    public var active: String
    public var version: String
    public var latest: String?
    public var updateAvailable: Bool
    public var checkedAt: Date?
    public var checkError: String?
    public var protocols: [String]
    public init(name: String, displayName: String, installed: [String], active: String, version: String, latest: String?,
                updateAvailable: Bool, checkedAt: Date?, checkError: String?, protocols: [String]) {
        self.name = name; self.displayName = displayName; self.installed = installed; self.active = active; self.version = version
        self.latest = latest; self.updateAvailable = updateAvailable; self.checkedAt = checkedAt; self.checkError = checkError
        self.protocols = protocols
    }
}

public struct Release: Codable, Hashable, Sendable {
    public var tag: String
    public var name: String?
    public var installed: Bool
    enum CodingKeys: String, CodingKey { case tag = "tag_name", name, installed }
}

public struct Job: Codable, Identifiable, Hashable, Sendable {
    public var id: String
    public var engine: String
    public var version: String?
    public var state: String // running done failed
    public var done: Int64
    public var total: Int64
    public var error: String?
    /// 0...1, or nil while the size is unknown.
    public var fraction: Double? { total > 0 ? min(1, Double(done) / Double(total)) : nil }
    public init(id: String, engine: String, version: String?, state: String, done: Int64, total: Int64, error: String?) {
        self.id = id; self.engine = engine; self.version = version; self.state = state; self.done = done; self.total = total; self.error = error
    }
}

public struct PreviewItem: Codable, Hashable, Sendable, Identifiable {
    public var id: String { "\(line)-\(name)-\(status)" }
    public var line: Int
    public var status: String // ready subscription skipped
    public var scheme: String?
    public var name: String
    public var countryCode: String?
    public var `protocol`: String?
    public var transport: String?
    public var engine: String?
    public var engineName: String?
    public var engineInstalled: Bool
    public var duplicate: Bool
    public var reason: String?
    public init(line: Int, status: String, scheme: String?, name: String, countryCode: String?, protocol p: String?, transport: String?,
                engine: String?, engineName: String?, engineInstalled: Bool, duplicate: Bool, reason: String?) {
        self.line = line; self.status = status; self.scheme = scheme; self.name = name; self.countryCode = countryCode
        self.protocol = p; self.transport = transport; self.engine = engine; self.engineName = engineName
        self.engineInstalled = engineInstalled; self.duplicate = duplicate; self.reason = reason
    }
}

public struct ImportPreview: Codable, Equatable, Sendable {
    public var items: [PreviewItem] = []
    public var ready = 0
    public var subscriptions = 0
    public var skipped = 0
    public init() {}
}

public struct AppSnapshot: Codable, Sendable {
    public var nodes: [Node]
    public var activeNodeId: String
    public var settings: AppSettings
    public var engines: [EngineInfo]
    public var subscriptions: [Subscription]
    public var running: Bool
    public var warning: String?
    public var systemProxyServices: [String]
}

public struct SysProxy: Codable, Sendable {
    public var supported: Bool
    public var services: [String]
    public var primary: String
    public var enabled: [String]
}

// MARK: engine-neutral server description (internal/profile)

public struct Profile: Codable, Equatable, Sendable {
    public var `protocol`: String
    public var server: String = ""
    public var port: Int = 0
    public var uuid: String?
    public var username: String?
    public var password: String?
    public var flow: String?
    public var encryption: String?
    public var alterId: Int?
    public var cipher: String?
    public var transport: Transport = .init()
    public var security: Security = .init()
    public var hysteria: Hysteria?
    public var wireguard: WireGuard?
    public var tuic: TUIC?
    public var shadowtls: ShadowTLS?
    public var ssh: SSH?
    public var anytls: AnyTLS?
    public var naive: Naive?
    public var openvpn: OpenVPN?
    public var custom: CustomConfig?
    public init(protocol p: String) { self.protocol = p }

    /// An OpenVPN client profile (TLS mode). Certificates and keys are PEM
    /// text. Every field of the backend's profile is kept so that editing an
    /// imported .ovpn never drops an option the form does not show.
    public struct OpenVPN: Codable, Equatable, Sendable {
        public var remotes: [Remote]?
        public var remoteRandom: Bool?
        public var ca: String?
        public var cert: String?
        public var key: String?
        public var peerFingerprint: [String]?
        public var needsCredential: Bool?
        public var controlWrap: ControlWrap?
        public var dataCiphers: [String]?
        public var cipher: String?
        public var auth: String?
        public var compression: String?
        public var compLzo: String?
        public var remoteCertTls: String?
        public var verifyName: String?
        public var verifyNameType: String?
        public var tlsVersionMin: String?
        public var renegSec: Int?
        public var pingInterval: Int?
        public var pingRestart: Int?
        public var mssfix: Int?
        public var fragment: Int?
        public var routeNoPull: Bool?
        public var topology: String?
        public init() {}

        public struct Remote: Codable, Equatable, Sendable {
            public var server: String
            public var port: Int
            public var network: String?
        }
        public struct ControlWrap: Codable, Equatable, Sendable {
            public var type: String // tls_auth | tls_crypt | tls_crypt_v2
            public var key: String
            public var direction: String?
            public init(type: String, key: String, direction: String? = nil) { self.type = type; self.key = key; self.direction = direction }
        }
    }

    public struct Transport: Codable, Equatable, Sendable {
        public var type: String = ""
        public var path: String?
        public var host: String?
        public var serviceName: String?
        public var authority: String?
        public var mode: String?
        public var headerType: String?
        public var seed: String?
        public init() {}
    }
    public struct Security: Codable, Equatable, Sendable {
        public var kind: String = ""
        public var sni: String?
        public var alpn: [String]?
        public var fingerprint: String?
        public var insecure: Bool?
        public var pinSha256: String?
        public var publicKey: String?
        public var shortId: String?
        public var spiderX: String?
        public init() {}
    }
    public struct Hysteria: Codable, Equatable, Sendable {
        public var upMbps: Int?
        public var downMbps: Int?
        public var obfs: String?
        public var obfsPassword: String?
        public init() {}
    }
    public struct WireGuard: Codable, Equatable, Sendable {
        public var privateKey: String = ""
        public var peerPublicKey: String = ""
        public var preSharedKey: String?
        public var localAddress: [String] = []
        public var mtu: Int?
        public var reserved: [Int]?
        public var allowedIps: [String]?
        public var keepalive: Int?
        public init() {}
    }
    public struct TUIC: Codable, Equatable, Sendable {
        public var congestionControl: String?
        public var udpRelayMode: String?
        public var zeroRtt: Bool?
        public init() {}
    }
    public struct ShadowTLS: Codable, Equatable, Sendable {
        public var version: Int = 3
        public var password: String = ""
        public var sni: String = ""
        public init() {}
    }
    public struct SSH: Codable, Equatable, Sendable {
        public var privateKeyPath: String?
        public var privateKey: String?
        public var passphrase: String?
        public var hostKeys: [String]?
        public init() {}
    }
    public struct AnyTLS: Codable, Equatable, Sendable {
        public var idleTimeoutSec: Int?
        public init() {}
    }
    public struct Naive: Codable, Equatable, Sendable {
        public var extraHeaders: [String: String]?
        public init() {}
    }
}

public struct TrafficSample: Codable, Equatable, Sendable {
    public var up: Int64
    public var down: Int64
    public init(up: Int64, down: Int64) { self.up = up; self.down = down }
}

/// What the running engine has carried (GET /api/traffic).
public struct Traffic: Codable, Equatable, Sendable {
    public var available = false
    public var upBps: Int64 = 0
    public var downBps: Int64 = 0
    public var upTotal: Int64 = 0
    public var downTotal: Int64 = 0
    public var history: [TrafficSample] = []
    public init() {}
}

/// One routing rule: every entry that matches sends traffic to `outbound`.
public struct RouteRule: Codable, Identifiable, Equatable, Hashable, Sendable {
    public var id: String
    public var name: String?
    public var enabled: Bool
    public var entries: [String]
    public var outbound: String // proxy | direct | block
    public init(id: String, name: String? = nil, enabled: Bool = true, entries: [String] = [], outbound: String = "proxy") {
        self.id = id; self.name = name; self.enabled = enabled; self.entries = entries; self.outbound = outbound
    }
}

public struct RuleSet: Codable, Identifiable, Equatable, Hashable, Sendable {
    public var id: String
    public var name: String
    public var rules: [RouteRule]
    public init(id: String, name: String, rules: [RouteRule] = []) { self.id = id; self.name = name; self.rules = rules }
}

/// Which rule a destination would hit (POST /api/routing/test).
public struct RouteMatch: Codable, Equatable, Sendable {
    public var outbound: String
    public var ruleId: String?
    public var entry: String?
    public var unknown: [String]?
}

public struct ImportedRules: Codable, Equatable, Sendable {
    public var rules: [RouteRule]
    public var skipped: [String]
}

/// Per-server tweaks over the global settings; a missing field means "use the global one".
public struct ServerOverrides: Codable, Equatable, Hashable, Sendable {
    public struct Fragment: Codable, Equatable, Hashable, Sendable {
        public var packets: String?
        public var length: String?
        public var interval: String?
        public init(packets: String? = nil, length: String? = nil, interval: String? = nil) {
            self.packets = packets; self.length = length; self.interval = interval
        }
    }

    public var mux: Bool?
    public var muxConcurrency: Int?
    public var fragment: Fragment?
    public var sni: String?
    public var fingerprint: String?
    public init() {}

    public static let fingerprints = ["chrome", "firefox", "safari", "ios", "android", "edge", "random", "randomized"]

    /// Drops empty strings and zero values so "nothing set" really sends nothing.
    public var cleaned: ServerOverrides? {
        var o = self
        if (o.sni ?? "").trimmingCharacters(in: .whitespaces).isEmpty { o.sni = nil } else { o.sni = o.sni?.trimmingCharacters(in: .whitespaces) }
        if (o.fingerprint ?? "").isEmpty { o.fingerprint = nil }
        if (o.muxConcurrency ?? 0) <= 0 { o.muxConcurrency = nil }
        if o.mux == nil { o.muxConcurrency = nil }
        if var f = o.fragment {
            for k in [\Fragment.packets, \Fragment.length, \Fragment.interval] where (f[keyPath: k] ?? "").trimmingCharacters(in: .whitespaces).isEmpty { f[keyPath: k] = nil }
            o.fragment = f
        }
        return o == ServerOverrides() ? nil : o
    }
}

/// A server written by hand as Xray or sing-box outbound JSON.
public struct CustomConfig: Codable, Equatable, Hashable, Sendable {
    public var engine: String // xray | sing-box
    public var config: String
    public init(engine: String, config: String) { self.engine = engine; self.config = config }
}

/// The configuration the app would run for a server: one entry per engine process.
public struct ConfigPreview: Codable, Equatable, Identifiable, Sendable {
    public var engines: [String]
    public var configs: [String]
    public var id: String { engines.joined(separator: "+") + String(configs.joined().hashValue) }
    public var title = ""
    enum CodingKeys: String, CodingKey { case engines, configs }
}
