import Foundation

/// One field of the New Server form (design/screens/NewServer.dc.html, `defs`).
public struct FormField: Identifiable, Hashable, Sendable {
    public enum Kind: Hashable, Sendable { case text, secret, multiline, select([String]), toggle }
    public var id: String { key }
    public let key: String
    public let label: String
    public let placeholder: String
    public let kind: Kind
    public let mono: Bool

    static func text(_ key: String, _ label: String, _ ph: String, mono: Bool = false) -> FormField {
        FormField(key: key, label: label, placeholder: ph, kind: .text, mono: mono)
    }
    static func secret(_ key: String, _ label: String = "Password", _ ph: String = "Required", mono: Bool = false) -> FormField {
        FormField(key: key, label: label, placeholder: ph, kind: .secret, mono: mono)
    }
    static func multiline(_ key: String, _ label: String, _ ph: String) -> FormField {
        FormField(key: key, label: label, placeholder: ph, kind: .multiline, mono: true)
    }
    static func select(_ key: String, _ label: String, _ options: [String]) -> FormField {
        FormField(key: key, label: label, placeholder: options.first ?? "", kind: .select(options), mono: false)
    }
    static func toggle(_ key: String, _ label: String) -> FormField {
        FormField(key: key, label: label, placeholder: "", kind: .toggle, mono: false)
    }
}

public struct FormSection: Identifiable, Hashable, Sendable {
    public var id: String { title }
    public let title: String
    public let fields: [FormField]
    public let note: String?
}

/// A protocol entry in the left-hand list.
public struct ProtocolDef: Identifiable, Hashable, Sendable {
    public let id: String       // form key: vless, hy2, stls, …
    public let label: String
    public let hint: String
    public let engine: String   // "xray" or "sing-box"
    public let about: String
    public let backend: String  // profile protocol name
    let auth: [FormField]
    let transport: Bool
    let tls: Bool
    let udp: Bool
}

public enum ServerForms {
    static let ssMethods = ["2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
                            "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "none"]
    static let ss2022 = Array(ssMethods.prefix(3))
    static let uuidPH = "00000000-0000-0000-0000-000000000000"

    public static let all: [ProtocolDef] = [
        ProtocolDef(id: "vless", label: "VLESS", hint: "Reality, Vision, XHTTP", engine: "xray",
                    about: "Lightweight, the usual choice with Reality or TLS.", backend: "vless",
                    auth: [.text("uuid", "UUID", uuidPH, mono: true), .select("flow", "Flow", ["xtls-rprx-vision", "None"]),
                           .select("encryption", "Encryption", ["none"])], transport: true, tls: false, udp: false),
        ProtocolDef(id: "vmess", label: "VMess", hint: "Classic V2Ray", engine: "xray",
                    about: "Older V2Ray protocol with built-in encryption.", backend: "vmess",
                    auth: [.text("uuid", "UUID", uuidPH, mono: true), .text("alterId", "Alter ID", "0"),
                           .select("cipher", "Cipher", ["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"])],
                    transport: true, tls: false, udp: false),
        ProtocolDef(id: "trojan", label: "Trojan", hint: "Looks like HTTPS", engine: "xray",
                    about: "Password protocol that looks like a normal HTTPS site.", backend: "trojan",
                    auth: [.secret("password")], transport: true, tls: false, udp: false),
        ProtocolDef(id: "ss", label: "Shadowsocks", hint: "Incl. 2022 ciphers", engine: "xray",
                    about: "Simple and fast; use a 2022-blake3 cipher.", backend: "shadowsocks",
                    auth: [.select("method", "Method", ssMethods), .secret("password"), .select("plugin", "Plugin", ["None"])],
                    transport: false, tls: false, udp: false),
        ProtocolDef(id: "hy2", label: "Hysteria2", hint: "QUIC, lossy networks", engine: "xray",
                    about: "QUIC-based; fast on lossy or congested networks.", backend: "hysteria2",
                    auth: [.secret("password"), .select("obfs", "Obfuscation", ["None", "Salamander"]),
                           .text("bandwidth", "Upload / Download", "50 / 200 Mbps")], transport: false, tls: true, udp: true),
        ProtocolDef(id: "wg", label: "WireGuard", hint: "Full tunnel, UDP", engine: "xray",
                    about: "Modern VPN protocol. Paste a .conf file to fill this in.", backend: "wireguard",
                    auth: [.secret("privateKey", "Private key", "Base64 key", mono: true),
                           .text("peerPublicKey", "Peer public key", "Base64 key", mono: true),
                           .secret("preSharedKey", "Pre-shared key", "Optional", mono: true),
                           .text("localAddress", "Local address", "10.7.0.2/32, fd00::2/128", mono: true),
                           .text("mtu", "MTU", "1420"), .text("reserved", "Reserved bytes", "Optional, e.g. 0,0,0")],
                    transport: false, tls: false, udp: true),
        ProtocolDef(id: "socks", label: "SOCKS5", hint: "Upstream proxy", engine: "xray",
                    about: "Chain through another SOCKS5 proxy.", backend: "socks",
                    auth: [.text("username", "Username", "Optional"), .secret("password", "Password")], transport: false, tls: false, udp: false),
        ProtocolDef(id: "http", label: "HTTP / HTTPS", hint: "Upstream proxy", engine: "xray",
                    about: "Chain through an HTTP CONNECT proxy, optionally over TLS.", backend: "http",
                    auth: [.text("username", "Username", "Optional"), .secret("password", "Password"),
                           .toggle("httpsTLS", "Connect over TLS (HTTPS proxy)")], transport: false, tls: false, udp: false),
        ProtocolDef(id: "tuic", label: "TUIC v5", hint: "QUIC, low latency", engine: "sing-box",
                    about: "QUIC proxy with 0-RTT and native UDP relay.", backend: "tuic",
                    auth: [.text("uuid", "UUID", uuidPH, mono: true), .secret("password"),
                           .select("cc", "Congestion control", ["BBR", "CUBIC", "NewReno"]),
                           .select("udpMode", "UDP relay mode", ["Native", "QUIC"]), .toggle("zeroRtt", "Zero-RTT handshake")],
                    transport: false, tls: true, udp: true),
        ProtocolDef(id: "hy1", label: "Hysteria", hint: "Version 1", engine: "sing-box",
                    about: "The original Hysteria. Prefer Hysteria2 for new servers.", backend: "hysteria",
                    auth: [.secret("password", "Auth string", "Required"), .text("bandwidth", "Upload / Download", "50 / 200 Mbps"),
                           .secret("obfsPassword", "Obfuscation password", "Optional")], transport: false, tls: true, udp: true),
        ProtocolDef(id: "anytls", label: "AnyTLS", hint: "TLS fingerprint-resistant", engine: "sing-box",
                    about: "Reduces TLS-in-TLS fingerprints with padding.", backend: "anytls",
                    auth: [.secret("password"), .text("idle", "Idle session timeout", "30 s")], transport: false, tls: true, udp: false),
        ProtocolDef(id: "stls", label: "ShadowTLS", hint: "Wraps Shadowsocks", engine: "sing-box",
                    about: "Borrows a real site’s TLS handshake, then runs Shadowsocks inside.", backend: "shadowtls",
                    auth: [.select("stlsVersion", "Version", ["3", "2", "1"]), .secret("stlsPassword", "ShadowTLS password"),
                           .text("handshake", "Handshake server", "www.example.com:443"),
                           .select("method", "Inner method", ss2022), .secret("password", "Inner password")],
                    transport: false, tls: false, udp: false),
        ProtocolDef(id: "naive", label: "NaiveProxy", hint: "Chrome network stack", engine: "sing-box",
                    about: "HTTP/2 proxy that looks like Chrome talking to a website.", backend: "naive",
                    auth: [.text("username", "Username", "Required"), .secret("password"), .text("headers", "Extra headers", "Optional")],
                    transport: false, tls: true, udp: false),
        ProtocolDef(id: "ssh", label: "SSH", hint: "Tunnel via any SSH host", engine: "sing-box",
                    about: "Use any server you can SSH into as a proxy.", backend: "ssh",
                    auth: [.text("username", "User", "root"), .select("sshAuth", "Authentication", ["Private key", "Password"]),
                           .text("keyPath", "Private key file", "~/.ssh/id_ed25519", mono: true),
                           .text("hostKey", "Host key", "Optional, pins the server", mono: true)], transport: false, tls: false, udp: false),
        ProtocolDef(id: "openvpn", label: "OpenVPN", hint: "UDP or TCP, .ovpn files", engine: "sing-box",
                    about: "The classic VPN. Open an .ovpn file to fill this in; it runs without administrator rights.", backend: "openvpn",
                    auth: [.text("username", "Username", "Optional with a client certificate"), .secret("password", "Password", "Optional"),
                           .multiline("ca", "CA certificate", "-----BEGIN CERTIFICATE-----"),
                           .multiline("cert", "Client certificate", "Optional with a username and password"),
                           .multiline("key", "Client key", "Optional with a username and password")], transport: false, tls: false, udp: false),
    ]

    /// The control channel options of the OpenVPN form.
    static let ovpnWraps = ["None", "tls-crypt", "tls-auth", "tls-crypt-v2"]
    static let ovpnWrapTypes = ["tls-crypt": "tls_crypt", "tls-auth": "tls_auth", "tls-crypt-v2": "tls_crypt_v2"]

    public static func def(_ id: String) -> ProtocolDef { all.first { $0.id == id } ?? all[0] }
    public static func def(backend: String) -> ProtocolDef? { all.first { $0.backend == backend } }

    static let transports = ["TCP", "WebSocket", "gRPC", "HTTP/2", "XHTTP", "mKCP", "HTTPUpgrade"]
    static let transportValues = ["tcp", "ws", "grpc", "h2", "xhttp", "kcp", "httpupgrade"]
    static let fingerprints = ["Chrome", "Firefox", "Safari", "iOS", "Edge", "Random", "None"]
}

/// The form's state for one protocol: string values keyed by field key.
public struct ServerForm: Equatable, Sendable {
    public var protocolID: String
    public var values: [String: String] = [:]
    public var flags: [String: Bool] = [:]
    /// The profile this form was filled from. Options the form has no field for
    /// (an imported .ovpn has dozens) are kept from it when the form is saved.
    public var base: Profile?

    public init(protocolID: String) { self.protocolID = protocolID }

    public var def: ProtocolDef { ServerForms.def(protocolID) }

    public func value(_ key: String) -> String { values[key] ?? "" }
    func trimmed(_ key: String) -> String { value(key).trimmingCharacters(in: .whitespacesAndNewlines) }

    /// The selected option of a select field (its first option when unset).
    public func choice(_ f: FormField) -> String {
        if case .select(let opts) = f.kind { return values[f.key].flatMap { opts.contains($0) ? $0 : nil } ?? opts.first ?? "" }
        return value(f.key)
    }

    func choice(_ key: String, in fields: [FormField]) -> String {
        fields.first { $0.key == key }.map(choice) ?? value(key)
    }

    /// The engine the badge names; Hysteria2 with obfuscation needs sing-box.
    public var engine: String {
        if protocolID == "hy2", choice("obfs", in: def.auth) == "Salamander" { return "sing-box" }
        return def.engine
    }

    public var portPlaceholder: String {
        switch protocolID {
        case "wg": return "51820"
        case "ssh": return "22"
        case "openvpn": return "1194"
        default: return "443"
        }
    }

    // MARK: sections

    public var sections: [FormSection] {
        let d = def
        var serverFields: [FormField] = [
            .text("name", "Name", "Shown in the server list"), .text("address", "Address", "server.example.net or IP"),
            .text("port", "Port", portPlaceholder),
        ]
        if protocolID == "openvpn" { serverFields.append(.select("network", "Protocol", ["UDP", "TCP"])) }
        var out = [FormSection(title: "Server", fields: serverFields, note: nil)]
        var auth = d.auth
        if protocolID == "hy2", choice("obfs", in: d.auth) == "Salamander" {
            auth.insert(.secret("obfsPassword", "Obfuscation password"), at: 2)
        }
        if protocolID == "ssh", choice("sshAuth", in: d.auth) == "Password" {
            auth[2] = .secret("password", "Password")
        }
        out.append(FormSection(title: "Authentication", fields: auth, note: nil))

        if protocolID == "openvpn" {
            var wrap: [FormField] = [.select("wrap", "Control channel key", ServerForms.ovpnWraps)]
            if choice("wrap", in: wrap) != "None" { wrap.append(.multiline("wrapKey", "Key", "-----BEGIN OpenVPN Static key V1-----")) }
            out.append(FormSection(title: "Control Channel", fields: wrap,
                                   note: "Pasting an .ovpn file anywhere in this window fills this form. UDP is the default; use “Real test” to measure latency."))
        } else if d.transport {
            out.append(FormSection(title: "Transport & Security", fields: transportFields,
                                   note: "Transport options: TCP, WebSocket, gRPC, HTTP/2, XHTTP, mKCP, HTTPUpgrade."))
        } else if d.tls {
            var tls: [FormField] = [.text("sni", "Server name (SNI)", "Defaults to address")]
            if protocolID != "naive" { // sing-box's naive outbound accepts only the server name
                tls.append(.text("alpn", "ALPN", "h3"))
                tls.append(.text("pin", "Pinned certificate SHA-256", "Optional", mono: true))
            }
            out.append(FormSection(title: "TLS", fields: tls, note: d.udp ? "UDP protocol — use “Real test” to measure latency." : nil))
        } else if d.udp {
            out.append(FormSection(title: "Network", fields: [.text("allowedIps", "Allowed IPs", "0.0.0.0/0, ::/0", mono: true),
                                                              .text("keepalive", "Persistent keepalive", "25 s")],
                                   note: "UDP protocol — use “Real test” to measure latency."))
        }
        return out
    }

    var transportFields: [FormField] {
        let isVLESS = protocolID == "vless"
        var transports = ServerForms.transports
        if !isVLESS { // design default: WebSocket for VMess/Trojan
            transports.swapAt(0, 1)
        }
        let securities = isVLESS ? ["Reality", "TLS", "None"] : ["TLS", "None"]
        var f: [FormField] = [.select("transport", "Transport", transports), .select("security", "Security", securities),
                              .text("sni", "Server name (SNI)", "www.example.com"), .select("fingerprint", "Fingerprint", ServerForms.fingerprints)]
        let tr = transportValue(choice("transport", in: f))
        let sec = choice("security", in: f)
        if isVLESS {
            f.append(.text("publicKey", "Public key", "Reality public key", mono: true))
            if sec == "Reality" { f.append(.text("shortId", "Short ID", "Optional", mono: true)) }
            if tr != "tcp" { f.append(.text("path", tr == "grpc" ? "Service name" : "Path", tr == "grpc" ? "grpc-service" : "/")) }
        } else {
            f.append(.text("path", tr == "grpc" ? "Service name" : "Path", "/ws"))
        }
        if ["ws", "h2", "httpupgrade", "xhttp"].contains(tr) { f.append(.text("host", "Host header", "Optional")) }
        return f
    }

    func transportValue(_ label: String) -> String {
        ServerForms.transportValues[ServerForms.transports.firstIndex(of: label) ?? 0]
    }

    // MARK: profile

    public struct FormError: LocalizedError, Equatable { public let message: String; public var errorDescription: String? { message } }

    /// Builds the engine-neutral profile; the backend validates it fully.
    public func profile() throws -> (name: String, profile: Profile) {
        let d = def
        var p = Profile(protocol: d.backend)
        p.server = trimmed("address")
        guard !p.server.isEmpty else { throw FormError(message: "Enter the server address.") }
        let portText = trimmed("port").isEmpty ? portPlaceholder : trimmed("port")
        guard let port = Int(portText), (1...65535).contains(port) else { throw FormError(message: "Port must be 1–65535.") }
        p.port = port
        let auth = sections.first { $0.title == "Authentication" }?.fields ?? d.auth
        func opt(_ k: String) -> String? { let v = trimmed(k); return v.isEmpty ? nil : v }

        switch protocolID {
        case "vless":
            p.uuid = opt("uuid")
            let flow = choice("flow", in: auth)
            p.flow = flow == "None" ? nil : flow
            p.encryption = "none"
            try applyTransport(&p)
        case "vmess":
            p.uuid = opt("uuid")
            p.alterId = Int(trimmed("alterId")) ?? 0
            p.cipher = choice("cipher", in: auth)
            try applyTransport(&p)
        case "trojan":
            p.password = opt("password")
            try applyTransport(&p)
        case "ss":
            p.cipher = choice("method", in: auth)
            p.password = opt("password")
        case "hy2":
            p.password = opt("password")
            var h = Profile.Hysteria()
            if choice("obfs", in: auth) == "Salamander" { h.obfs = "salamander"; h.obfsPassword = opt("obfsPassword") }
            (h.upMbps, h.downMbps) = try bandwidth()
            if h != Profile.Hysteria() { p.hysteria = h }
            applyTLS(&p, defaultALPN: "h3")
        case "wg":
            var w = Profile.WireGuard()
            w.privateKey = trimmed("privateKey")
            w.peerPublicKey = trimmed("peerPublicKey")
            w.preSharedKey = opt("preSharedKey")
            w.localAddress = list("localAddress")
            w.mtu = Int(trimmed("mtu"))
            if let r = opt("reserved") {
                let bytes = r.split(separator: ",").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
                guard bytes.count == 3, bytes.allSatisfy({ (0...255).contains($0) }) else {
                    throw FormError(message: "Reserved bytes must be three numbers 0–255.")
                }
                w.reserved = bytes
            }
            let ips = list("allowedIps")
            w.allowedIps = ips.isEmpty ? nil : ips
            w.keepalive = seconds("keepalive")
            p.wireguard = w
            p.transport.type = "udp"
        case "socks", "http":
            p.username = opt("username")
            p.password = opt("password")
            if protocolID == "http", flags["httpsTLS"] == true {
                p.security.kind = "tls"
                p.security.sni = opt("sni")
            }
        case "tuic":
            p.uuid = opt("uuid")
            p.password = opt("password")
            var t = Profile.TUIC()
            t.congestionControl = ["BBR": "bbr", "CUBIC": "cubic", "NewReno": "new_reno"][choice("cc", in: auth)]
            t.udpRelayMode = choice("udpMode", in: auth).lowercased()
            t.zeroRtt = flags["zeroRtt"] == true ? true : nil
            p.tuic = t
            applyTLS(&p, defaultALPN: "h3")
        case "hy1":
            p.password = opt("password")
            var h = Profile.Hysteria()
            (h.upMbps, h.downMbps) = try bandwidth()
            if let o = opt("obfsPassword") { h.obfs = "xplus"; h.obfsPassword = o }
            p.hysteria = h
            applyTLS(&p, defaultALPN: "hysteria")
        case "anytls":
            p.password = opt("password")
            if let idle = seconds("idle") { var a = Profile.AnyTLS(); a.idleTimeoutSec = idle; p.anytls = a }
            applyTLS(&p, defaultALPN: nil)
        case "stls":
            var s = Profile.ShadowTLS()
            s.version = Int(choice("stlsVersion", in: auth)) ?? 3
            s.password = trimmed("stlsPassword")
            s.sni = String(trimmed("handshake").split(separator: ":").first ?? "")
            p.shadowtls = s
            p.cipher = choice("method", in: auth)
            p.password = opt("password")
        case "naive":
            p.username = opt("username")
            p.password = opt("password")
            p.transport.type = "h2"
            p.security.kind = "tls"
            p.security.sni = opt("sni")
            if let h = opt("headers") {
                var hdr: [String: String] = [:]
                for pair in h.split(whereSeparator: { $0 == "," || $0 == "\n" }) {
                    let kv = pair.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                    guard kv.count == 2, !kv[0].isEmpty else { throw FormError(message: "Extra headers must look like Name: value, Name2: value.") }
                    hdr[kv[0]] = kv[1]
                }
                var n = Profile.Naive(); n.extraHeaders = hdr; p.naive = n
            }
        case "openvpn":
            if let b = base, b.protocol == "openvpn" {
                var kept = b // everything the form does not show stays as imported
                kept.server = p.server
                kept.port = p.port
                p = kept
            }
            var o = p.openvpn ?? Profile.OpenVPN()
            let network = choice("network", in: sections[0].fields)
            p.transport.type = network == "TCP" ? "tcp" : "udp"
            p.username = opt("username")
            p.password = opt("password")
            o.ca = opt("ca")
            o.cert = opt("cert")
            o.key = opt("key")
            if p.username != nil { o.needsCredential = nil }
            let wrap = choice("wrap", in: sections.last?.fields ?? [])
            if let type = ServerForms.ovpnWrapTypes[wrap] {
                guard let key = opt("wrapKey") else { throw FormError(message: "Paste the \(wrap) key.") }
                o.controlWrap = Profile.OpenVPN.ControlWrap(type: type, key: key,
                                                            direction: o.controlWrap?.direction ?? (type == "tls_auth" ? "client" : nil))
            } else {
                o.controlWrap = nil
            }
            p.openvpn = o
            p.security.kind = "tls"
        case "ssh":
            p.username = opt("username")
            var s = Profile.SSH()
            if choice("sshAuth", in: d.auth) == "Password" {
                p.password = opt("password")
            } else {
                s.privateKeyPath = opt("keyPath")
            }
            if let hk = opt("hostKey") { s.hostKeys = [hk] }
            p.ssh = s
        default:
            break
        }
        return (trimmed("name"), p)
    }

    func list(_ key: String) -> [String] {
        value(key).split(whereSeparator: { $0 == "," || $0 == "\n" }).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    func seconds(_ key: String) -> Int? {
        let v = trimmed(key).replacingOccurrences(of: "s", with: "").trimmingCharacters(in: .whitespaces)
        return Int(v)
    }

    /// "50 / 200 Mbps" -> (50, 200); blank -> (nil, nil).
    func bandwidth() throws -> (Int?, Int?) {
        let v = trimmed("bandwidth").lowercased().replacingOccurrences(of: "mbps", with: "")
        if v.isEmpty { return (nil, nil) }
        let parts = v.split(separator: "/").map { Int($0.trimmingCharacters(in: .whitespaces)) }
        guard parts.count == 2, let up = parts[0], let down = parts[1], up > 0, down > 0 else {
            throw FormError(message: "Upload / Download must look like 50 / 200 Mbps.")
        }
        return (up, down)
    }

    func applyTLS(_ p: inout Profile, defaultALPN: String?) {
        p.security.kind = "tls"
        p.security.sni = trimmed("sni").isEmpty ? nil : trimmed("sni")
        let alpn = list("alpn")
        p.security.alpn = alpn.isEmpty ? defaultALPN.map { [$0] } : alpn
        p.security.pinSha256 = trimmed("pin").isEmpty ? nil : trimmed("pin")
        p.transport.type = def.udp ? "quic" : "tcp"
    }

    func applyTransport(_ p: inout Profile) throws {
        let f = transportFields
        let tr = transportValue(choice("transport", in: f))
        p.transport.type = tr
        let path = trimmed("path")
        if tr == "grpc" { p.transport.serviceName = path.isEmpty ? nil : path } else if !path.isEmpty { p.transport.path = path }
        p.transport.host = trimmed("host").isEmpty ? nil : trimmed("host")
        switch choice("security", in: f) {
        case "Reality":
            p.security.kind = "reality"
            p.security.publicKey = trimmed("publicKey")
            p.security.shortId = trimmed("shortId").isEmpty ? nil : trimmed("shortId")
            if p.security.publicKey?.isEmpty != false { throw FormError(message: "Reality needs the server's public key.") }
        case "TLS": p.security.kind = "tls"
        default: p.security.kind = "none"
        }
        p.security.sni = trimmed("sni").isEmpty ? nil : trimmed("sni")
        let fp = choice("fingerprint", in: f)
        if p.security.kind != "none", fp != "None" { p.security.fingerprint = fp.lowercased() }
    }

    // MARK: fill from a profile (edit, paste a link)

    public init(profile p: Profile, name: String) {
        let d = ServerForms.def(backend: p.protocol) ?? ServerForms.all[0]
        self.init(protocolID: d.id)
        values["name"] = name
        values["address"] = p.server
        values["port"] = String(p.port)
        func set(_ k: String, _ v: String?) { if let v, !v.isEmpty { values[k] = v } }
        set("uuid", p.uuid)
        set("password", p.password)
        set("username", p.username)
        set("sni", p.security.sni)
        set("alpn", p.security.alpn?.joined(separator: ", "))
        set("pin", p.security.pinSha256)
        switch d.id {
        case "vless", "vmess", "trojan":
            values["flow"] = (p.flow?.isEmpty ?? true) ? "None" : p.flow
            set("alterId", p.alterId.map(String.init))
            set("cipher", p.cipher)
            let idx = ServerForms.transportValues.firstIndex(of: p.transport.type.isEmpty ? "tcp" : p.transport.type) ?? 0
            values["transport"] = ServerForms.transports[idx]
            values["security"] = ["reality": "Reality", "tls": "TLS"][p.security.kind] ?? "None"
            values["fingerprint"] = p.security.fingerprint.map { fp in
                ServerForms.fingerprints.first { $0.lowercased() == fp.lowercased() } ?? "Chrome"
            } ?? "None"
            set("publicKey", p.security.publicKey)
            set("shortId", p.security.shortId)
            set("path", p.transport.type == "grpc" ? p.transport.serviceName : p.transport.path)
            set("host", p.transport.host)
        case "ss", "stls":
            set("method", p.cipher)
            if let s = p.shadowtls {
                values["stlsVersion"] = String(s.version)
                set("stlsPassword", s.password)
                set("handshake", s.sni.isEmpty ? nil : s.sni + ":443")
            }
        case "hy2", "hy1":
            if let h = p.hysteria {
                if let up = h.upMbps, let down = h.downMbps { values["bandwidth"] = "\(up) / \(down) Mbps" }
                if d.id == "hy2" { values["obfs"] = h.obfs == "salamander" ? "Salamander" : "None" }
                set("obfsPassword", h.obfsPassword)
            }
        case "wg":
            if let w = p.wireguard {
                set("privateKey", w.privateKey)
                set("peerPublicKey", w.peerPublicKey)
                set("preSharedKey", w.preSharedKey)
                set("localAddress", w.localAddress.joined(separator: ", "))
                set("mtu", w.mtu.map(String.init))
                set("reserved", w.reserved?.map(String.init).joined(separator: ","))
                set("allowedIps", w.allowedIps?.joined(separator: ", "))
                set("keepalive", w.keepalive.map { "\($0) s" })
            }
        case "http":
            flags["httpsTLS"] = p.security.kind == "tls"
        case "tuic":
            values["cc"] = ["bbr": "BBR", "cubic": "CUBIC", "new_reno": "NewReno"][p.tuic?.congestionControl ?? ""] ?? "BBR"
            values["udpMode"] = p.tuic?.udpRelayMode == "quic" ? "QUIC" : "Native"
            flags["zeroRtt"] = p.tuic?.zeroRtt ?? false
        case "anytls":
            set("idle", p.anytls?.idleTimeoutSec.map { "\($0) s" })
        case "naive":
            set("headers", p.naive?.extraHeaders?.sorted { $0.key < $1.key }.map { "\($0.key): \($0.value)" }.joined(separator: ", "))
        case "openvpn":
            base = p
            values["network"] = p.transport.type == "tcp" ? "TCP" : "UDP"
            set("ca", p.openvpn?.ca)
            set("cert", p.openvpn?.cert)
            set("key", p.openvpn?.key)
            if let w = p.openvpn?.controlWrap {
                values["wrap"] = ServerForms.ovpnWrapTypes.first { $0.value == w.type }?.key ?? "None"
                set("wrapKey", w.key)
            }
        case "ssh":
            values["sshAuth"] = p.ssh?.privateKeyPath != nil || p.ssh?.privateKey != nil ? "Private key" : "Password"
            set("keyPath", p.ssh?.privateKeyPath)
            set("hostKey", p.ssh?.hostKeys?.first)
        default:
            break
        }
    }
}
