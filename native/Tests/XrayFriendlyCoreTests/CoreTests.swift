import XCTest
@testable import XrayFriendlyCore

final class FormatTests: XCTestCase {
    func testLatencyClasses() {
        XCTAssertEqual(LatencyClass(ms: 48), .fast)
        XCTAssertEqual(LatencyClass(ms: 99), .fast)
        XCTAssertEqual(LatencyClass(ms: 100), .ok)
        XCTAssertEqual(LatencyClass(ms: 199), .ok)
        XCTAssertEqual(LatencyClass(ms: 200), .slow)
        XCTAssertEqual(LatencyClass(ms: -2), .timeout)
        XCTAssertEqual(LatencyClass(ms: -3), .notApplicable)
        XCTAssertEqual(LatencyClass(ms: -1), .unknown)
        XCTAssertEqual(Format.latency(48), "48 ms")
        XCTAssertEqual(Format.latency(-2), "Timeout")
        XCTAssertEqual(Format.latency(-3), "n/a")
        XCTAssertEqual(Format.latencyLong(118), "118 ms · OK")
        XCTAssertEqual(Format.latencyLong(-3), "UDP — use Real test")
        XCTAssertLessThan(Format.latencySortKey(500), Format.latencySortKey(-3))
        XCTAssertLessThan(Format.latencySortKey(-1), Format.latencySortKey(-2))
    }

    func testButtonsAndSummaries() {
        XCTAssertEqual(Format.addButton(servers: 4, subscriptions: 1), "Add 4 Servers & 1 Subscription")
        XCTAssertEqual(Format.addButton(servers: 1, subscriptions: 0), "Add 1 Server")
        XCTAssertEqual(Format.addButton(servers: 0, subscriptions: 2), "Add 2 Subscriptions")
        var p = ImportPreview()
        p.ready = 4; p.subscriptions = 1; p.skipped = 1
        XCTAssertEqual(Format.previewSummary(p), "4 servers · 1 subscription · 1 skipped")
        let nodes = [Node(id: "a", name: "A", protocol: "vless", server: "a", port: 1, source: "s1"),
                     Node(id: "b", name: "B", protocol: "tuic", server: "b", port: 1),
                     Node(id: "c", name: "C", protocol: "vless", server: "c", port: 1)]
        XCTAssertEqual(Format.serverSummary(nodes), "3 servers · 2 protocols · 2 sources")
        XCTAssertEqual(Format.uptime(872), "00:14:32")
        XCTAssertEqual(Format.engineBadge(displayName: "sing-box", active: "v1.14.4"), "sing-box 1.14")
        XCTAssertEqual(Format.exportCommand(socks: 10808, http: 10809),
                       "export http_proxy=http://127.0.0.1:10809 https_proxy=http://127.0.0.1:10809; export all_proxy=socks5://127.0.0.1:10808")
    }
}

final class FormTests: XCTestCase {
    func testVLESSReality() throws {
        var f = ServerForm(protocolID: "vless")
        f.values = ["name": "Frankfurt", "address": "fra1.example.net", "uuid": "id", "sni": "www.example.com", "publicKey": "PK", "shortId": "ab"]
        let (name, p) = try f.profile()
        XCTAssertEqual(name, "Frankfurt")
        XCTAssertEqual(p.protocol, "vless")
        XCTAssertEqual(p.port, 443) // placeholder default
        XCTAssertEqual(p.flow, "xtls-rprx-vision")
        XCTAssertEqual(p.transport.type, "tcp")
        XCTAssertEqual(p.security.kind, "reality")
        XCTAssertEqual(p.security.publicKey, "PK")
        XCTAssertEqual(p.security.fingerprint, "chrome")
        XCTAssertEqual(ServerForm(profile: p, name: name).values["publicKey"], "PK")
    }

    func testTrojanDefaultsToWebSocketAndPathIsServiceNameForGRPC() throws {
        var f = ServerForm(protocolID: "trojan")
        f.values = ["address": "t.example.net", "password": "pw", "path": "/w"]
        XCTAssertEqual(try f.profile().profile.transport.type, "ws")
        f.values["transport"] = "gRPC"
        f.values["path"] = "svc"
        let p = try f.profile().profile
        XCTAssertEqual(p.transport.serviceName, "svc")
        XCTAssertNil(p.transport.path)
    }

    func testHysteria2ObfsSwitchesEngine() throws {
        var f = ServerForm(protocolID: "hy2")
        XCTAssertEqual(f.engine, "xray")
        f.values = ["address": "h.example.net", "password": "pw", "obfs": "Salamander", "obfsPassword": "ob", "bandwidth": "50 / 200 Mbps"]
        XCTAssertEqual(f.engine, "sing-box")
        XCTAssertTrue(f.sections[1].fields.contains { $0.key == "obfsPassword" })
        let p = try f.profile().profile
        XCTAssertEqual(p.hysteria?.obfs, "salamander")
        XCTAssertEqual(p.hysteria?.upMbps, 50)
        XCTAssertEqual(p.hysteria?.downMbps, 200)
        XCTAssertEqual(p.security.alpn, ["h3"])
        f.values["bandwidth"] = "fast"
        XCTAssertThrowsError(try f.profile())
    }

    func testWireGuardAndPortDefaults() throws {
        var f = ServerForm(protocolID: "wg")
        f.values = ["address": "wg.example.org", "privateKey": "K", "peerPublicKey": "P", "localAddress": "10.7.0.2/32, fd00::2/128",
                    "reserved": "1,2,3", "keepalive": "25 s"]
        let p = try f.profile().profile
        XCTAssertEqual(p.port, 51820)
        XCTAssertEqual(p.wireguard?.localAddress, ["10.7.0.2/32", "fd00::2/128"])
        XCTAssertEqual(p.wireguard?.reserved, [1, 2, 3])
        XCTAssertEqual(p.wireguard?.keepalive, 25)
        f.values["reserved"] = "1,2"
        XCTAssertThrowsError(try f.profile())
        XCTAssertEqual(ServerForm(protocolID: "ssh").portPlaceholder, "22")
    }

    func testTUICShadowTLSNaiveSSH() throws {
        var t = ServerForm(protocolID: "tuic")
        t.values = ["address": "t.net", "uuid": "u", "password": "p", "cc": "NewReno"]
        t.flags["zeroRtt"] = true
        let tp = try t.profile().profile
        XCTAssertEqual(tp.tuic?.congestionControl, "new_reno")
        XCTAssertEqual(tp.tuic?.udpRelayMode, "native")
        XCTAssertEqual(tp.tuic?.zeroRtt, true)
        XCTAssertEqual(tp.transport.type, "quic")

        var s = ServerForm(protocolID: "stls")
        s.values = ["address": "st.net", "stlsPassword": "outer", "handshake": "www.apple.com:443", "password": "inner"]
        let sp = try s.profile().profile
        XCTAssertEqual(sp.shadowtls?.sni, "www.apple.com")
        XCTAssertEqual(sp.cipher, "2022-blake3-aes-128-gcm")
        XCTAssertEqual(sp.password, "inner")

        var n = ServerForm(protocolID: "naive")
        XCTAssertFalse(n.sections.last!.fields.contains { $0.key == "alpn" || $0.key == "pin" }, "sing-box naive accepts only the server name")
        n.values = ["address": "n.net", "username": "u", "password": "p", "headers": "X-A: 1, X-B: 2"]
        XCTAssertEqual(try n.profile().profile.naive?.extraHeaders, ["X-A": "1", "X-B": "2"])

        var h = ServerForm(protocolID: "ssh")
        h.values = ["address": "s.net", "username": "root", "keyPath": "~/.ssh/id"]
        XCTAssertEqual(try h.profile().profile.ssh?.privateKeyPath, "~/.ssh/id")
        h.values["sshAuth"] = "Password"
        h.values["password"] = "pw"
        XCTAssertTrue(h.sections[1].fields.contains { $0.key == "password" })
        XCTAssertEqual(try h.profile().profile.password, "pw")
    }

    func testRequiresAddressAndValidPort() {
        XCTAssertThrowsError(try ServerForm(protocolID: "trojan").profile())
        var f = ServerForm(protocolID: "trojan")
        f.values = ["address": "a", "port": "70000"]
        XCTAssertThrowsError(try f.profile())
    }

    func testEveryProtocolHasDesignSections() {
        for d in ServerForms.all {
            let titles = ServerForm(protocolID: d.id).sections.map(\.title)
            XCTAssertEqual(titles.prefix(2), ["Server", "Authentication"], d.id)
        }
        XCTAssertEqual(ServerForms.all.filter { $0.engine == "sing-box" }.map(\.label),
                       ["TUIC v5", "Hysteria", "AnyTLS", "ShadowTLS", "NaiveProxy", "SSH", "OpenVPN"])
    }
}

final class DecodeTests: XCTestCase {
    func testDecodesBackendJSON() throws {
        let json = """
        {"running":true,"pid":42,"startedAt":"2026-10-29T12:26:40.218514-07:00","lastExitAt":"0001-01-01T00:00:00Z",
         "activeNode":"Frankfurt test","activeNodeId":"7198","activeCountryCode":"DE","activeLatencyMs":40,"protocol":"VLESS",
         "transport":"TCP","engine":"xray","engineVersion":"v26.3.27","uptimeSec":3,"routingMode":"bypass-private",
         "autoPick":false,"systemProxyServices":[],"systemProxyOn":false}
        """
        let s = try APIClient.decoder.decode(Status.self, from: Data(json.utf8))
        XCTAssertTrue(s.running)
        XCTAssertEqual(s.activeCountryCode, "DE")
        XCTAssertNotNil(s.startedAt)
        XCTAssertEqual(APIClient.parseDate("0001-01-01T00:00:00Z"), .distantPast)

        let node = """
        {"id":"a","name":"🇩🇪 Fra","protocol":"vless","server":"1.2.3.4","port":443,"rawLink":"vless://x","createdAt":"2026-10-29T12:00:00Z",
         "latencyMs":-1,"displayName":"Fra","countryCode":"DE","protocolName":"VLESS","transport":"Reality","security":"Reality · Vision",
         "sni":"w.com","udp":false,"engine":"xray","engineName":"Xray core","engineInstalled":true,"hasLink":true}
        """
        let n = try APIClient.decoder.decode(Node.self, from: Data(node.utf8))
        XCTAssertEqual(n.displayName, "Fra")
        XCTAssertNil(n.source)
    }
}
