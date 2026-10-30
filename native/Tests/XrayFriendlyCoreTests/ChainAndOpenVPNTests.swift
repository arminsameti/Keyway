import XCTest
@testable import XrayFriendlyCore

final class ChainFormTests: XCTestCase {
    func node(_ id: String, _ name: String, chain: Bool = false) -> Node {
        Node(id: id, name: name, protocol: chain ? "chain" : "vless", server: "s", port: 1, chain: chain)
    }

    func testEditingOrder() {
        var c = ChainForm()
        for id in ["a", "b", "c"] { c.add(id) }
        c.move(at: 0, by: 1)
        XCTAssertEqual(c.hops, ["b", "a", "c"])
        c.move(at: 0, by: -1) // already the entry: nothing happens
        XCTAssertEqual(c.hops, ["b", "a", "c"])
        c.move(at: 2, by: 1)
        XCTAssertEqual(c.hops, ["b", "a", "c"])
        c.remove(at: 1)
        XCTAssertEqual(c.hops, ["b", "c"])
        c.remove(at: 9) // out of range: ignored
        XCTAssertEqual(c.hops, ["b", "c"])
        c.add("b") // the same server may appear twice (e.g. as entry and exit)
        XCTAssertEqual(c.hops, ["b", "c", "b"])

        var d = ChainForm(hops: ["a", "b", "c", "d"])
        d.move(fromOffsets: IndexSet(integer: 0), toOffset: 3)
        XCTAssertEqual(d.hops, ["b", "c", "a", "d"])
        d.move(fromOffsets: IndexSet(integer: 3), toOffset: 0)
        XCTAssertEqual(d.hops, ["d", "b", "c", "a"])
    }

    func testLimitIsEnforced() {
        var c = ChainForm()
        for i in 0..<(ChainForm.maxHops + 5) { c.add("n\(i)") }
        XCTAssertEqual(c.hops.count, ChainForm.maxHops)
        XCTAssertFalse(c.canAddMore)
    }

    func testBlockersAndCandidates() {
        let nodes = [node("a", "Frankfurt"), node("b", "Home"), node("c", "A chain", chain: true)]
        XCTAssertEqual(ChainForm(hops: []).blocker(in: nodes), "Add at least two servers.")
        XCTAssertEqual(ChainForm(hops: ["a"]).blocker(in: nodes), "Add at least two servers.")
        XCTAssertNil(ChainForm(hops: ["a", "b"]).blocker(in: nodes), "valid orders are left to the backend")
        XCTAssertEqual(ChainForm(hops: ["a", "gone"]).blocker(in: nodes), "Server 2 is no longer in your list.")
        XCTAssertTrue(ChainForm(hops: ["a", "c"]).blocker(in: nodes)!.contains("is a chain"))
        XCTAssertEqual(ChainForm().candidates(from: nodes).map(\.id), ["a", "b"], "a chain cannot contain a chain")
        XCTAssertEqual(ChainForm(hops: ["b", "a"]).defaultName(in: nodes), "Home → Frankfurt")
        XCTAssertEqual(ChainForm().defaultName(in: nodes), "Chain")
    }

    func testDecodesChainNodeAndPlan() throws {
        let json = """
        {"id":"28fb71925ab9","name":"Office → Frankfurt → Home","protocol":"chain","server":"","port":0,"createdAt":"2026-10-29T12:00:00Z",
         "latencyMs":144,"displayName":"Office → Frankfurt → Home","protocolName":"Chain","transport":"3 hops","security":"—","sni":"—",
         "udp":true,"relaysUdp":false,"engine":"sing-box","engineName":"sing-box","engineInstalled":true,"hasLink":false,"chain":true,
         "hops":[{"id":"o","name":"Office VPN","countryCode":"US","protocolName":"OpenVPN","transport":"UDP","missing":false},
                 {"id":"x","name":"","protocolName":"","missing":true}]}
        """
        let n = try APIClient.decoder.decode(Node.self, from: Data(json.utf8))
        XCTAssertTrue(n.isChain)
        XCTAssertEqual(n.hopList.count, 2)
        XCTAssertEqual(n.hopList[0].protocolName, "OpenVPN")
        XCTAssertTrue(n.hopList[1].missing)
        XCTAssertFalse(n.hasLink)
        // servers from older JSON have no chain fields at all
        let plain = """
        {"id":"a","name":"A","protocol":"vless","server":"s","port":1,"latencyMs":-1,"displayName":"A","protocolName":"VLESS","transport":"TCP",
         "security":"TLS","sni":"s","udp":false,"engineInstalled":true,"hasLink":true}
        """
        let p = try APIClient.decoder.decode(Node.self, from: Data(plain.utf8))
        XCTAssertFalse(p.isChain)
        XCTAssertTrue(p.hopList.isEmpty)
        XCTAssertFalse(p.canRelayUDP)

        let plan = try APIClient.decoder.decode(ChainPlan.self, from: Data(#"{"engine":"xray","engineName":"sing-box + Xray core","processes":2,"installed":false}"#.utf8))
        XCTAssertEqual(plan.processes, 2)
        XCTAssertFalse(plan.installed)

        let body = try APIClient.decoder.decode(ProfileBody.self, from: Data(#"{"name":"Work","chain":["a","b"]}"#.utf8))
        XCTAssertNil(body.profile)
        XCTAssertEqual(body.chain, ["a", "b"])
        let srv = try APIClient.decoder.decode(ProfileBody.self, from: Data(#"{"name":"S","profile":{"protocol":"vless","server":"s","port":1,"transport":{"type":"tcp"},"security":{"kind":"none"}}}"#.utf8))
        XCTAssertNil(srv.chain)
        XCTAssertEqual(srv.profile?.server, "s")
    }
}

final class OpenVPNFormTests: XCTestCase {
    static let ca = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----"

    func testManualProfile() throws {
        var f = ServerForm(protocolID: "openvpn")
        XCTAssertEqual(f.portPlaceholder, "1194")
        XCTAssertEqual(f.engine, "sing-box")
        XCTAssertEqual(f.sections.map(\.title), ["Server", "Authentication", "Control Channel"])
        f.values = ["name": "Office", "address": "vpn.example.com", "network": "TCP", "username": "alice", "password": "pw", "ca": Self.ca]
        let (name, p) = try f.profile()
        XCTAssertEqual(name, "Office")
        XCTAssertEqual(p.protocol, "openvpn")
        XCTAssertEqual(p.port, 1194)
        XCTAssertEqual(p.transport.type, "tcp")
        XCTAssertEqual(p.username, "alice")
        XCTAssertEqual(p.openvpn?.ca, Self.ca)
        XCTAssertNil(p.openvpn?.controlWrap)
        XCTAssertEqual(p.security.kind, "tls")

        // a control channel key is required once a type is chosen
        f.values["wrap"] = "tls-crypt"
        XCTAssertTrue(f.sections.last!.fields.contains { $0.key == "wrapKey" })
        XCTAssertThrowsError(try f.profile())
        f.values["wrapKey"] = "KEY"
        XCTAssertEqual(try f.profile().profile.openvpn?.controlWrap, Profile.OpenVPN.ControlWrap(type: "tls_crypt", key: "KEY", direction: nil))
        f.values["wrap"] = "tls-auth"
        XCTAssertEqual(try f.profile().profile.openvpn?.controlWrap?.direction, "client")
    }

    func testEditingKeepsWhatTheFormDoesNotShow() throws {
        // an imported profile with options the form has no field for
        var imported = Profile(protocol: "openvpn")
        imported.server = "vpn.example.com"
        imported.port = 443
        imported.transport.type = "udp"
        var o = Profile.OpenVPN()
        o.ca = Self.ca
        o.cert = "CERT"
        o.key = "KEY"
        o.cipher = "AES-256-CBC"
        o.auth = "SHA256"
        o.compression = "lz4-v2"
        o.verifyName = "server"
        o.renegSec = 0
        o.pingInterval = 10
        o.remotes = [.init(server: "b.example.com", port: 443, network: "tcp")]
        o.controlWrap = .init(type: "tls_auth", key: "WRAP", direction: "server")
        imported.openvpn = o

        var f = ServerForm(profile: imported, name: "Office")
        XCTAssertEqual(f.protocolID, "openvpn")
        XCTAssertEqual(f.values["address"], "vpn.example.com")
        XCTAssertEqual(f.values["port"], "443")
        XCTAssertEqual(f.values["wrap"], "tls-auth")
        XCTAssertEqual(f.values["wrapKey"], "WRAP")

        // change only the server name and port, then save
        f.values["address"] = "other.example.com"
        f.values["port"] = "1195"
        let saved = try f.profile().profile
        XCTAssertEqual(saved.server, "other.example.com")
        XCTAssertEqual(saved.port, 1195)
        let kept = try XCTUnwrap(saved.openvpn)
        XCTAssertEqual(kept.cipher, "AES-256-CBC")
        XCTAssertEqual(kept.auth, "SHA256")
        XCTAssertEqual(kept.compression, "lz4-v2")
        XCTAssertEqual(kept.verifyName, "server")
        XCTAssertEqual(kept.renegSec, 0)
        XCTAssertEqual(kept.pingInterval, 10)
        XCTAssertEqual(kept.remotes?.count, 1)
        XCTAssertEqual(kept.controlWrap?.direction, "server", "the imported key direction is kept")

        // a credentials prompt is satisfied once a username is entered
        var needs = imported
        needs.openvpn?.needsCredential = true
        var g = ServerForm(profile: needs, name: "x")
        g.values["username"] = "alice"
        g.values["password"] = "pw"
        XCTAssertNil(try g.profile().profile.openvpn?.needsCredential)
    }

    func testOpenVPNJSONRoundTripKeepsEveryField() throws {
        let json = #"""
        {"protocol":"openvpn","server":"v.example.com","port":1194,"transport":{"type":"udp"},"security":{"kind":"tls"},"username":"u","password":"p",
         "openvpn":{"remotes":[{"server":"b","port":443,"network":"tcp"}],"remoteRandom":true,"ca":"CA","cert":"C","key":"K","peerFingerprint":["ab"],
         "needsCredential":false,"controlWrap":{"type":"tls_crypt","key":"W"},"dataCiphers":["AES-256-GCM"],"cipher":"AES-256-CBC","auth":"SHA256",
         "compression":"lz4","compLzo":"adaptive","remoteCertTls":"server","verifyName":"srv","verifyNameType":"name","tlsVersionMin":"1.2",
         "renegSec":0,"pingInterval":10,"pingRestart":60,"mssfix":1200,"fragment":1300,"routeNoPull":true,"topology":"subnet"}}
        """#
        let p = try JSONDecoder().decode(Profile.self, from: Data(json.utf8))
        let again = try JSONDecoder().decode(Profile.self, from: try JSONEncoder().encode(p))
        XCTAssertEqual(p, again)
        let o = try XCTUnwrap(p.openvpn)
        XCTAssertEqual(o.peerFingerprint, ["ab"])
        XCTAssertEqual(o.mssfix, 1200)
        XCTAssertEqual(o.fragment, 1300)
        XCTAssertEqual(o.routeNoPull, true)
        XCTAssertEqual(o.topology, "subnet")
        XCTAssertEqual(o.remoteRandom, true)
    }
}
