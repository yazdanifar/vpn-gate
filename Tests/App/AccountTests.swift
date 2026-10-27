import Foundation

func registerAccountTests() {
    test("account/model-codable-roundtrip") {
        let acc = ClientAccount(
            name: "Home Lab",
            host: "vpn.homelab.local",
            portList: [443, 992, 5555],
            hub: "HOMELAB",
            username: "admin",
            authType: .password,
            proxy: ProxySettings(),
            checkServerCert: true,
            serverCertFingerprint: "1122334455667788990011223344556677889900",
            maxConnection: 16,
            halfConnection: true,
            compression: true,
            udpAcceleration: true,
            autoReconnect: true,
            reconnectInterval: 5.0,
            reconnectCount: 10,
            virtualMacAddress: "00:AC:22:33:44:55",
            mtu: 1400
        )

        let data = try JSONEncoder().encode(acc)
        let decoded = try JSONDecoder().decode(ClientAccount.self, from: data)

        expectEqual(decoded.id, acc.id)
        expectEqual(decoded.name, "Home Lab")
        expectEqual(decoded.host, "vpn.homelab.local")
        expectEqual(decoded.portList, [443, 992, 5555])
        expectEqual(decoded.hub, "HOMELAB")
        expectEqual(decoded.username, "admin")
        expectEqual(decoded.authType, .password)
        expectEqual(decoded.maxConnection, 16)
        expect(decoded.halfConnection)
        expect(decoded.compression)
        expect(decoded.udpAcceleration)
        expectEqual(decoded.mtu, 1400)
    }

    test("account/to-connect-config-mapping") {
        let acc = ClientAccount(
            name: "Work Office",
            host: "office.example.com",
            portList: [443, 1194],
            hub: "OFFICE",
            username: "user1",
            authType: .plainPassword,
            maxConnection: 4,
            compression: true,
            udpAcceleration: false
        )

        let cfg = acc.toConnectConfig(password: "mypassword", blockIPv6: true)
        expectEqual(cfg.host, "office.example.com")
        expectEqual(cfg.ports, [443, 1194])
        expectEqual(cfg.hubName, "OFFICE")
        expectEqual(cfg.userName, "user1")
        expectEqual(cfg.password, "mypassword")
        expectEqual(cfg.maxConnection, 4)
        expect(cfg.useCompress)
        expect(!cfg.useUdpAccel)
        expect(cfg.blockIPv6)
    }

}
