package com.yazdanifar.vpngate

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@OptIn(ExperimentalCoroutinesApi::class)
class AccountConnectTest {
    private val dir: File = Files.createTempDirectory("vpngate-model").toFile().also { it.deleteOnExit() }

    private class Rig(test: TestScope, dir: File) {
        val engine = FakeEngine()
        val settings = MemorySettings(hasAgreedToDisclaimer = true)
        val secrets = MemorySecretStore()
        val accounts = AccountStore(File(dir, "accounts.json"), secrets)
        val history = ConnectionHistoryStore(File(dir, "history.json")) { test.currentTime }
        val model = MainModel(
            IpcClient(engine, test.backgroundScope), settings, test.backgroundScope,
            preparer = { true },
            clock = { test.currentTime },
            accountStore = accounts,
            historyStore = history,
        )

        init {
            engine.onRequest = { cmd, _ -> if (cmd == "listServers" || cmd == "refreshServers") resultJson(listResult(server("vpn1", "1.1.1.1"))) else null }
        }
    }

    @Test
    fun connectingAnAccountSendsItsConfig() = runTest {
        val r = Rig(this, dir)
        r.model.start()
        r.model.saveAccount(AccountEditorState(name = "Work", host = "vpn.example.com", username = "bob", password = "pw"), null)
        val account = r.model.state.value.accounts.single()
        r.model.updateSettings(globalRouting = RoutingConfig(bypassPrivateNetworks = true))
        r.model.connectAccount(account)
        runCurrent()
        val connect = r.engine.requests.last { it["cmd"]!!.jsonPrimitive.content == "connect" }
        val cfg = connect["config"]!!.jsonObject
        assertEquals("vpn.example.com", cfg["host"]!!.jsonPrimitive.content)
        assertEquals("pw", cfg["password"]!!.jsonPrimitive.content)
        assertTrue("routing" in cfg, "global rules apply to an account without its own")
        assertEquals(account.id, r.settings.lastAccountId)
        assertEquals(null, r.settings.lastServer)
    }

    @Test
    fun aListConnectionCarriesTheProxy() = runTest {
        val r = Rig(this, dir)
        r.model.start()
        runCurrent()
        r.model.updateSettings(proxy = ProxySettings(ProxyKind.Http, "proxy.example", 3128))
        r.model.select(r.model.state.value.allServers.single())
        r.model.connect()
        runCurrent()
        val connect = r.engine.requests.last { it["cmd"]!!.jsonPrimitive.content == "connect" }
        assertEquals("proxy.example", connect["proxy"]!!.jsonObject["host"]!!.jsonPrimitive.content)
    }

    @Test
    fun historyHasOneEntryPerConnectedPeriod() = runTest {
        val r = Rig(this, dir)
        r.model.start()
        runCurrent()
        r.model.select(r.model.state.value.allServers.single())
        r.model.connect()
        runCurrent()
        r.engine.event("connected", "1.1.1.1")
        runCurrent()
        r.engine.event("connected", "1.1.1.1", extra = ""","bytesIn":1""")
        runCurrent()
        assertEquals(1, r.model.state.value.history.size)
        r.model.updateSettings(autoReconnect = false)
        r.model.disconnect()
        r.engine.event("disconnected")
        runCurrent()
        val e = r.model.state.value.history.single()
        assertEquals("vpn1", e.serverName)
        assertTrue(e.disconnectedAtMs != null)
        r.model.clearHistory()
        assertTrue(r.model.state.value.history.isEmpty())
        assertFalse(File(dir, "history.json").readText().contains("vpn1"))
    }
}

@OptIn(ExperimentalCoroutinesApi::class)
class AndroidLimitsTest {
    private fun rule(t: RoutingRuleType, v: String, a: RoutingAction = RoutingAction.Direct, enabled: Boolean = true) =
        RoutingRule(type = t, value = v, action = a, enabled = enabled)

    @Test
    fun onlyDirectIpv4RulesSurvive() {
        val keep = rule(RoutingRuleType.Cidr, "10.0.0.0/8")
        val cfg = RoutingConfig(
            rules = listOf(
                keep,
                rule(RoutingRuleType.DomainSuffix, "example.com"),
                rule(RoutingRuleType.Ip, "1.2.3.4", RoutingAction.Block),
                rule(RoutingRuleType.Ip, "::1"),
                rule(RoutingRuleType.Ip, "5.6.7.8", enabled = false),
            ),
            defaultAction = RoutingAction.Direct,
        ).forAndroid()
        assertEquals(listOf(keep), cfg.rules)
        assertEquals(RoutingAction.Proxy, cfg.defaultAction)
        val account = ClientAccount(host = "h")
        assertEquals(null, account.toConnectConfig(null, null, null, true, RoutingConfig(rules = listOf(rule(RoutingRuleType.DomainFull, "a.com")))).routing)
    }

    @Test
    fun certificateCheckNeedsAFingerprint() {
        val s = AccountEditorState(name = "n", host = "h.example", checkServerCert = true)
        assertFalse(s.canSave)
        assertTrue(s.copy(fingerprint = "ab".repeat(20)).canSave)
    }

    @Test
    fun probeResultsFillTheList() = runTest {
        val engine = FakeEngine()
        val model = MainModel(
            IpcClient(engine, backgroundScope), MemorySettings(hasAgreedToDisclaimer = true), backgroundScope, preparer = { true },
        )
        val list = listResult(server("a", "1.1.1.1"), server("b", "2.2.2.2"))
        engine.onRequest = { cmd, _ ->
            when (cmd) {
                "listServers", "refreshServers" -> resultJson(list)
                "probe" -> """"ok":true,"result":{"results":[{"host":"1.1.1.1","ok":true,"connectMs":40,"port":443},{"host":"2.2.2.2","ok":false,"error":"Cannot connect"}]}"""
                else -> null
            }
        }
        model.start()
        runCurrent()
        model.testConnections()
        runCurrent()
        val s = model.state.value
        assertEquals(Probe.Ok(40, null, 443), s.probes["a"])
        assertEquals(Probe.Failed("Cannot connect"), s.probes["b"])
        assertFalse(s.isTesting)
        assertEquals("a", s.allServers.sortedBy(SortKey.Test, false, s.probes).first().id)
    }
}
